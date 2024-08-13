// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package blob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"go.uber.org/zap"
	"gocloud.dev/blob"
	"gocloud.dev/blob/gcsblob"
	"gocloud.dev/blob/s3blob"
	"gocloud.dev/gcp"
	"google.golang.org/protobuf/types/known/structpb"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	dotcache   = ".cache"
	DriverName = "blob"
)

var (
	_ storage.SourceStore = (*Store)(nil)
	_ storage.Reloadable  = (*Store)(nil)
)

var ErrUnsupportedBucketScheme = errors.New("currently only \"s3\" and \"gs\" bucket URL schemes are supported")

var driverSourceAttr = policy.SourceDriver(DriverName)

func init() {
	storage.RegisterDriver(DriverName, func(ctx context.Context, confW *config.Wrapper) (storage.Store, error) {
		conf := new(Conf)
		if err := confW.GetSection(conf); err != nil {
			return nil, fmt.Errorf("failed to read blob configuration: %w", err)
		}

		bucket, err := newBucket(ctx, conf)
		if err != nil {
			return nil, err
		}

		if err := validateOrCreateDir(conf.WorkDir); err != nil {
			return nil, fmt.Errorf("failed to create work directory: %w", err)
		}

		return NewStore(ctx, conf, NewCloner(bucket, storeFS{dir: filepath.Join(conf.WorkDir, dotcache)}))
	})
}

func newBucket(ctx context.Context, conf *Conf) (*blob.Bucket, error) {
	u, err := url.Parse(conf.Bucket)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bucket URL %q: %w", conf.Bucket, err)
	}
	var bucket *blob.Bucket
	switch u.Scheme {
	case "s3":
		bucket, err = openS3Bucket(ctx, conf, u)
	case "gs":
		bucket, err = openGSBucket(ctx, conf, u)
	default:
		err = ErrUnsupportedBucketScheme
	}
	if err != nil {
		return nil, err
	}

	if conf.Prefix != "" {
		bucket = blob.PrefixedBucket(bucket, conf.Prefix)
	}

	return bucket, nil
}

func openGSBucket(ctx context.Context, conf *Conf, bucketURL *url.URL) (*blob.Bucket, error) {
	creds, err := gcp.DefaultCredentials(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not get default GCP credentials: %w", err)
	}
	client, err := gcp.NewHTTPClient(gcp.DefaultTransport(), creds.TokenSource)
	if err != nil {
		return nil, fmt.Errorf("could not create gcp HTTP client: %w", err)
	}
	client.Timeout = *conf.RequestTimeout
	opener := gcsblob.URLOpener{Client: client}
	// The following query parameters are supported:
	//
	//   - access_id: sets Options.GoogleAccessID
	//   - private_key_path: path to read for Options.PrivateKey
	//
	// Currently their use is limited to SignedURL.
	return opener.OpenBucketURL(ctx, bucketURL)
}

func openS3Bucket(ctx context.Context, conf *Conf, bucketURL *url.URL) (*blob.Bucket, error) {
	client := &http.Client{Timeout: *conf.RequestTimeout}
	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{HTTPClient: client},
		// Force enable Shared Config support
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return nil, err
	}
	opener := s3blob.URLOpener{ConfigProvider: sess}
	return opener.OpenBucketURL(ctx, bucketURL)
}

func validateOrCreateDir(dir string) error {
	fileInfo, err := os.Stat(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to stat directory %q: %w", dir, err)
		}

		if err := os.MkdirAll(dir, 0o775); err != nil { //nolint:mnd
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	if fileInfo != nil && !fileInfo.IsDir() {
		return fmt.Errorf("dir is not a directory: %s", dir)
	}

	return nil
}

type bucketCloner interface {
	Clean() error
	Clone(ctx context.Context) (*CloneResult, error)
}

type Store struct {
	*storage.SubscriptionManager
	log      *zap.SugaredLogger
	conf     *Conf
	idx      index.Index
	cloner   bucketCloner
	cacheFS  fs.FS
	workFS   fs.FS
	cacheDir string
	workDir  string
}

func (s *Store) Subscribe(sub storage.Subscriber) {
	s.SubscriptionManager.Subscribe(sub)
}

func NewStore(ctx context.Context, conf *Conf, cloner bucketCloner) (*Store, error) {
	s := &Store{
		log:                 zap.S().Named(DriverName).With("bucket", conf.Bucket, "workDir", conf.WorkDir),
		conf:                conf,
		cloner:              cloner,
		SubscriptionManager: storage.NewSubscriptionManager(ctx),
	}

	if err := s.init(ctx); err != nil {
		s.log.Errorw("Failed to initialize blob store", "error", err)
		return nil, err
	}

	return s, nil
}

func (s *Store) init(ctx context.Context) error {
	s.cacheDir = filepath.Join(s.conf.WorkDir, dotcache)
	s.cacheFS = os.DirFS(s.cacheDir)
	if err := validateOrCreateDir(s.cacheDir); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	cr, err := s.clone(ctx)
	if err != nil {
		s.log.Errorw("Failed to clone blob store", "error", err)
		return fmt.Errorf("failed to clone blob store: %w", err)
	}

	idx, newWorkDir, err := s.buildIndex(ctx, cr.all)
	if err != nil {
		return fmt.Errorf("failed to build index from the new set of files: %w", err)
	}

	s.workDir = newWorkDir
	s.workFS = os.DirFS(newWorkDir)
	s.idx = idx
	go s.pollForUpdates(ctx)

	return nil
}

func (s *Store) updateIndex(ctx context.Context) error {
	s.log.Debug("Checking for updates")
	cr, err := s.clone(ctx)
	if err != nil {
		return fmt.Errorf("failed to clone blob store: %w", err)
	}

	if cr.isEmpty() {
		s.log.Debug("No changes")
		return nil
	}

	s.log.Infof("Detected changes: added or updated (%d), deleted (%d)", len(cr.addedOrUpdated), len(cr.deleted))

	idx, newWorkDir, err := s.buildIndex(ctx, cr.all)
	if err != nil {
		return fmt.Errorf("failed to build index from the new set of files: %w", err)
	}

	oldWorkDir := s.workDir
	s.workDir = newWorkDir
	s.workFS = os.DirFS(newWorkDir)
	s.idx = idx

	evts := make([]storage.Event, 0, len(cr.addedOrUpdated)+len(cr.deleted))
	for _, i := range cr.addedOrUpdated {
		e, err := s.addOrUpdateEvent(i.etag, i.file)
		if err != nil {
			return fmt.Errorf("failed to create add or update event: %w", err)
		}
		evts = append(evts, e)
	}

	for _, i := range cr.deleted {
		e, err := s.deleteEvent(i.etag, i.file)
		if err != nil {
			return fmt.Errorf("failed to create delete event: %w", err)
		}
		evts = append(evts, e)
	}

	s.NotifySubscribers(evts...)
	s.log.Info("Index updated")

	if err := s.cloner.Clean(); err != nil {
		s.log.Warnw("Failed to clean up the cache", "error", err)
	}

	if err := os.RemoveAll(oldWorkDir); err != nil && !os.IsNotExist(err) {
		s.log.Warnw(fmt.Sprintf("Failed to remove old work directory %s", oldWorkDir), "error", err)
	}

	return nil
}

func (s *Store) addOrUpdateEvent(etag, file string) (storage.Event, error) {
	if schemaFile, ok := util.RelativeSchemaPath(file); ok {
		return storage.NewSchemaEvent(storage.EventAddOrUpdateSchema, schemaFile), nil
	}

	p, err := policy.ReadPolicyFromFile(s.cacheFS, etag)
	if err != nil {
		return storage.Event{}, fmt.Errorf("failed to read policy from file %s: %w", etag, err)
	}
	wp := policy.Wrap(policy.WithSourceAttributes(p, driverSourceAttr, etagSourceAttr(etag)))

	return storage.NewPolicyEvent(storage.EventAddOrUpdatePolicy, wp.ID), nil
}

func (s *Store) deleteEvent(etag, file string) (storage.Event, error) {
	if schemaFile, ok := util.RelativeSchemaPath(file); ok {
		return storage.NewSchemaEvent(storage.EventDeleteSchema, schemaFile), nil
	}

	p, err := policy.ReadPolicyFromFile(s.cacheFS, etag)
	if err != nil {
		return storage.Event{}, fmt.Errorf("failed to read policy from file %s: %w", etag, err)
	}

	return storage.NewPolicyEvent(storage.EventDeleteOrDisablePolicy, namer.GenModuleID(p)), nil
}

func (s *Store) clone(ctx context.Context) (*CloneResult, error) {
	ctx, cancelFunc := s.conf.getCloneCtx(ctx)
	defer cancelFunc()

	return s.cloner.Clone(ctx)
}

func (s *Store) pollForUpdates(ctx context.Context) {
	if s.conf.UpdatePollInterval <= 0 {
		s.log.Info("Polling disabled: new updates will not be pulled automatically")
		return
	}

	s.log.Infof("Polling for updates every %s", s.conf.UpdatePollInterval)

	ticker := time.NewTicker(s.conf.UpdatePollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.log.Info("Stopped polling for updates")
			return
		case <-ticker.C:
			err := s.updateIndex(ctx)
			if err != nil {
				if errors.Is(err, &indexBuildError{}) {
					s.log.Warnw("Remote store is in an invalid state", "error", err)
					s.log.Warnf("Remote store is in an invalid state. Using the last good state from %s", s.workDir)
				} else {
					s.log.Warnw("Failed to check for updates", "error", err)
				}

				metrics.Inc(ctx, metrics.StoreSyncErrorCount(), metrics.DriverKey(DriverName))
			}

			metrics.Inc(ctx, metrics.StorePollCount(), metrics.DriverKey(DriverName))
		}
	}
}

func (s *Store) createSymlink(destination, source string) error {
	if _, err := os.Lstat(source); err == nil {
		if err := os.Remove(source); err != nil {
			return fmt.Errorf("failed to delete left-over symlink at %q: %w", source, err)
		}
	}

	// If there are subdirectories in the blob storage we need to create them in the source directory before creation
	// of the symlink
	//nolint:mnd
	if err := os.MkdirAll(filepath.Dir(source), 0o775); err != nil {
		return fmt.Errorf("failed to create directory %q: %w", filepath.Dir(source), err)
	}

	if err := os.Symlink(destination, source); err != nil {
		return fmt.Errorf("failed to create symlink to destination %q from source %q: %w", destination, source, err)
	}

	return nil
}

func (s *Store) createSymlinks(all map[string][]string, destDir, sourceDir string) error {
	for etag, files := range all {
		for _, file := range files {
			source := filepath.Join(sourceDir, file)
			dest := filepath.Join(destDir, etag)
			if err := s.createSymlink(dest, source); err != nil {
				return fmt.Errorf("failed to create symbolic link for %s: %w", source, err)
			}
		}
	}

	return nil
}

type indexBuildError struct {
	err error
	// workDir is the temporary work directory which the store tried build an index from the new set of files
	workDir string
}

func (e *indexBuildError) Error() string {
	return fmt.Sprintf("failed to build index at temporary work directory at %s: %v", e.workDir, e.err)
}

// buildIndex creates a new work directory with its name set to current timestamp, creates symlinks targeted to
// s.cacheDir according to the given map 'all' and tries to build a temporary index to see if there are any errors
// with the incoming policies/schemas. If there are no errors returns the index built and the path to the new work directory.
func (s *Store) buildIndex(ctx context.Context, all map[string][]string) (index.Index, string, error) {
	newWorkDir := filepath.Join(s.conf.WorkDir, strconv.FormatInt(time.Now().Unix(), 10))
	if err := validateOrCreateDir(newWorkDir); err != nil {
		return nil, "", fmt.Errorf("failed to create new work directory %s: %w", newWorkDir, err)
	}

	if err := s.createSymlinks(all, s.cacheDir, newWorkDir); err != nil {
		return nil, "", fmt.Errorf("failed to create symbolic links for the new work directory: %w", err)
	}

	idx, err := index.Build(ctx, os.DirFS(newWorkDir), index.WithRootDir("."), index.WithSourceAttributes(driverSourceAttr))
	if err != nil {
		if rerr := os.RemoveAll(newWorkDir); rerr != nil && !os.IsNotExist(rerr) {
			return nil, "", errors.Join(err, fmt.Errorf("failed to remove directory %s: %w", newWorkDir, rerr))
		}

		return nil, "", &indexBuildError{workDir: newWorkDir, err: err}
	}

	return idx, newWorkDir, nil
}

func (s *Store) Driver() string {
	return DriverName
}

func (s *Store) GetFirstMatch(_ context.Context, candidates []namer.ModuleID) (*policy.CompilationUnit, error) {
	return s.idx.GetFirstMatch(candidates)
}

func (s *Store) GetAll(_ context.Context, modIDs []namer.ModuleID) ([]*policy.CompilationUnit, error) {
	return s.idx.GetAll(modIDs)
}

func (s *Store) GetCompilationUnits(_ context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error) {
	return s.idx.GetCompilationUnits(ids...)
}

func (s *Store) GetDependents(_ context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error) {
	return s.idx.GetDependents(ids...)
}

func (s *Store) InspectPolicies(ctx context.Context, params storage.ListPolicyIDsParams) (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	return s.idx.InspectPolicies(ctx, params.IDs...)
}

func (s *Store) ListPolicyIDs(ctx context.Context, params storage.ListPolicyIDsParams) ([]string, error) {
	return s.idx.ListPolicyIDs(ctx, params.IDs...)
}

func (s *Store) ListSchemaIDs(ctx context.Context) ([]string, error) {
	return s.idx.ListSchemaIDs(ctx)
}

func (s *Store) LoadSchema(ctx context.Context, url string) (io.ReadCloser, error) {
	return s.idx.LoadSchema(ctx, url)
}

func (s *Store) LoadPolicy(ctx context.Context, file ...string) ([]*policy.Wrapper, error) {
	return s.idx.LoadPolicy(ctx, file...)
}

func (s *Store) RepoStats(ctx context.Context) storage.RepoStats {
	return s.idx.RepoStats(ctx)
}

func (s *Store) Reload(ctx context.Context) error {
	cr, err := s.clone(ctx)
	if err != nil {
		return fmt.Errorf("failed to clone blob store: %w", err)
	}

	idx, newWorkDir, err := s.buildIndex(ctx, cr.all)
	if err != nil {
		if errors.Is(err, &indexBuildError{}) {
			s.log.Warnw("Remote store is in an invalid state", "error", err)
			s.log.Warnf("Remote store is in an invalid state. Using the last good state from %s", s.workDir)
		}

		return fmt.Errorf("failed to reload state from remote store: %w", err)
	}

	oldWorkDir := s.workDir
	s.workDir = newWorkDir
	s.workFS = os.DirFS(newWorkDir)
	s.idx = idx
	s.NotifySubscribers(storage.NewReloadEvent())

	if err := s.cloner.Clean(); err != nil {
		s.log.Warnw("Failed to clean up the cache", "error", err)
	}

	if err := os.RemoveAll(oldWorkDir); err != nil && !os.IsNotExist(err) {
		s.log.Warnw(fmt.Sprintf("Failed to remove old work directory %s", oldWorkDir), "error", err)
	}

	return nil
}

func etagSourceAttr(etag string) policy.SourceAttribute {
	return policy.SourceAttribute{Key: "etag", Value: structpb.NewStringValue(etag)}
}
