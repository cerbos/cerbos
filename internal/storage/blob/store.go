// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package blob

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

		cacheDir := filepath.Join(conf.WorkDir, dotcache, base64.URLEncoding.EncodeToString([]byte(conf.Bucket)))
		workDir := conf.WorkDir

		if err := createOrValidateDir(workDir); err != nil {
			return nil, fmt.Errorf("failed to create work directory: %w", err)
		}

		cloner, err := NewCloner(bucket, cacheDir)
		if err != nil {
			return nil, fmt.Errorf("failed to create cloner: %w", err)
		}

		workFS := newBlobFS(workDir)
		return NewStore(ctx, conf, workFS, cloner, symlinkerFunc(func(destination, source string) error {
			src := filepath.Join(workDir, source)
			dst := filepath.Join(cacheDir, destination)

			return os.Symlink(dst, src)
		}))
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

type bucketCloner interface {
	Clean() error
	Clone(ctx context.Context) (*CloneResult, error)
}

type symlinker interface {
	Symlink(destination, source string) error
}

type symlinkerFunc func(destination, source string) error

func (s symlinkerFunc) Symlink(destination, source string) error {
	return s(destination, source)
}

type Store struct {
	*storage.SubscriptionManager
	log         *zap.SugaredLogger
	conf        *Conf
	idx         index.Index
	cloner      bucketCloner
	symlink     symlinker
	workFS      FS
	currDirName string
	workDir     string
}

func (s *Store) Subscribe(sub storage.Subscriber) {
	s.SubscriptionManager.Subscribe(sub)
}

func NewStore(ctx context.Context, conf *Conf, workFS FS, cloner bucketCloner, symlink symlinker) (*Store, error) {
	s := &Store{
		log: zap.S().Named(DriverName).With(
			"bucket", conf.Bucket,
			"workDir", conf.WorkDir,
		),
		conf:                conf,
		workDir:             conf.WorkDir,
		workFS:              workFS,
		cloner:              cloner,
		symlink:             symlink,
		SubscriptionManager: storage.NewSubscriptionManager(ctx),
	}

	if err := s.init(ctx); err != nil {
		s.log.Errorw("Failed to initialize blob store", "error", err)
		return nil, err
	}

	return s, nil
}

func (s *Store) init(ctx context.Context) error {
	cr, err := s.clone(ctx)
	if err != nil {
		s.log.Errorw("Failed to clone blob store", "error", err)
		return fmt.Errorf("failed to clone blob store: %w", err)
	}

	idx, dirName, _, err := s.buildIndex(ctx, cr.all)
	if err != nil {
		return fmt.Errorf("failed to build index from the new set of files: %w", err)
	}

	s.currDirName = dirName
	s.idx = idx
	go s.pollForUpdates(ctx)

	if err := s.cloner.Clean(); err != nil {
		s.log.Warnw("Failed to clean up the cache", "error", err)
	}

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

	idx, dirName, ts, err := s.buildIndex(ctx, cr.all)
	if err != nil {
		return fmt.Errorf("failed to build index from the new set of files: %w", err)
	}

	evts := make([]storage.Event, 0, len(cr.addedOrUpdated)+len(cr.deleted))
	for _, i := range cr.deleted {
		e, err := s.deleteEvent(i.file)
		if err != nil {
			return fmt.Errorf("failed to create delete event: %w", err)
		}
		evts = append(evts, e)
	}

	oldDirName := s.currDirName
	s.currDirName = dirName
	s.idx = idx

	for _, i := range cr.addedOrUpdated {
		e, err := s.addOrUpdateEvent(i.etag, i.file, ts)
		if err != nil {
			return fmt.Errorf("failed to create add or update event: %w", err)
		}
		evts = append(evts, e)
	}

	s.NotifySubscribers(evts...)
	s.log.Info("Index updated")

	if err := s.cloner.Clean(); err != nil {
		s.log.Warnw("Failed to clean up the cache", "error", err)
	}

	if err := s.workFS.RemoveAll(oldDirName); err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.log.Warnw(fmt.Sprintf("Failed to remove old work directory %s", oldDirName), "error", err)
	}

	return nil
}

func (s *Store) addOrUpdateEvent(etag, file string, ts int64) (storage.Event, error) {
	if schemaFile, ok := util.RelativeSchemaPath(file); ok {
		return storage.NewSchemaEvent(storage.EventAddOrUpdateSchema, schemaFile), nil
	}

	p, err := policy.ReadPolicyFromFile(newBlobFS(filepath.Join(s.workDir, s.currDirName)), file)
	if err != nil {
		return storage.Event{}, fmt.Errorf("failed to read policy from file %s: %w", file, err)
	}
	wp := policy.Wrap(policy.WithSourceAttributes(p, driverSourceAttr, etagSourceAttr(etag), indexBuildTSSourceAttr(ts)))

	return storage.NewPolicyEvent(storage.EventAddOrUpdatePolicy, wp.ID), nil
}

func (s *Store) deleteEvent(file string) (storage.Event, error) {
	if schemaFile, ok := util.RelativeSchemaPath(file); ok {
		return storage.NewSchemaEvent(storage.EventDeleteSchema, schemaFile), nil
	}

	p, err := policy.ReadPolicyFromFile(newBlobFS(filepath.Join(s.workDir, s.currDirName)), file)
	if err != nil {
		return storage.Event{}, fmt.Errorf("failed to read policy from file %s: %w", file, err)
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
			if err := s.updateIndex(ctx); err != nil {
				if errors.Is(err, &indexBuildError{}) {
					s.log.Warnw("Remote store is in an invalid state", "error", err)
					s.log.Warnf("Remote store is in an invalid state. Using the last good state from %s", s.workDir)
				} else {
					s.log.Warnw("Failed to check for updates", "error", err)
				}
			}
		}
	}
}

func (s *Store) createSymlink(tmpDir, destination, source string) error {
	src := filepath.Join(tmpDir, source)
	if err := s.workFS.Remove(src); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to delete left-over symlink at %s: %w", src, err)
	}

	// If there are subdirectories in the blob storage we need to create them in the source directory before creation
	// of the symlink
	if err := s.workFS.MkdirAll(filepath.Dir(src), perm775); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", src, err)
	}

	if err := s.symlink.Symlink(destination, src); err != nil {
		return fmt.Errorf("failed to create symlink to destination %s from source %s: %w", destination, src, err)
	}

	return nil
}

func (s *Store) createSymlinks(all map[string][]string, tmpDir string) error {
	for etag, files := range all {
		for _, file := range files {
			if err := s.createSymlink(tmpDir, etag, file); err != nil {
				return fmt.Errorf("failed to create symbolic link for %s: %w", file, err)
			}
		}
	}

	return nil
}

type indexBuildError struct {
	err error
	// dir is the temporary work directory which the store tried build an index from the new set of files
	dir string
}

func (e *indexBuildError) Error() string {
	return fmt.Sprintf("failed to build index at temporary work directory at %s: %v", e.dir, e.err)
}

// buildIndex creates a new work directory with its name set to current timestamp, creates symlinks targeted to
// s.cacheDir according to the given map 'all' and tries to build a temporary index to see if there are any errors
// with the incoming policies/schemas. If there are no errors returns the index built and the path to the new work directory.
func (s *Store) buildIndex(ctx context.Context, all map[string][]string) (idx index.Index, currDirName string, ts int64, err error) {
	ts = time.Now().UnixMilli()
	defer func() {
		metrics.Inc(ctx, metrics.StorePollCount(), metrics.DriverKey(DriverName))
		if err != nil {
			metrics.Inc(ctx, metrics.StoreSyncErrorCount(), metrics.DriverKey(DriverName))
		} else {
			metrics.Record(ctx, metrics.StoreLastSuccessfulRefresh(), ts, metrics.DriverKey(DriverName))
		}
	}()

	dir, err := os.MkdirTemp(s.workDir, fmt.Sprintf("cerbos-%s-%d-*", DriverName, ts))
	if err != nil {
		return nil, "", 0, fmt.Errorf("failed to create new temporary storage directory: %w", err)
	}

	if currDirName, err = filepath.Rel(s.workDir, dir); err != nil {
		return nil, "", 0, fmt.Errorf("failed to determine relative path of directory %s: %w", dir, err)
	}

	if err := s.createSymlinks(all, currDirName); err != nil {
		return nil, "", 0, fmt.Errorf("failed to create symbolic links for the new work directory: %w", err)
	}

	s.log.Debugw("Building index", "dir", dir)
	if idx, err = index.Build(ctx, newBlobFS(dir), index.WithRootDir("."), index.WithSourceAttributes(driverSourceAttr)); err != nil {
		if rerr := s.workFS.RemoveAll(currDirName); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			return nil, "", 0, errors.Join(err, fmt.Errorf("failed to remove directory %s: %w", dir, rerr))
		}

		return nil, "", 0, &indexBuildError{dir: dir, err: err}
	}

	return idx, currDirName, ts, nil
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

	idx, dirName, _, err := s.buildIndex(ctx, cr.all)
	if err != nil {
		if errors.Is(err, &indexBuildError{}) {
			s.log.Warnw("Remote store is in an invalid state", "error", err)
			s.log.Warnf("Remote store is in an invalid state. Using the last good state from %s", s.workDir)
		}

		return fmt.Errorf("failed to reload state from remote store: %w", err)
	}

	oldDirName := s.currDirName
	s.currDirName = dirName
	s.idx = idx
	s.NotifySubscribers(storage.NewReloadEvent())

	if err := s.cloner.Clean(); err != nil {
		s.log.Warnw("Failed to clean up the cache", "error", err)
	}

	if err := s.workFS.RemoveAll(oldDirName); err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.log.Warnw(fmt.Sprintf("Failed to remove old work directory %s", oldDirName), "error", err)
	}

	return nil
}

func indexBuildTSSourceAttr(ts int64) policy.SourceAttribute {
	return policy.SourceAttribute{Key: "index_build_ts", Value: structpb.NewNumberValue(float64(ts))}
}

func etagSourceAttr(etag string) policy.SourceAttribute {
	return policy.SourceAttribute{Key: "etag", Value: structpb.NewStringValue(etag)}
}
