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
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/util"
)

const DriverName = "blob"

var (
	_ storage.SourceStore = (*Store)(nil)
	_ storage.Reloadable  = (*Store)(nil)
)

var ErrUnsupportedBucketScheme = errors.New("currently only \"s3\" and \"gs\" bucket URL schemes are supported")

var driverSourceAttr = policy.SourceDriver(DriverName)

func etagSourceAttr(etag []byte) policy.SourceAttribute {
	return policy.SourceAttribute{Key: "etag", Value: structpb.NewStringValue(string(etag))}
}

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

		if err := removeAndCreateDir(conf.CacheDir); err != nil {
			return nil, err
		}

		if err := removeAndCreateDir(conf.WorkDir); err != nil {
			return nil, err
		}

		c, err := NewCloner(bucket, storeFS{dir: conf.CacheDir})
		if err != nil {
			return nil, err
		}

		return NewStore(ctx, conf, c)
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

func removeAndCreateDir(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("failed to remove directory %q: %w", dir, err)
	}

	if err := os.MkdirAll(dir, 0o744); err != nil { //nolint:mnd
		return fmt.Errorf("failed to create dir %q: %w", dir, err)
	}

	return nil
}

type bucketCloner interface {
	Clone(ctx context.Context) (*CloneResult, error)
}

type Store struct {
	*storage.SubscriptionManager
	log              *zap.SugaredLogger
	conf             *Conf
	idx              index.Index
	cloner           bucketCloner
	cacheFS          fs.FS
	workFS           fs.FS
	deleteLater      map[string]deleteInfo
	updateOrAddLater []fileInfo
}

func (s *Store) Subscribe(sub storage.Subscriber) {
	s.SubscriptionManager.Subscribe(sub)
}

func NewStore(ctx context.Context, conf *Conf, cloner bucketCloner) (*Store, error) {
	s := &Store{
		log:                 zap.S().Named(DriverName).With("bucket", conf.Bucket, "cacheDir", conf.CacheDir, "workDir", conf.WorkDir),
		conf:                conf,
		cloner:              cloner,
		SubscriptionManager: storage.NewSubscriptionManager(ctx),
		deleteLater:         make(map[string]deleteInfo),
	}

	if err := s.init(ctx); err != nil {
		s.log.Errorw("Failed to initialize blob store", "error", err)
		return nil, err
	}

	return s, nil
}

var ErrPartialFailureToDownloadOnInit = errors.New("failed to download some files from the bucket")

func (s *Store) clearWorkDir() error {
	absWorkDir, err := filepath.Abs(s.conf.WorkDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute path of work dir: %w", err)
	}

	if err := filepath.WalkDir(s.conf.WorkDir, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if path == absWorkDir {
			return nil
		}

		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("failed to remove at path %q: %w", path, err)
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to walk directory: %w", err)
	}

	return nil
}

func (s *Store) init(ctx context.Context) error {
	s.cacheFS = os.DirFS(s.conf.CacheDir)
	s.workFS = os.DirFS(s.conf.WorkDir)
	if err := s.clearWorkDir(); err != nil {
		return fmt.Errorf("failed to clear work dir %q: %w", s.conf.WorkDir, err)
	}

	cr, err := s.clone(ctx)
	if err != nil {
		s.log.Errorw("Failed to clone blob store", "error", err)
		return fmt.Errorf("failed to clone blob store: %w", err)
	} else if cr.failuresCount > 0 {
		s.log.Errorf("Failed to download (%d) files from the bucket %q", cr.failuresCount, s.conf.Bucket)
		return ErrPartialFailureToDownloadOnInit
	}

	if err := s.createSymlinks(s.conf.WorkDir, cr.fileToSymlink); err != nil {
		return fmt.Errorf("failed to create symbolic links for the files: %w", err)
	}

	s.idx, err = index.Build(ctx, s.workFS, index.WithRootDir("."), index.WithSourceAttributes(driverSourceAttr))
	if err != nil {
		s.log.Errorw("Failed to build index", "error", err)
		return err
	}

	go s.pollForUpdates(ctx)

	return nil
}

func (s *Store) clone(ctx context.Context) (*CloneResult, error) {
	ctx, cancelFunc := s.conf.getCloneCtx(ctx)
	defer cancelFunc()

	return s.cloner.Clone(ctx)
}

func (s *Store) updateIndex(ctx context.Context) error {
	s.log.Debug("Checking for updates")

	changes, err := s.clone(ctx)
	if err != nil {
		return err
	}

	if failures := changes.failures(); failures > 0 {
		s.log.Warnf("Failed to download (%d) files", failures)
	}

	if changes.isEmpty() {
		s.log.Debug("No changes")
		return nil
	}

	s.log.Infof("Detected changes: added or updated (%d), deleted (%d)", len(changes.updateOrAdd), len(changes.delete))

	tmpIndexDir, err := os.MkdirTemp("", "cerbos-blob-index-dir-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory for index: %w", err)
	}
	defer os.RemoveAll(tmpIndexDir)
	s.log.Debugw("Temporary index directory is created", "indexDir", tmpIndexDir)

	if err := s.createSymlinks(tmpIndexDir, changes.fileToSymlink); err != nil {
		s.log.Errorw("Failed to create symbolic links for the files", "error", err)
		return err
	}

	tmpIndexFS := os.DirFS(tmpIndexDir)
	if _, err := index.Build(ctx, tmpIndexFS, index.WithRootDir("."), index.WithSourceAttributes(driverSourceAttr)); err != nil {
		for _, delInfo := range changes.delete {
			s.deleteLater[delInfo.file] = delInfo
		}
		s.updateOrAddLater = append(s.updateOrAddLater, changes.updateOrAdd...)
		s.log.Errorw("Failed to build the temporary index from the changed files", "error", err)
		return err
	}

	absCacheDir, err := filepath.Abs(s.conf.CacheDir)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path of the cache directory %q: %w", s.conf.CacheDir, err)
	}

	absWorkDir, err := filepath.Abs(s.conf.WorkDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute path of the work directory: %w", err)
	}

	for _, file := range changes.updateOrAdd {
		delete(s.deleteLater, file.file)
		symlink, ok := changes.fileToSymlink[file.file]
		if !ok {
			return fmt.Errorf("failed to find symlink for file %q", file.file)
		}

		if err := s.addOrUpdate(tmpIndexFS, absCacheDir, symlink, absWorkDir, file.file, file.etag); err != nil {
			return fmt.Errorf("failed to add or update file: %w", err)
		}
	}

	for _, file := range s.updateOrAddLater {
		delete(s.deleteLater, file.file)
		if delInfo, ok := changes.delete[file.file]; ok {
			pathToSymlink := filepath.Join(absCacheDir, delInfo.symlink)
			s.log.Debugw("Removing symlink file removed between changes", "file", pathToSymlink)
			if err := os.Remove(pathToSymlink); err != nil {
				return fmt.Errorf("failed to remove symlink file removed between changes  %q: %w", pathToSymlink, err)
			}
			delete(changes.delete, file.file)
			continue
		}

		symlink, ok := changes.fileToSymlink[file.file]
		if !ok {
			return fmt.Errorf("failed to find symlink for file %q", file.file)
		}

		if err := s.addOrUpdate(tmpIndexFS, absCacheDir, symlink, absWorkDir, file.file, file.etag); err != nil {
			return fmt.Errorf("failed to add or update file: %w", err)
		}
	}
	clear(s.updateOrAddLater)

	for _, delInfo := range changes.delete {
		symlinkPath := filepath.Join(absCacheDir, delInfo.symlink)
		if err := s.delete(delInfo.file, absWorkDir, symlinkPath); err != nil {
			return fmt.Errorf("failed to delete file: %w", err)
		}
	}

	for _, delInfo := range s.deleteLater {
		symlinkPath := filepath.Join(absCacheDir, delInfo.symlink)
		if err := s.delete(delInfo.file, absWorkDir, symlinkPath); err != nil {
			return fmt.Errorf("failed to delete file: %w", err)
		}
	}
	clear(s.deleteLater)

	s.log.Info("Index updated")
	return nil
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
				s.log.Errorw("Failed to check for updates", "error", err)
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

	//nolint:mnd
	if err := os.MkdirAll(filepath.Dir(source), 0o744); err != nil {
		return fmt.Errorf("failed to create directory %q: %w", filepath.Dir(source), err)
	}

	if err := os.Symlink(destination, source); err != nil {
		return fmt.Errorf("failed to create symlink to destination %q from source %q: %w", destination, source, err)
	}

	return nil
}

func (s *Store) createSymlinks(dir string, fileToSymlink map[string]string) error {
	absCacheDir, err := filepath.Abs(s.conf.CacheDir)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path of the cache directory %q: %w", s.conf.CacheDir, err)
	}

	for file, symlink := range fileToSymlink {
		source := filepath.Join(dir, file)
		destination := filepath.Join(absCacheDir, symlink)
		if err := s.createSymlink(destination, source); err != nil {
			return fmt.Errorf("failed to create symlink to destinatiın %q from source %s: %w", destination, source, err)
		}
	}

	return nil
}

func (s *Store) addOrUpdate(fs fs.FS, destinationDir, destinationFile, sourceDir, sourceFile string, sourceETag []byte) error {
	source := filepath.Join(sourceDir, sourceFile)
	destination := filepath.Join(destinationDir, destinationFile)
	if err := s.createSymlink(destination, source); err != nil {
		return fmt.Errorf("failed to create symlink to destination %q from source %q: %w", destination, source, err)
	}

	if schemaFile, ok := util.RelativeSchemaPath(sourceFile); ok {
		s.NotifySubscribers(storage.NewSchemaEvent(storage.EventAddOrUpdateSchema, schemaFile))
		return nil
	}

	p, err := policy.ReadPolicyFromFile(fs, sourceFile)
	if err != nil {
		return err
	}

	entry := index.Entry{File: sourceFile, Policy: policy.Wrap(policy.WithSourceAttributes(p, driverSourceAttr, etagSourceAttr(sourceETag)))}
	event, err := s.idx.AddOrUpdate(entry)
	if err != nil {
		return err
	}

	s.NotifySubscribers(event)
	return nil
}

func (s *Store) delete(file, fileDir, pathToSymlink string) error {
	s.log.Debugw("Removing symlink file", "file", pathToSymlink)
	if err := os.Remove(pathToSymlink); err != nil {
		return fmt.Errorf("failed to remove symlink file %q: %w", pathToSymlink, err)
	}

	pathToFile := filepath.Join(fileDir, file)
	s.log.Debugw("Removing file", "file", pathToFile)
	if err := os.Remove(pathToFile); err != nil {
		return fmt.Errorf("failed to remove file %q: %w", pathToFile, err)
	}

	if schemaFile, ok := util.RelativeSchemaPath(file); ok {
		s.NotifySubscribers(storage.NewSchemaEvent(storage.EventDeleteSchema, schemaFile))
		return nil
	}

	entry := index.Entry{File: file}
	event, err := s.idx.Delete(entry)
	if err != nil {
		return err
	}

	s.NotifySubscribers(event)
	return nil
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
	changes, err := s.clone(ctx)
	if err != nil {
		return fmt.Errorf("failed to clone: %w", err)
	}

	if failures := changes.failures(); failures > 0 {
		logging.ReqScopeLog(ctx).Warn(fmt.Sprintf("Failed to download (%d) files", failures))
	}

	evts, err := s.idx.Reload(ctx)
	if err != nil {
		return fmt.Errorf("failed to reload the index: %w", err)
	}

	s.NotifySubscribers(evts...)

	return nil
}
