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
	"time"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"go.uber.org/zap"
	"gocloud.dev/blob"
	"google.golang.org/protobuf/types/known/structpb"

	// Import gcsblob package to register GCS driver.
	"gocloud.dev/blob/gcsblob"
	"gocloud.dev/blob/s3blob"
	"gocloud.dev/gcp"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
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

		if err := validateOrCreateWorkDir(conf.WorkDir); err != nil {
			return nil, err
		}

		c, err := NewCloner(bucket, storeFS{dir: conf.WorkDir})
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

func validateOrCreateWorkDir(workDir string) error {
	fileInfo, err := os.Stat(workDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to stat workDir %q: %w", workDir, err)
		}

		if err := os.MkdirAll(workDir, 0o744); err != nil { //nolint:gomnd
			return fmt.Errorf("failed to create workDir %q: %w", workDir, err)
		}
	}

	if fileInfo != nil && !fileInfo.IsDir() {
		return fmt.Errorf("workDir is not a directory: %s", workDir)
	}

	return nil
}

type bucketCloner interface {
	Clone(ctx context.Context) (*CloneResult, error)
}

type Store struct {
	*storage.SubscriptionManager
	log    *zap.SugaredLogger
	conf   *Conf
	idx    index.Index
	cloner bucketCloner
	fsys   fs.FS
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

var ErrPartialFailureToDownloadOnInit = errors.New("failed to download some files from the bucket")

func (s *Store) init(ctx context.Context) error {
	s.fsys = os.DirFS(s.conf.WorkDir)

	if cr, err := s.clone(ctx); err != nil {
		s.log.Errorw("Failed to clone blob store", "error", err)
		return err
	} else if cr.failuresCount > 0 {
		s.log.Errorf("Failed to download (%d) files from the bucket %q", cr.failuresCount, s.conf.Bucket)
		return ErrPartialFailureToDownloadOnInit
	}

	var err error
	s.idx, err = index.Build(ctx, s.fsys, index.WithRootDir("."), index.WithSourceAttributes(driverSourceAttr))
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

	var p *policyv1.Policy
	var event storage.Event
	for _, f := range changes.updateOrAdd {
		if schemaFile, ok := util.RelativeSchemaPath(f.file); ok {
			s.NotifySubscribers(storage.NewSchemaEvent(storage.EventAddOrUpdateSchema, schemaFile))
			continue
		}

		p, err = policy.ReadPolicyFromFile(s.fsys, f.file)
		if err != nil {
			return err
		}
		entry := index.Entry{File: f.file, Policy: policy.Wrap(policy.WithSourceAttributes(p, driverSourceAttr, etagSourceAttr(f.etag)))}
		event, err = s.idx.AddOrUpdate(entry)
		if err != nil {
			return err
		}
		s.NotifySubscribers(event)
	}

	for _, f := range changes.delete {
		if schemaFile, ok := util.RelativeSchemaPath(f); ok {
			s.NotifySubscribers(storage.NewSchemaEvent(storage.EventDeleteSchema, schemaFile))
			continue
		}

		entry := index.Entry{File: f}
		event, err = s.idx.Delete(entry)
		if err != nil {
			return err
		}
		s.NotifySubscribers(event)
	}

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

func (s *Store) Driver() string {
	return DriverName
}

func (s *Store) GetFirstMatch(_ context.Context, candidates []namer.ModuleID) (*policy.CompilationUnit, error) {
	return s.idx.GetFirstMatch(candidates)
}

func (s *Store) GetCompilationUnits(_ context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error) {
	return s.idx.GetCompilationUnits(ids...)
}

func (s *Store) GetDependents(_ context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error) {
	return s.idx.GetDependents(ids...)
}

func (s *Store) InspectPolicies(ctx context.Context, _ storage.ListPolicyIDsParams) (map[string]*responsev1.InspectPoliciesResponse_Inspection, error) {
	policyIDs, err := s.idx.ListPolicyIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}
	if len(policyIDs) == 0 {
		return nil, nil
	}

	policies, err := s.LoadPolicy(ctx, policyIDs...)
	if err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	metadata := make(map[string]*responsev1.InspectPoliciesResponse_Inspection)
	for _, p := range policies {
		actions := policy.Actions(p.Policy)
		if len(actions) > 0 {
			metadata[p.FQN] = &responsev1.InspectPoliciesResponse_Inspection{
				Actions: actions,
			}
		}
	}

	return metadata, nil
}

func (s *Store) ListPolicyIDs(ctx context.Context, _ storage.ListPolicyIDsParams) ([]string, error) {
	return s.idx.ListPolicyIDs(ctx)
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
