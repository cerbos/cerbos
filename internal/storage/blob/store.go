// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package blob

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"go.uber.org/zap"
	"gocloud.dev/blob"

	// Import gcsblob package to register GCS driver.
	"gocloud.dev/blob/gcsblob"
	"gocloud.dev/blob/s3blob"
	"gocloud.dev/gcp"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/index"
)

const DriverName = "blob"

var _ storage.Store = (*Store)(nil)

var ErrUnsupportedBucketScheme = errors.New("currently only \"s3\" and \"gs\" bucket URL schemes are supported")

func init() {
	storage.RegisterDriver(DriverName, func(ctx context.Context) (storage.Store, error) {
		conf := &Conf{}
		if err := config.GetSection(conf); err != nil {
			return nil, err
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
	s.idx, err = index.Build(ctx, s.fsys, index.WithRootDir("."))
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
		p, err = policy.ReadPolicyFromFile(s.fsys, f)
		if err != nil {
			return err
		}
		entry := index.Entry{File: f, Policy: policy.Wrap(p)}
		event, err = s.idx.AddOrUpdate(entry)
		if err != nil {
			return err
		}
		s.NotifySubscribers(event)
	}
	for _, f := range changes.delete {
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
			}
		}
	}
}

func (s *Store) Driver() string {
	return DriverName
}

func (s *Store) GetCompilationUnits(_ context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error) {
	return s.idx.GetCompilationUnits(ids...)
}

func (s *Store) GetDependents(_ context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error) {
	return s.idx.GetDependents(ids...)
}

func (s *Store) GetPolicies(ctx context.Context) ([]*policy.Wrapper, error) {
	return s.idx.GetPolicies(ctx)
}
