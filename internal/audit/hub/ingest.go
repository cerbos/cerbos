// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cloud-api/base"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
	"github.com/cerbos/cloud-api/logcap"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
)

type ErrIngestBackoff struct {
	underlying error
	Backoff    time.Duration
}

func (e ErrIngestBackoff) Error() string {
	return e.underlying.Error()
}

type IngestSyncer interface {
	Sync(context.Context, *logsv1.IngestBatch) error
}

type Impl struct {
	client *logcap.Client
	log    *zap.Logger
}

func NewIngestSyncer(conf *Conf, logger *zap.Logger) (*Impl, error) {
	pdpID := util.PDPIdentifier(conf.Ingest.Credentials.PDPID)

	logger = logger.Named("ingest").With(zap.String("instance", pdpID.Instance))

	creds, err := conf.Ingest.Credentials.ToCredentials()
	if err != nil {
		return nil, errors.New("failed to generate credentials from config")
	}

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: conf.Ingest.Connection.TLS.Authority,
	}

	caCertPath := conf.Ingest.Connection.TLS.CACert
	if caCertPath != "" {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert from %q: %w", caCertPath, err)
		}

		tlsConf.RootCAs = x509.NewCertPool()
		if !tlsConf.RootCAs.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certs")
		}
	}

	clientConf := logcap.ClientConf{
		ClientConf: base.ClientConf{
			Logger:            zapr.NewLogger(logger),
			PDPIdentifier:     pdpID,
			TLS:               tlsConf,
			Credentials:       creds,
			APIEndpoint:       conf.Ingest.Connection.APIEndpoint,
			BootstrapEndpoint: conf.Ingest.Connection.BootstrapEndpoint,
			RetryWaitMin:      conf.Ingest.Connection.MinRetryWait,
			RetryWaitMax:      conf.Ingest.Connection.MaxRetryWait,
			RetryMaxAttempts:  int(conf.Ingest.Connection.NumRetries),
			HeartbeatInterval: conf.Ingest.Connection.HeartbeatInterval,
		},
	}

	client, err := logcap.NewClient(clientConf)
	if err != nil {
		return nil, err
	}

	return &Impl{
		client: client,
		log:    logger,
	}, nil
}

func (i *Impl) Sync(ctx context.Context, batch *logsv1.IngestBatch) error {
	if err := i.client.Ingest(ctx, batch); err != nil {
		i.log.Error("Failed to sync batch", zap.Error(err))
		return err
	}

	return nil
}
