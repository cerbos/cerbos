// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cerbos/cerbos/internal/observability/logging"
	"go.uber.org/zap"
)

const DefaultTLSVersion = tls.VersionTLS12

type TLSReloader struct {
	cert           *tls.Certificate
	certPath       string
	keyPath        string
	mu             sync.RWMutex
	reloadInterval time.Duration
}

func newTLSReloader(ctx context.Context, reloadInterval time.Duration, certPath, keyPath string) (*TLSReloader, error) {
	reloader := &TLSReloader{
		certPath:       certPath,
		keyPath:        keyPath,
		reloadInterval: reloadInterval,
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS key pair: %w", err)
	}
	reloader.cert = &cert

	go func() {
		if err := reloader.reload(ctx); err != nil {
			logging.FromContext(ctx).Named("kafka").Error("Failed to reload TLS certificate", zap.Error(err))
		}
	}()

	return reloader, nil
}

func (r *TLSReloader) reload(ctx context.Context) error {
	ticker := time.NewTicker(r.reloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():

		case <-ticker.C:
			cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
			if err != nil {
				return fmt.Errorf("failed to load TLS key pair: %w", err)
			}

			r.mu.Lock()
			defer r.mu.Unlock()
			r.cert = &cert
		}
	}
}

func NewTLSConfig(ctx context.Context, reloadInterval time.Duration, insecureSkipVerify bool, caPath, certPath, keyPath string) (*tls.Config, error) {
	if caPath == "" || certPath == "" || keyPath == "" || reloadInterval == 0 {
		return nil, errors.New("invalid TLS configuration")
	}

	reloader, err := newTLSReloader(ctx, reloadInterval, certPath, keyPath)
	if err != nil {
		return nil, err
	}

	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificate")
	}

	// #nosec G402
	return &tls.Config{
		RootCAs:              caCertPool,
		ClientCAs:            caCertPool,
		MinVersion:           DefaultTLSVersion,
		InsecureSkipVerify:   insecureSkipVerify,
		GetClientCertificate: reloader.GetCertificateFunc(),
	}, nil
}

func (r *TLSReloader) GetCertificateFunc() func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(chi *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		r.mu.RLock()
		defer r.mu.RUnlock()

		return r.cert, nil
	}
}
