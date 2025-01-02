// Copyright 2021-2025 Zenauth Ltd.
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

func NewTLSConfig(ctx context.Context, reloadInterval time.Duration, insecureSkipVerify bool, caPath, certPath, keyPath string) (*tls.Config, error) {
	if certPath != "" && keyPath == "" || certPath == "" && keyPath != "" {
		return nil, errors.New("certPath and keyPath must both be empty or both be non-empty")
	}

	var caCertPool *x509.CertPool
	if caPath != "" {
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool, err = x509.SystemCertPool()
		if err != nil {
			caCertPool = x509.NewCertPool()
		}
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to append CA certificate")
		}
	}

	// #nosec G402
	tlsConfig := &tls.Config{
		RootCAs:            caCertPool,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecureSkipVerify, //nolint:gosec
	}

	if certPath == "" && keyPath == "" {
		return tlsConfig, nil
	}

	if reloadInterval == 0 {
		cert, err := loadTLSCert(certPath, keyPath)
		if err != nil {
			return nil, err
		}

		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
		return tlsConfig, nil
	}

	reloader, err := newTLSReloader(ctx, reloadInterval, certPath, keyPath)
	if err != nil {
		return nil, err
	}
	tlsConfig.GetClientCertificate = reloader.GetCertificateFunc()

	return tlsConfig, nil
}

func loadTLSCert(certPath, keyPath string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS key pair: %w", err)
	}
	return &cert, nil
}

type tlsReloader struct {
	cert           *tls.Certificate
	certPath       string
	keyPath        string
	mu             sync.RWMutex
	reloadInterval time.Duration
}

func newTLSReloader(ctx context.Context, reloadInterval time.Duration, certPath, keyPath string) (*tlsReloader, error) {
	reloader := &tlsReloader{
		certPath:       certPath,
		keyPath:        keyPath,
		reloadInterval: reloadInterval,
	}

	cert, err := loadTLSCert(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	reloader.cert = cert

	go func() {
		reloader.reload(ctx)
	}()

	return reloader, nil
}

func (r *tlsReloader) reload(ctx context.Context) {
	ticker := time.NewTicker(r.reloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cert, err := loadTLSCert(r.certPath, r.keyPath)
			if err != nil {
				logging.FromContext(ctx).Named("kafka").Error("Failed to load TLS key pair", zap.Error(err))
				continue
			}

			r.mu.Lock()
			r.cert = cert
			r.mu.Unlock()
		}
	}
}

func (r *tlsReloader) GetCertificateFunc() func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		r.mu.RLock()
		defer r.mu.RUnlock()

		return r.cert, nil
	}
}
