package kafka

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

const DefaultTLSVersion = tls.VersionTLS12

type TLSReloader struct {
	mu       sync.RWMutex
	certPath string
	keyPath  string
	cert     *tls.Certificate
}

func NewTLSReloader(certPath, keyPath string) (*TLSReloader, error) {
	reloader := &TLSReloader{
		certPath: certPath,
		keyPath:  keyPath,
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS key pair: %w", err)
	}
	reloader.cert = &cert

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)
		for range c {
			if err := reloader.reload(); err != nil {
				log.Printf("unable to renew certificate, using previous: %v", err)
			}
		}
	}()

	return reloader, nil
}

func (r *TLSReloader) reload() error {
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("failed to load TLS key pair: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.cert = &cert
	return nil
}

func NewTLSConfig(caPath, certPath, keyPath string) (*tls.Config, error) {
	if caPath == "" || certPath == "" || keyPath == "" {
		return nil, errors.New("invalid TLS configuration")
	}

	reloader, err := NewTLSReloader(certPath, keyPath)
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

	return &tls.Config{
		RootCAs:              caCertPool,
		ClientCAs:            caCertPool,
		MinVersion:           DefaultTLSVersion,
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
