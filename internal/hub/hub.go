// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cloud-api/base"
	"github.com/cerbos/cloud-api/hub"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
)

var Get = sync.OnceValues(getInstance)

func getInstance() (*hub.Hub, error) {
	conf, err := GetConf()
	if err != nil {
		return nil, err
	}

	pdpID := util.PDPIdentifier(conf.Credentials.PDPID)
	logger := zap.L().Named("hub").With(zap.String("instance", pdpID.Instance))

	creds, err := conf.Credentials.ToCredentials()
	if err != nil {
		return nil, errors.New("failed to generate credentials from config")
	}

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: conf.Connection.TLS.Authority,
	}

	caCertPath := conf.Connection.TLS.CACert
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

	return hub.Get(base.ClientConf{
		Logger:            zapr.NewLogger(logger),
		PDPIdentifier:     pdpID,
		TLS:               tlsConf,
		Credentials:       creds,
		APIEndpoint:       conf.Connection.APIEndpoint,
		BootstrapEndpoint: conf.Connection.BootstrapEndpoint,
		RetryWaitMin:      conf.Connection.MinRetryWait,
		RetryWaitMax:      conf.Connection.MaxRetryWait,
		RetryMaxAttempts:  int(conf.Connection.NumRetries),
		HeartbeatInterval: conf.Connection.HeartbeatInterval,
	})
}
