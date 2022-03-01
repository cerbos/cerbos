// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package healthcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/alecthomas/kong"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/local"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const (
	defaultGRPCHostPort = "127.0.0.1:3593"
	defaultHTTPHostPort = "127.0.0.1:3592"

	help = `
Performs a healthcheck on a Cerbos PDP. This can be used as a Docker HEALTHCHECK command.
By default, the local Cerbos gRPC endpoint (127.0.0.1:3593) will be checked using the gRPC healthcheck protocol. This is usually sufficient for most cases as the Cerbos REST API is built on top of the gRPC API as well.   

Examples:

# Check gRPC endpoint

cerbos healthcheck

# Check gRPC endpoint and ignore server certificate verification

cerbos healthcheck --insecure

# Check https endpoint, ignoring server certificate verification and with a custom timeout

cerbos healthcheck --kind=https --insecure --timeout=2s

# Use a different host address

cerbos healthcheck --kind=http --host-port=10.0.1.5:3592
`
)

type Cmd struct {
	Kind      string        `help:"Healthcheck kind (${enum})" default:"grpc" enum:"grpc,http,https" env:"CERBOS_HC_KIND"`
	HostPort  string        `help:"Host and port to check. Defaults to 127.0.0.1:3592 for http/https and 127.0.0.1:3593 for grpc" env:"CERBOS_HC_HOST"`
	CACert    string        `help:"CA Certificate to use to verify the server certificate" type:"existingfile"`
	Insecure  bool          `help:"Do not verify server certificate" default:"false"`
	Plaintext bool          `help:"No TLS (gRPC only)" default:"false"`
	Timeout   time.Duration `help:"Healthcheck timeout" default:"10s" env:"CERBOS_HC_TIMEOUT"`
}

func (c *Cmd) Run(k *kong.Kong) error {
	switch c.Kind {
	case "grpc":
		return c.grpcCheck(k)
	case "http", "https":
		return c.httpCheck(k)
	default:
		return fmt.Errorf("unknown healthcheck kind %q", c.Kind)
	}
}

func (c *Cmd) grpcCheck(k *kong.Kong) error {
	var dialOpts []grpc.DialOption
	if c.Plaintext {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(local.NewCredentials()))
	} else {
		tlsConf, err := c.mkTLSConfig()
		if err != nil {
			return err
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
	}

	address := defaultGRPCHostPort
	if c.HostPort != "" {
		address = c.HostPort
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), c.Timeout)
	defer cancelFunc()

	conn, err := grpc.DialContext(ctx, address, dialOpts...)
	if err != nil {
		return fmt.Errorf("failed to connect to gRPC service at %q: %w", c.HostPort, err)
	}

	hc := healthpb.NewHealthClient(conn)
	resp, err := hc.Check(ctx, &healthpb.HealthCheckRequest{Service: svcv1.CerbosService_ServiceDesc.ServiceName})
	if err != nil {
		return fmt.Errorf("failed to execute healthcheck RPC: %w", err)
	}

	_, _ = fmt.Fprintln(k.Stdout, resp.Status.String())

	switch resp.Status {
	case healthpb.HealthCheckResponse_SERVING, healthpb.HealthCheckResponse_UNKNOWN:
		return nil
	default:
		return fmt.Errorf("service status is %q", resp.Status.String())
	}
}

func (c *Cmd) httpCheck(k *kong.Kong) error {
	client := &http.Client{Timeout: c.Timeout}

	if c.Kind == "https" {
		tlsConf, err := c.mkTLSConfig()
		if err != nil {
			return err
		}

		//nolint:forcetypeassert
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = tlsConf

		client.Transport = transport
	}

	address := defaultHTTPHostPort
	if c.HostPort != "" {
		address = c.HostPort
	}
	url := fmt.Sprintf("%s://%s/_cerbos/health", c.Kind, address)

	ctx, cancelFunc := context.WithTimeout(context.Background(), c.Timeout)
	defer cancelFunc()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}

	defer func() {
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %s (%d)", resp.Status, resp.StatusCode)
	}

	_, _ = io.Copy(k.Stdout, resp.Body)

	return nil
}

func (c *Cmd) mkTLSConfig() (*tls.Config, error) {
	tlsConfig := util.DefaultTLSConfig()
	if c.Insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	if c.CACert != "" {
		certPool := x509.NewCertPool()
		bs, err := os.ReadFile(c.CACert)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate from %q: %w", c.CACert, err)
		}

		ok := certPool.AppendCertsFromPEM(bs)
		if !ok {
			return nil, errors.New("failed to append certificates to the pool")
		}

		tlsConfig.RootCAs = certPool
	}

	return tlsConfig, nil
}

func (c *Cmd) Help() string {
	return help
}
