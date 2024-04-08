// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package healthcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/alecthomas/kong"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/server"
	"github.com/cerbos/cerbos/internal/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/local"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const (
	defaultGRPCHostPort = "127.0.0.1:3593"
	defaultHTTPHostPort = "127.0.0.1:3592"
	grpcKind            = "grpc"
	httpKind            = "http"

	help = `
Performs a healthcheck on a Cerbos PDP. This can be used as a Docker HEALTHCHECK command.
When the path to the Cerbos config file is provided via the '--config' flag or the CERBOS_CONFIG environment variable, the healthcheck will be automatically configured based on the settings from the file.
By default, the gRPC endpoint will be checked using the gRPC healthcheck protocol. This is usually sufficient for most cases as the Cerbos REST API is built on top of the gRPC API as well.

Examples:

# Check gRPC endpoint

cerbos healthcheck --config=/path/to/.cerbos.yaml

# Check HTTP endpoint and ignore server certificate verification

cerbos healthcheck --config=/path/to/.cerbos.yaml --kind=http --insecure

# Check the HTTP endpoint of a specific host with no TLS.

cerbos healthcheck --kind=http --host-port=10.0.1.5:3592 --no-tls
`
)

type Cmd struct {
	Config   string        `help:"Cerbos config file" group:"config" xor:"hostport,cacert,notls" env:"CERBOS_CONFIG"`
	Kind     string        `help:"Healthcheck kind (${enum})" default:"grpc" enum:"grpc,http" env:"CERBOS_HC_KIND"`
	HostPort string        `help:"Host and port to connect to" group:"manual" xor:"hostport" env:"CERBOS_HC_HOSTPORT"`
	CACert   string        `help:"Path to CA cert for validating server cert" type:"existingfile" group:"manual" xor:"cacert" env:"CERBOS_HC_CACERT"`
	NoTLS    bool          `help:"Don't use TLS" group:"manual" xor:"notls" env:"CERBOS_HC_NOTLS"`
	Insecure bool          `help:"Do not verify server certificate" default:"false" env:"CERBOS_HC_INSECURE"`
	Timeout  time.Duration `help:"Healthcheck timeout" default:"2s" env:"CERBOS_HC_TIMEOUT"`
}

type checker interface {
	check(context.Context, io.Writer) error
}

func (c *Cmd) Help() string {
	return help
}

func (c *Cmd) Run(k *kong.Kong) error {
	chk, err := c.buildCheck()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	return chk.check(ctx, k.Stdout)
}

func (c *Cmd) buildCheck() (checker, error) {
	if c.Config != "" {
		if err := config.Load(c.Config, nil); err != nil {
			return nil, fmt.Errorf("failed to load config file %q: %w", c.Config, err)
		}

		serverConf := &server.Conf{}
		if err := config.GetSection(serverConf); err != nil {
			return nil, fmt.Errorf("failed to read configuration: %w", err)
		}

		return c.doBuildCheckFromConf(serverConf)
	}

	return c.doBuildCheckManual()
}

func (c *Cmd) doBuildCheckFromConf(serverConf *server.Conf) (checker, error) {
	var tlsConf *tls.Config
	if serverConf.TLS != nil {
		var err error
		tlsConf, err = mkTLSConfig(serverConf.TLS, c.Insecure)
		if err != nil {
			return nil, err
		}
	}

	switch c.Kind {
	case grpcKind:
		return grpcCheck{addr: serverConf.GRPCListenAddr, tlsConf: tlsConf}, nil
	case httpKind:
		host, port, err := net.SplitHostPort(serverConf.HTTPListenAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse httpListenAddr %q: %w", serverConf.HTTPListenAddr, err)
		}

		if host == "" {
			host = "127.0.0.1"
		}

		hostPort := net.JoinHostPort(host, port)
		return newHTTPCheck(hostPort, tlsConf), nil
	}

	return nil, fmt.Errorf("unknown check kind %q", c.Kind)
}

func (c *Cmd) doBuildCheckManual() (checker, error) {
	var tlsConf *tls.Config
	if !c.NoTLS {
		var err error
		tc := &server.TLSConf{CACert: c.CACert}
		tlsConf, err = mkTLSConfig(tc, c.Insecure)
		if err != nil {
			return nil, err
		}
	}

	switch c.Kind {
	case grpcKind:
		hostPort := c.HostPort
		if hostPort == "" {
			hostPort = defaultGRPCHostPort
		}

		return grpcCheck{addr: hostPort, tlsConf: tlsConf}, nil
	case httpKind:
		hostPort := c.HostPort
		if hostPort == "" {
			hostPort = defaultHTTPHostPort
		}

		return newHTTPCheck(hostPort, tlsConf), nil
	}

	return nil, fmt.Errorf("unknown check kind %q", c.Kind)
}

func mkTLSConfig(tc *server.TLSConf, insecure bool) (*tls.Config, error) {
	tlsConfig := util.DefaultTLSConfig()
	if insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	cert := tc.CACert
	if cert == "" {
		cert = tc.Cert
	}

	if cert != "" {
		certPool := x509.NewCertPool()
		bs, err := os.ReadFile(cert)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate from %q: %w", cert, err)
		}

		ok := certPool.AppendCertsFromPEM(bs)
		if !ok {
			return nil, errors.New("failed to append certificates to the pool")
		}

		tlsConfig.RootCAs = certPool
	}

	return tlsConfig, nil
}

type grpcCheck struct {
	tlsConf *tls.Config
	addr    string
}

func (gc grpcCheck) check(ctx context.Context, out io.Writer) error {
	var dialOpts []grpc.DialOption
	if gc.tlsConf == nil {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(local.NewCredentials()))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(gc.tlsConf)))
	}

	conn, err := grpc.NewClient(gc.addr, dialOpts...)
	if err != nil {
		return fmt.Errorf("failed to connect to gRPC service at %q: %w", gc.addr, err)
	}

	hc := healthpb.NewHealthClient(conn)
	resp, err := hc.Check(ctx, &healthpb.HealthCheckRequest{Service: svcv1.CerbosService_ServiceDesc.ServiceName})
	if err != nil {
		return fmt.Errorf("failed to execute healthcheck RPC: %w", err)
	}

	_, _ = fmt.Fprintln(out, resp.Status.String())

	switch resp.Status {
	case healthpb.HealthCheckResponse_SERVING, healthpb.HealthCheckResponse_UNKNOWN:
		return nil
	default:
		return fmt.Errorf("service status is %q", resp.Status.String())
	}
}

type httpCheck struct {
	tlsConf *tls.Config
	url     string
}

func newHTTPCheck(hostPort string, tlsConf *tls.Config) httpCheck {
	protocol := "http"
	if tlsConf != nil {
		protocol = "https"
	}

	url := fmt.Sprintf("%s://%s/_cerbos/health", protocol, hostPort)
	return httpCheck{url: url, tlsConf: tlsConf}
}

func (hc httpCheck) check(ctx context.Context, out io.Writer) error {
	client := &http.Client{}

	if hc.tlsConf != nil {
		//nolint:forcetypeassert
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = hc.tlsConf

		client.Transport = transport
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hc.url, http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to create request to %q: %w", hc.url, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request to %q failed: %w", hc.url, err)
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

	_, _ = io.Copy(out, resp.Body)

	return nil
}
