// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package util

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"google.golang.org/grpc"
)

const unixNetwork = "unix"

// ParseListenAddress parses an address and returns the network type and the address to dial.
// inspired by https://github.com/ghostunnel/ghostunnel/blob/6e58c75c8762fe371c1134e89dd55033a6d577a4/socket/net.go#L31
func ParseListenAddress(listenAddr string) (network, addr string, err error) {
	if strings.HasPrefix(listenAddr, "unix:") {
		network = unixNetwork
		addr = listenAddr[5:]

		return
	}

	if _, err = net.ResolveTCPAddr("tcp", listenAddr); err != nil {
		return
	}

	return "tcp", listenAddr, nil
}

// DefaultTLSConfig returns the default TLS configuration.
func DefaultTLSConfig() *tls.Config {
	// See https://wiki.mozilla.org/Security/Server_Side_TLS
	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		NextProtos: []string{"h2"},
	}
}

func GetFreeListenAddr() (string, error) {
	lis, err := net.Listen("tcp", "localhost:0") //nolint:noctx
	if err != nil {
		return "", err
	}

	addr := lis.Addr().String()

	return addr, lis.Close()
}

func GetFreePort() (int, error) {
	addr, err := GetFreeListenAddr()
	if err != nil {
		return 0, err
	}

	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(p)
}

func NewInsecureHTTPClient(httpListenAddr string, tlsSpecified bool) (client *http.Client, httpAddr string, err error) {
	network, addr, err := ParseListenAddress(httpListenAddr)
	if err != nil {
		return nil, "", err
	}
	protocol := "http"
	var tlsConfig *tls.Config
	if tlsSpecified && network != unixNetwork {
		tlsConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
		protocol = "https"
	}
	transport := newTransportForAddress(network, addr, tlsConfig)
	httpAddr = fmt.Sprintf("%s://%s", protocol, httpListenAddr)
	if network == unixNetwork {
		httpAddr = "http://localhost"
	}
	return &http.Client{Transport: transport}, httpAddr, nil
}

func newTransportForAddress(network, addr string, tlsConfig *tls.Config) http.RoundTripper {
	if network == unixNetwork {
		dialer := &net.Dialer{}
		return &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", addr)
			},
		}
	}

	transport := http.DefaultTransport.(*http.Transport) //nolint:forcetypeassert
	if tlsConfig != nil {
		transport = transport.Clone()
		transport.TLSClientConfig = tlsConfig
	}

	return transport
}

// EagerGRPCClient creates a gRPC client and establishes a connection immediately.
func EagerGRPCClient(target string, dialOpts ...grpc.DialOption) (*grpc.ClientConn, error) {
	client, err := grpc.NewClient("passthrough:///"+target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	client.Connect()
	return client, nil
}
