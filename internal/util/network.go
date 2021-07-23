// Copyright 2021 Zenauth Ltd.

package util

import (
	"crypto/tls"
	"net"
	"strconv"
	"strings"
)

// ParseListenAddress parses an address and returns the network type and the address to dial.
// inspired by https://github.com/ghostunnel/ghostunnel/blob/6e58c75c8762fe371c1134e89dd55033a6d577a4/socket/net.go#L31
func ParseListenAddress(listenAddr string) (network, addr string, err error) {
	if strings.HasPrefix(listenAddr, "unix:") {
		network = "unix"
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
	lis, err := net.Listen("tcp", "localhost:0")
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
