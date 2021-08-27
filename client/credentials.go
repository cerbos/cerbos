// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/jdxcode/netrc"
)

const (
	authorizationHeader      = "authorization"
	playgroundInstanceHeader = "playground-instance"
	usernameEnvVar           = "CERBOS_USERNAME"
	passwordEnvVar           = "CERBOS_PASSWORD"
	serverEnvVar             = "CERBOS_SERVER"
	netrcFile                = ".netrc"
	netrcEnvVar              = "NETRC"
	netrcUserKey             = "login"
	netrcPassKey             = "password"
)

var (
	errServerNotDefined       = errors.New("server not defined")
	errNoCredentialsFound     = errors.New("no credentials found")
	errNetrcUnsupportedForUDS = errors.New("netrc fallback not supported for Unix domain socket addresses")
)

type environment interface {
	Getenv(string) string
	LookupEnv(string) (string, bool)
}

type osEnvironment struct{}

func (osEnvironment) Getenv(k string) string { return os.Getenv(k) }

func (osEnvironment) LookupEnv(k string) (string, bool) { return os.LookupEnv(k) }

// loadBasicAuthData loads basic auth credentials and the server address by considering the following options:
// - User provided values (config or flags)
// - Environment variables
// - netrc file.
func loadBasicAuthData(env environment, providedServer, providedUsername, providedPassword string) (server, username, password string, err error) {
	server = coalesceWithEnv(env, providedServer, serverEnvVar)
	if server == "" {
		return "", "", "", errServerNotDefined
	}

	username = coalesceWithEnv(env, providedUsername, usernameEnvVar)
	password = coalesceWithEnv(env, providedPassword, passwordEnvVar)

	if username != "" && password != "" {
		return
	}

	username, password, err = loadCredsFromNetrc(env, server)
	return
}

func loadCredsFromNetrc(env environment, server string) (username, password string, err error) {
	machineName, err := extractMachineName(server)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse server target '%s': %w", server, err)
	}

	netrcPath := ""
	if np, ok := env.LookupEnv(netrcEnvVar); ok {
		netrcPath = np
	} else {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", "", fmt.Errorf("failed to determine home directory to load netrc: %w", err)
		}

		netrcPath = filepath.Join(homeDir, netrcFile)
	}

	n, err := netrc.Parse(netrcPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read netrc from '%s': %w", netrcPath, err)
	}

	m := n.Machine(machineName)
	if m == nil {
		return "", "", errNoCredentialsFound
	}

	username = m.Get(netrcUserKey)
	password = m.Get(netrcPassKey)

	if username == "" || password == "" {
		return "", "", errNoCredentialsFound
	}

	return username, password, nil
}

func coalesceWithEnv(env environment, val, envVar string) string {
	if v := strings.TrimSpace(val); v != "" {
		return v
	}

	if envVal, ok := env.LookupEnv(envVar); ok {
		return envVal
	}

	return val
}

// extractMachineName picks out the machine name from a gRPC target.
// See https://github.com/grpc/grpc/blob/master/doc/naming.md
func extractMachineName(target string) (string, error) {
	scheme, remainder, ok := split2(target, ":")
	if !ok {
		return target, nil
	}

	switch strings.ToLower(scheme) {
	case "unix", "unix-abstract":
		return "", errNetrcUnsupportedForUDS
	case "dns":
		addr := remainder
		if strings.HasPrefix(addr, "//") {
			_, hostName, ok := split2(remainder[2:], "/")
			if !ok {
				return "", fmt.Errorf("invalid server target '%s'", target)
			}

			addr = hostName
		}

		m, _, err := net.SplitHostPort(addr)
		return m, err
	}

	m, _, err := net.SplitHostPort(target)
	return m, err
}

//nolint:gomnd
func split2(str, sep string) (string, string, bool) {
	parts := strings.SplitN(str, sep, 2)
	if len(parts) != 2 {
		return "", "", false
	}

	return parts[0], parts[1], true
}

type basicAuthCredentials struct {
	headerVal  string
	requireTLS bool
}

// newBasicAuthCredentials creates a new grpc PerRPCCredentials object that uses basic auth.
func newBasicAuthCredentials(username, password string) basicAuthCredentials {
	auth := username + ":" + password
	enc := base64.StdEncoding.EncodeToString([]byte(auth))

	return basicAuthCredentials{headerVal: "Basic " + enc, requireTLS: true}
}

// Insecure relaxes the TLS requirement for using the credential.
func (ba basicAuthCredentials) Insecure() basicAuthCredentials {
	return basicAuthCredentials{headerVal: ba.headerVal, requireTLS: false}
}

func (ba basicAuthCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{authorizationHeader: ba.headerVal}, nil
}

func (ba basicAuthCredentials) RequireTransportSecurity() bool {
	return ba.requireTLS
}

type playgroundInstanceCredentials struct {
	instance string
}

func newPlaygroundInstanceCredentials(instance string) playgroundInstanceCredentials {
	return playgroundInstanceCredentials{instance: instance}
}

func (pic playgroundInstanceCredentials) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{playgroundInstanceHeader: pic.instance}, nil
}

func (playgroundInstanceCredentials) RequireTransportSecurity() bool {
	return false
}
