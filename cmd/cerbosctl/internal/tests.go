// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package internal

import (
	"context"
	"testing"
	"time"

	"github.com/cerbos/cerbos-sdk-go/testutil"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/flagset"
	"github.com/stretchr/testify/require"
)

const (
	adminUsername = "cerbos"
	adminPassword = "cerbosAdmin"
	readyTimeout  = 30 * time.Second
)

func StartTestServer(t *testing.T) *testutil.CerbosServerInstance {
	t.Helper()
	t.Setenv("CERBOS_TEST_DEBUG", "true")

	conf := testutil.LaunchConf{
		Cmd: []string{
			"server",
			"--set=server.adminAPI.enabled=true",
			"--set=storage.driver=sqlite3",
			"--set=storage.sqlite3.dsn=:mem:?_fk=true",
		},
	}

	ctx, cancel := context.WithTimeout(t.Context(), readyTimeout)
	t.Cleanup(cancel)

	s, err := testutil.LaunchCerbosServer(ctx, conf)
	require.NoError(t, err)

	return s
}

func CreateGlobalsFlagset(t *testing.T, address string) *flagset.Globals {
	t.Helper()

	return &flagset.Globals{
		Server:    address,
		Username:  adminUsername,
		Password:  adminPassword,
		Plaintext: true,
	}
}
