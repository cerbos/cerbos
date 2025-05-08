// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package store_test

import (
	"os"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/cerbos/cerbos/cmd/cerbosctl/root"
)

func TestStoreCmd(t *testing.T) {
	// Create an .env file with the following values and run `just test ./cmd/cerbosctl/hub/store/...`
	for _, envVar := range []string{"CERBOS_HUB_CLIENT_ID", "CERBOS_HUB_CLIENT_SECRET", "CERBOS_HUB_STORE_ID"} {
		if os.Getenv(envVar) == "" {
			t.Skipf("Skipping because %s is not set", envVar)
		}
	}

	testscript.Run(t, testscript.Params{
		Dir: "testdata/testscripts",
		Cmds: map[string]func(*testscript.TestScript, bool, []string){
			"cerbosctl":         cerbosctl,
			"cerbosctl_lenient": cerbosctlLenient,
		},
	})
}

func cerbosctl(ts *testscript.TestScript, neg bool, args []string) {
	var exitCode int
	exit := func(code int) {
		exitCode = code
	}
	root.Run(args, exit, ts.Stdout(), ts.Stderr())

	switch {
	case neg && exitCode == 0:
		ts.Fatalf("cerbosctl exited with %d", exitCode)
	case !neg && exitCode > 0:
		ts.Fatalf("cerbosctl exited with %d", exitCode)
	}
}

func cerbosctlLenient(ts *testscript.TestScript, neg bool, args []string) {
	var exitCode int
	exit := func(code int) {
		exitCode = code
	}
	root.Run(args, exit, ts.Stdout(), ts.Stderr())

	switch {
	case neg && (exitCode == 0 || exitCode == 5):
		ts.Fatalf("cerbosctl exited with %d", exitCode)
	case !neg && (exitCode != 0 && exitCode != 5):
		ts.Fatalf("cerbosctl exited with %d", exitCode)
	}
}
