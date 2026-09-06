// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package run

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"
)

func TestRunPropagatesCommandStartError(t *testing.T) {
	httpPort, grpcPort := allocateFreePorts(t)

	dir := t.TempDir()
	policiesDir := filepath.Join(dir, "policies")
	require.NoError(t, os.MkdirAll(policiesDir, 0o755))

	confPath := filepath.Join(dir, ".cerbos.yaml")
	conf := fmt.Sprintf(`
server:
  httpListenAddr: "127.0.0.1:%d"
  grpcListenAddr: "127.0.0.1:%d"
storage:
  driver: "disk"
  disk:
    directory: %q
`, httpPort, grpcPort, policiesDir)
	require.NoError(t, os.WriteFile(confPath, []byte(conf), 0o600))

	k, err := kong.New(&struct{}{}, kong.Writers(&bytes.Buffer{}, &bytes.Buffer{}))
	require.NoError(t, err)

	const cmdName = "cerbos-test-nonexistent-command"
	cmd := &Cmd{
		Config:  confPath,
		Command: []string{"--", cmdName},
		Timeout: 30 * time.Second,
	}

	err = cmd.Run(k)
	require.Error(t, err)
	require.ErrorContains(t, err, cmdName)
}

func allocateFreePorts(t *testing.T) (httpPort, grpcPort int) {
	t.Helper()

	var lc net.ListenConfig
	ports := make([]int, 2)
	for i := range ports {
		l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		ports[i] = l.Addr().(*net.TCPAddr).Port
		require.NoError(t, l.Close())
	}

	return ports[0], ports[1]
}
