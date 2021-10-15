// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auxdata

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/test"
)

func TestKeySet(t *testing.T) {
	t.Parallel()

	keysDir := test.PathToDir(t, filepath.Join("auxdata", "keys"))
	keys := findKeys(t, keysDir)

	ts := httptest.NewServer(http.FileServer(http.Dir(keysDir)))
	t.Cleanup(ts.Close)

	for _, k := range keys {
		k := k
		isPEM := filepath.Ext(k) == ".pem"

		t.Run(fmt.Sprintf("local/file/%s", filepath.Base(k)), func(t *testing.T) {
			t.Parallel()
			conf := &LocalSource{
				File: k,
				PEM:  isPEM,
			}

			lks := newLocalKeySet(nil, conf)
			ks, err := lks.keySet(context.Background())
			require.NoError(t, err)
			require.NotNil(t, ks)
			require.True(t, ks.Len() > 0)
		})

		t.Run(fmt.Sprintf("local/data/%s", filepath.Base(k)), func(t *testing.T) {
			t.Parallel()
			contents, err := os.ReadFile(k)
			require.NoError(t, err, "Failed to read file %s", k)

			conf := &LocalSource{
				Data: base64.StdEncoding.EncodeToString(contents),
				PEM:  isPEM,
			}

			lks := newLocalKeySet(nil, conf)
			ks, err := lks.keySet(context.Background())
			require.NoError(t, err)
			require.NotNil(t, ks)
			require.True(t, ks.Len() > 0)
		})

		if !isPEM {
			t.Run(fmt.Sprintf("remote/%s", filepath.Base(k)), func(t *testing.T) {
				t.Parallel()
				conf := &RemoteSource{
					URL: fmt.Sprintf("%s/%s", ts.URL, filepath.Base(k)),
				}

				ctx, cancelFn := context.WithTimeout(context.Background(), 1*time.Second)
				defer cancelFn()

				rks := newRemoteKeySet(ctx, conf)
				ks, err := rks.keySet(ctx)

				require.NoError(t, err)
				require.NotNil(t, ks)
				require.True(t, ks.Len() > 0)
			})
		}
	}
}

func findKeys(t *testing.T, keysDir string) []string {
	t.Helper()

	entries, err := os.ReadDir(keysDir)
	require.NoError(t, err)

	keys := make([]string, len(entries))
	for i, entry := range entries {
		keys[i] = filepath.Join(keysDir, entry.Name())
	}

	return keys
}
