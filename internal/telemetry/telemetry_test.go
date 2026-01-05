// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"fmt"
	"sync"
	"testing"

	"github.com/cerbos/cerbos/internal/test/mocks"
	analytics "github.com/rudderlabs/analytics-go"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestSegmentReporter(t *testing.T) {
	logger := zap.L().Named("telemetry")
	conf := &Conf{}

	t.Run("state", func(t *testing.T) {
		t.Run("no_state", func(t *testing.T) {
			fsys := afero.NewMemMapFs()
			mockClient := newMockAnalyticsClient()

			r := newAnalyticsReporterWithClient(mockClient, conf, &mocks.Store{}, fsys, logger)
			r.reportServerLaunch()
			require.NoError(t, r.Stop())

			mockClient.WaitForClose()
			require.Len(t, mockClient.Events(), 2)

			exists, err := afero.Exists(fsys, stateFile)
			require.NoError(t, err)
			require.True(t, exists)
		})

		t.Run("corrupt_state", func(t *testing.T) {
			fsys := afero.NewMemMapFs()
			require.NoError(t, afero.WriteFile(fsys, stateFile, []byte("rubbish"), 0o600))

			mockClient := newMockAnalyticsClient()
			r := newAnalyticsReporterWithClient(mockClient, conf, &mocks.Store{}, fsys, logger)
			r.reportServerLaunch()
			require.NoError(t, r.Stop())

			mockClient.WaitForClose()
			require.Len(t, mockClient.Events(), 2)

			state, err := afero.ReadFile(fsys, stateFile)
			require.NoError(t, err)
			require.NotEqual(t, []byte("rubbish"), state)
		})

		t.Run("read_only_fs", func(t *testing.T) {
			fsys := afero.NewReadOnlyFs(afero.NewMemMapFs())
			mockClient := newMockAnalyticsClient()

			r := newAnalyticsReporterWithClient(mockClient, conf, &mocks.Store{}, fsys, logger)
			r.reportServerLaunch()
			require.NoError(t, r.Stop())

			mockClient.WaitForClose()
			require.Len(t, mockClient.Events(), 2)

			exists, err := afero.Exists(fsys, stateFile)
			require.NoError(t, err)
			require.False(t, exists)
		})
	})
}

func TestIsEnabled(t *testing.T) {
	for _, envVar := range []string{noTelemetryEnvVar, doNotTrackEnvVar} {
		t.Run(fmt.Sprintf("disabled_by_%s", envVar), func(t *testing.T) {
			t.Setenv(envVar, "true")

			conf := &Conf{}
			conf.SetDefaults()

			require.False(t, isEnabled(conf))
		})
	}

	t.Run("disabled_by_conf", func(t *testing.T) {
		conf := &Conf{Disabled: true}

		require.False(t, isEnabled(conf))
	})
}

type mockAnalytics struct {
	shutdown chan struct{}
	events   []analytics.Message
	mu       sync.RWMutex
}

func newMockAnalyticsClient() *mockAnalytics {
	return &mockAnalytics{
		shutdown: make(chan struct{}),
	}
}

func (ma *mockAnalytics) Close() error {
	close(ma.shutdown)
	return nil
}

func (ma *mockAnalytics) Enqueue(event analytics.Message) error {
	ma.mu.Lock()
	ma.events = append(ma.events, event)
	ma.mu.Unlock()

	return nil
}

func (ma *mockAnalytics) Events() []analytics.Message {
	ma.mu.RLock()
	c := make([]analytics.Message, len(ma.events))
	copy(c, ma.events)
	ma.mu.RUnlock()

	return c
}

func (ma *mockAnalytics) WaitForClose() {
	<-ma.shutdown
}
