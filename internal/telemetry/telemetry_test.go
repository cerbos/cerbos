// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cerbos/cerbos/internal/test/mocks"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestState(t *testing.T) {
	logger := zap.L().Named("telemetry")

	t.Run("fresh_state", func(t *testing.T) {
		fsys := afero.NewMemMapFs()
		r := newReporter(&mocks.Store{}, fsys, logger)
		require.True(t, r.report(context.Background()))

		exists, err := afero.Exists(fsys, stateFile)
		require.NoError(t, err)
		require.True(t, exists)

		// don't report again because state was created recently
		r = newReporter(&mocks.Store{}, fsys, logger)
		require.False(t, r.report(context.Background()))
	})

	t.Run("existing_state", func(t *testing.T) {
		t.Run("valid_but_old", func(t *testing.T) {
			fsys := afero.NewMemMapFs()

			state := newState()
			state.LastTimestamp = timestamppb.New(time.Date(2020, 1, 1, 0, 0, 0, 0, time.Local))

			stateBytes, err := protojson.Marshal(state)
			require.NoError(t, err)
			require.NoError(t, afero.WriteFile(fsys, stateFile, stateBytes, 0o600))

			r := newReporter(&mocks.Store{}, fsys, logger)
			require.True(t, r.report(context.Background()))
		})

		t.Run("corrupt", func(t *testing.T) {
			fsys := afero.NewMemMapFs()

			require.NoError(t, afero.WriteFile(fsys, stateFile, []byte("rubbish"), 0o600))

			r := newReporter(&mocks.Store{}, fsys, logger)
			require.True(t, r.report(context.Background()))
		})
	})

	t.Run("read_only_fs", func(t *testing.T) {
		fsys := afero.NewReadOnlyFs(afero.NewMemMapFs())
		r := newReporter(&mocks.Store{}, fsys, logger)
		require.True(t, r.report(context.Background()))

		exists, err := afero.Exists(fsys, stateFile)
		require.NoError(t, err)
		require.False(t, exists)
	})
}

func TestReporter(t *testing.T) {
	logger := zap.L().Named("telemetry")

	for _, envVar := range []string{noTelemetryEnvVar, doNotTrackEnvVar} {
		t.Run(fmt.Sprintf("disabled_by_%s", envVar), func(t *testing.T) {
			t.Setenv(envVar, "true")
			fsys := afero.NewMemMapFs()
			r := newReporter(&mocks.Store{}, fsys, logger)

			require.False(t, r.report(context.Background()))

			exists, err := afero.Exists(fsys, stateFile)
			require.NoError(t, err)
			require.False(t, exists)
		})
	}
}
