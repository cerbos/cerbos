// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/cerbos/cerbos/internal/observability/logging"
)

func newLogCtx(t *testing.T) (context.Context, *observer.ObservedLogs) {
	t.Helper()
	core, logs := observer.New(zapcore.DebugLevel)
	return logging.ToContext(t.Context(), zap.New(core)), logs
}

func resetCELErrorHint() {
	celErrorHintOnce = sync.Once{}
}

func TestCELErrorsAdd(t *testing.T) {
	levels := map[CELErrorLogLevel]zapcore.Level{
		CELErrorLogLevelDebug: zapcore.DebugLevel,
		CELErrorLogLevelInfo:  zapcore.InfoLevel,
		CELErrorLogLevelWarn:  zapcore.WarnLevel,
		CELErrorLogLevelError: zapcore.ErrorLevel,
		"":                    zapcore.WarnLevel, // zero value behaves like the default
	}

	for level, wantLevel := range levels {
		t.Run(string(level), func(t *testing.T) {
			resetCELErrorHint()
			ctx, logs := newLogCtx(t)

			c := NewCELErrors(level)
			c.Add(ctx, "R.attr.x > 1", errors.New("no such key: x"))

			entries := c.All()
			require.Len(t, entries, 1)
			require.Equal(t, "R.attr.x > 1", entries[0].GetCelError().GetExpression())
			require.Equal(t, "no such key: x", entries[0].GetCelError().GetMessage())

			errLogs := logs.FilterMessage(celErrorMsg).All()
			require.Len(t, errLogs, 1)
			require.Equal(t, wantLevel, errLogs[0].Level)
			require.Equal(t, "R.attr.x > 1", errLogs[0].ContextMap()["expression"])
			require.Equal(t, "no such key: x", errLogs[0].ContextMap()["error"])

			hintLogs := logs.FilterMessage(celErrorHint).All()
			require.Len(t, hintLogs, 1)
			require.Equal(t, wantLevel, hintLogs[0].Level)
		})
	}

	t.Run("none_collects_without_logging", func(t *testing.T) {
		resetCELErrorHint()
		ctx, logs := newLogCtx(t)

		c := NewCELErrors(CELErrorLogLevelNone)
		c.Add(ctx, "R.attr.x > 1", errors.New("no such key: x"))

		require.Len(t, c.All(), 1)
		require.Zero(t, logs.Len())
	})

	t.Run("deduplicates_identical_errors", func(t *testing.T) {
		resetCELErrorHint()
		ctx, logs := newLogCtx(t)

		c := NewCELErrors(CELErrorLogLevelWarn)
		c.Add(ctx, "R.attr.x > 1", errors.New("no such key: x"))
		c.Add(ctx, "R.attr.x > 1", errors.New("no such key: x"))
		c.Add(ctx, "R.attr.x > 1", errors.New("no such key: y"))

		require.Len(t, c.All(), 2)
		require.Equal(t, 2, logs.FilterMessage(celErrorMsg).Len())
	})

	t.Run("hint_logged_once_across_collectors", func(t *testing.T) {
		resetCELErrorHint()
		ctx, logs := newLogCtx(t)

		c1 := NewCELErrors(CELErrorLogLevelWarn)
		c1.Add(ctx, "a", errors.New("boom"))
		c1.Add(ctx, "b", errors.New("boom"))
		c2 := NewCELErrors(CELErrorLogLevelWarn)
		c2.Add(ctx, "c", errors.New("boom"))

		require.Equal(t, 3, logs.FilterMessage(celErrorMsg).Len())
		require.Equal(t, 1, logs.FilterMessage(celErrorHint).Len())
	})

	t.Run("nil_collector_has_no_errors", func(t *testing.T) {
		var c *CELErrors
		require.Nil(t, c.All())
	})
}
