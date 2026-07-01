// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"io"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewHandlerExposesRuntimeMetrics(t *testing.T) {
	h, err := NewHandler()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), "GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Result().Body)
	s := string(body)
	for _, want := range []string{
		"go_cpu_classes_gc_total_cpu_seconds_total",
		"go_cpu_classes_total_cpu_seconds_total",
		"go_memstats_heap_released_bytes",
		"go_memstats_sys_bytes",
		"go_gc_duration_seconds",
		"go_memstats_alloc_bytes_total",
	} {
		require.Contains(t, s, want, "metric %q not found in /metrics output", want)
	}
}
