// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/engine/tracer"
)

func TracesToBatch(traces []*enginev1.Trace) *enginev1.TraceBatch {
	return tracer.TracesToBatch(traces)
}
