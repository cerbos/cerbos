// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package engine

import (
	"bytes"
	"testing"
	"time"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/stretchr/testify/require"
)

func TestSatisfiesCondition(t *testing.T) {
	testCases := test.LoadTestCases(t, "cel_eval")

	timeNow, err := time.Parse(time.RFC3339, "2021-04-22T10:05:20.021-05:00")
	require.NoError(t, err, "Failed to parse timestamp")

	eparams := evaluator.EvalParams{NowFunc: func() time.Time { return timeNow }}

	for _, tcase := range testCases {
		t.Run(tcase.Name, func(t *testing.T) {
			tc := readCELTestCase(t, tcase.Input)
			cond, err := compile.Condition(&policyv1.Condition{Condition: &policyv1.Condition_Match{Match: tc.Condition}})
			require.NoError(t, err)

			tctx := tracer.Start(newTestTraceSink(t))
			retVal, err := ruletable.NewEvalContext(eparams, tc.Request).SatisfiesCondition(t.Context(), tctx.StartCondition(), cond, nil, nil)

			if tc.WantError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.Want, retVal)
		})
	}
}

func readCELTestCase(t *testing.T, data []byte) *privatev1.CelTestCase {
	t.Helper()

	tc := &privatev1.CelTestCase{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}
