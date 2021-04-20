package engine

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	responsev1 "github.com/cerbos/cerbos/internal/genpb/response/v1"
	sharedv1 "github.com/cerbos/cerbos/internal/genpb/shared/v1"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
)

func TestEngineCheck(t *testing.T) {
	eng, cancelFunc := mkEngine(t)
	defer cancelFunc()

	testCases := []struct {
		desc             string
		request          func() *requestv1.CheckRequest
		wantEffect       sharedv1.Effect
		wantPolicy       string
		wantDerivedRoles []string
		wantErr          bool
	}{
		{
			desc:             "John views own leave request",
			request:          test.MkCheckRequest,
			wantEffect:       sharedv1.Effect_EFFECT_ALLOW,
			wantPolicy:       "leave_request:20210210",
			wantDerivedRoles: []string{"employee_that_owns_the_record", "any_employee"},
		},
		{
			desc: "John tries to approve his own leave_request",
			request: func() *requestv1.CheckRequest {
				// John trying to approve his own leave request
				req := test.MkCheckRequest()
				req.Action = "approve"

				return req
			},
			wantEffect:       sharedv1.Effect_EFFECT_DENY,
			wantPolicy:       "leave_request:20210210",
			wantDerivedRoles: []string{"employee_that_owns_the_record", "any_employee"},
		},
		{
			desc: "John's manager approves leave_request",
			request: func() *requestv1.CheckRequest {
				// John's manager approving his leave request
				req := test.MkCheckRequest()
				req.Action = "approve"
				req.Principal.Id = "sally"
				req.Principal.Roles = []string{"employee", "manager"}
				req.Principal.Attr["managed_geographies"] = structpb.NewStringValue("GB")
				req.Resource.Attr["status"] = structpb.NewStringValue("PENDING_APPROVAL")

				return req
			},
			wantEffect:       sharedv1.Effect_EFFECT_ALLOW,
			wantPolicy:       "leave_request:20210210",
			wantDerivedRoles: []string{"direct_manager", "any_employee"},
		},
		{
			desc: "Some other manager tries to approve leave_request",
			request: func() *requestv1.CheckRequest {
				// Some other manager trying to approve John's leave request
				req := test.MkCheckRequest()
				req.Action = "approve"
				req.Principal.Id = "betty"
				req.Principal.Roles = []string{"employee", "manager"}
				req.Principal.Attr["managed_geographies"] = structpb.NewStringValue("FR")
				req.Resource.Attr["status"] = structpb.NewStringValue("PENDING_APPROVAL")

				return req
			},
			wantEffect:       sharedv1.Effect_EFFECT_DENY,
			wantPolicy:       "leave_request:20210210",
			wantDerivedRoles: []string{"any_employee"},
		},
		{
			desc: "Donald Duck approves leave_request that has dev_record attribute [Principal policy override]",
			request: func() *requestv1.CheckRequest {
				// Donald Duck has a principal policy that lets him do anything on leave_request as long as it's a dev record
				req := test.MkCheckRequest()
				req.Action = "approve"
				req.Principal.Id = "donald_duck"
				req.Resource.Attr["dev_record"] = structpb.NewBoolValue(true)

				return req
			},
			wantEffect: sharedv1.Effect_EFFECT_ALLOW,
			wantPolicy: "donald_duck:20210210",
		},
		{
			desc: "Donald Duck views leave_request [Principal policy cascades to resource policy]",
			request: func() *requestv1.CheckRequest {
				// Donald Duck trying to do something on a non-dev record
				// It should cascade down to resource policy because there's no explicit rule for Donald Duck
				req := test.MkCheckRequest()
				req.Action = "view:public"
				req.Principal.Id = "donald_duck"

				return req
			},
			wantEffect:       sharedv1.Effect_EFFECT_ALLOW,
			wantPolicy:       "leave_request:20210210",
			wantDerivedRoles: []string{"any_employee"},
		},
		{
			desc: "Donald Duck tries to view salary_record [Principal policy override]",
			request: func() *requestv1.CheckRequest {
				// Donald Duck has an explicit deny on salary_record
				req := test.MkCheckRequest()
				req.Action = "view"
				req.Principal.Id = "donald_duck"
				req.Resource.Name = "salary_record"
				req.Resource.Attr["dev_record"] = structpb.NewBoolValue(true)

				return req
			},
			wantEffect: sharedv1.Effect_EFFECT_DENY,
			wantPolicy: "donald_duck:20210210",
		},
	}

	for _, tc := range testCases {
		req := tc.request()
		name := fmt.Sprintf("principal=%s;resource=%s;action=%s", req.Principal.Id, req.Resource.Name, req.Action)
		t.Run(name, func(t *testing.T) {
			t.Log(tc.desc)
			resp, err := eng.Check(context.Background(), req)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantEffect, resp.Effect)
			require.Equal(t, tc.wantPolicy, resp.Meta.MatchedPolicy)
			require.ElementsMatch(t, tc.wantDerivedRoles, resp.Meta.EffectiveDerivedRoles)
		})
	}
}

func TestCheckResourceBatch(t *testing.T) {
	eng, cancelFunc := mkEngine(t)
	defer cancelFunc()

	t.Run("valid", func(t *testing.T) {
		req := test.MkCheckResourceBatchRequest()

		want := &responsev1.CheckResourceBatchResponse{
			RequestId: "test",
			ResourceInstances: map[string]*responsev1.ActionEffectList{
				"XX125": {
					Actions: map[string]sharedv1.Effect{
						"view:public": sharedv1.Effect_EFFECT_ALLOW,
						"approve":     sharedv1.Effect_EFFECT_DENY,
						"create":      sharedv1.Effect_EFFECT_DENY,
					},
				},
				"XX150": {
					Actions: map[string]sharedv1.Effect{
						"view:public": sharedv1.Effect_EFFECT_ALLOW,
						"approve":     sharedv1.Effect_EFFECT_DENY,
						"create":      sharedv1.Effect_EFFECT_DENY,
					},
				},
				"XX250": {
					Actions: map[string]sharedv1.Effect{
						"view:public": sharedv1.Effect_EFFECT_ALLOW,
						"approve":     sharedv1.Effect_EFFECT_DENY,
						"create":      sharedv1.Effect_EFFECT_DENY,
					},
				},
				"YY100": {
					Actions: map[string]sharedv1.Effect{
						"view:public": sharedv1.Effect_EFFECT_ALLOW,
						"approve":     sharedv1.Effect_EFFECT_ALLOW,
						"create":      sharedv1.Effect_EFFECT_ALLOW,
					},
				},
				"YY200": {
					Actions: map[string]sharedv1.Effect{
						"view:public": sharedv1.Effect_EFFECT_ALLOW,
						"approve":     sharedv1.Effect_EFFECT_ALLOW,
						"create":      sharedv1.Effect_EFFECT_ALLOW,
					},
				},
			},
		}

		have, err := eng.CheckResourceBatch(context.Background(), req)
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(want, have, protocmp.Transform()))
	})

	t.Run("no_policy_match", func(t *testing.T) {
		req := test.MkCheckResourceBatchRequest()
		req.Principal.Id = "bugs_bunny"
		req.Resource.Name = "quarterly_report"

		want := &responsev1.CheckResourceBatchResponse{
			RequestId: "test",
			ResourceInstances: map[string]*responsev1.ActionEffectList{
				"XX125": {
					Actions: map[string]sharedv1.Effect{
						"view:public": sharedv1.Effect_EFFECT_DENY,
						"approve":     sharedv1.Effect_EFFECT_DENY,
						"create":      sharedv1.Effect_EFFECT_DENY,
					},
				},
				"XX150": {
					Actions: map[string]sharedv1.Effect{
						"view:public": sharedv1.Effect_EFFECT_DENY,
						"approve":     sharedv1.Effect_EFFECT_DENY,
						"create":      sharedv1.Effect_EFFECT_DENY,
					},
				},
				"XX250": {
					Actions: map[string]sharedv1.Effect{
						"view:public": sharedv1.Effect_EFFECT_DENY,
						"approve":     sharedv1.Effect_EFFECT_DENY,
						"create":      sharedv1.Effect_EFFECT_DENY,
					},
				},
				"YY100": {
					Actions: map[string]sharedv1.Effect{
						"view:public": sharedv1.Effect_EFFECT_DENY,
						"approve":     sharedv1.Effect_EFFECT_DENY,
						"create":      sharedv1.Effect_EFFECT_DENY,
					},
				},
				"YY200": {
					Actions: map[string]sharedv1.Effect{
						"view:public": sharedv1.Effect_EFFECT_DENY,
						"approve":     sharedv1.Effect_EFFECT_DENY,
						"create":      sharedv1.Effect_EFFECT_DENY,
					},
				},
			},
		}

		have, err := eng.CheckResourceBatch(context.Background(), req)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoPoliciesMatched)
		require.Empty(t, cmp.Diff(want, have, protocmp.Transform()))
	})
}

func BenchmarkCheck(b *testing.B) {
	eng, cancelFunc := mkEngine(b)
	defer cancelFunc()

	b.Run("only_resource_policy", func(b *testing.B) {
		request := test.MkCheckRequest()

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			result, err := eng.Check(context.Background(), request)
			if err != nil {
				b.Errorf("ERROR: %v", err)
			}

			if result.Effect != sharedv1.Effect_EFFECT_ALLOW {
				b.Errorf("Unexpected result: %v", result.Effect)
			}
		}
	})

	b.Run("only_principal_policy", func(b *testing.B) {
		request := test.MkCheckRequest()
		request.Action = "approve"
		request.Principal.Id = "donald_duck"
		request.Resource.Attr["dev_record"] = structpb.NewBoolValue(true)

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			result, err := eng.Check(context.Background(), request)
			if err != nil {
				b.Errorf("ERROR: %v", err)
			}

			if result.Effect != sharedv1.Effect_EFFECT_ALLOW {
				b.Errorf("Unexpected result: %v", result.Effect)
			}
		}
	})

	b.Run("fallback_to_resource_policy", func(b *testing.B) {
		request := test.MkCheckRequest()
		request.Action = "view:public"
		request.Principal.Id = "donald_duck"

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			result, err := eng.Check(context.Background(), request)
			if err != nil {
				b.Errorf("ERROR: %v", err)
			}

			if result.Effect != sharedv1.Effect_EFFECT_ALLOW {
				b.Errorf("Unexpected result: %v", result.Effect)
			}
		}
	})

	b.Run("no_match", func(b *testing.B) {
		request := test.MkCheckRequest()
		request.Resource.Name = "unknown"

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			result, err := eng.Check(context.Background(), request)
			if !errors.Is(err, ErrNoPoliciesMatched) {
				b.Errorf("ERROR: %v", err)
			}

			if result.Effect != sharedv1.Effect_EFFECT_DENY {
				b.Errorf("Unexpected result: %v", result.Effect)
			}
		}
	})
}

func mkEngine(tb testing.TB) (*Engine, context.CancelFunc) {
	tb.Helper()

	dir := test.PathToDir(tb, "store")

	ctx, cancelFunc := context.WithCancel(context.Background())

	store, err := disk.NewReadOnlyStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(tb, err)

	eng, err := New(ctx, store)
	require.NoError(tb, err)

	return eng, cancelFunc
}
