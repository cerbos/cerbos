package engine

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	sharedv1 "github.com/cerbos/cerbos/internal/genpb/shared/v1"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
)

func TestEngineCheck(t *testing.T) {
	dir := test.PathToDir(t, "store")

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	store, err := disk.NewReadOnlyStore(ctx, dir)
	require.NoError(t, err)

	eng, err := New(ctx, store)
	require.NoError(t, err)

	testCases := []struct {
		desc    string
		request func() *requestv1.CheckRequest
		want    sharedv1.Effect
		wantErr bool
	}{
		{
			desc:    "John views own leave request",
			request: test.MkRequest,
			want:    sharedv1.Effect_EFFECT_ALLOW,
		},
		{
			desc: "John tries to approve his own leave_request",
			request: func() *requestv1.CheckRequest {
				// John trying to approve his own leave request
				req := test.MkRequest()
				req.Action = "approve"

				return req
			},
			want: sharedv1.Effect_EFFECT_DENY,
		},
		{
			desc: "John's manager approves leave_request",
			request: func() *requestv1.CheckRequest {
				// John's manager approving his leave request
				req := test.MkRequest()
				req.Action = "approve"
				req.Principal.Id = "sally"
				req.Principal.Roles = []string{"employee", "manager"}
				req.Principal.Attr["managed_geographies"] = structpb.NewStringValue("GB")
				req.Resource.Attr["status"] = structpb.NewStringValue("PENDING_APPROVAL")

				return req
			},
			want: sharedv1.Effect_EFFECT_ALLOW,
		},
		{
			desc: "Some other manager tries to approve leave_request",
			request: func() *requestv1.CheckRequest {
				// Some other manager trying to approve John's leave request
				req := test.MkRequest()
				req.Action = "approve"
				req.Principal.Id = "betty"
				req.Principal.Roles = []string{"employee", "manager"}
				req.Principal.Attr["managed_geographies"] = structpb.NewStringValue("FR")
				req.Resource.Attr["status"] = structpb.NewStringValue("PENDING_APPROVAL")

				return req
			},
			want: sharedv1.Effect_EFFECT_DENY,
		},
		{
			desc: "Donald Duck approves leave_request that has dev_record attribute [Principal policy override]",
			request: func() *requestv1.CheckRequest {
				// Donald Duck has a principal policy that lets him do anything on leave_request as long as it's a dev record
				req := test.MkRequest()
				req.Action = "approve"
				req.Principal.Id = "donald_duck"
				req.Resource.Attr["dev_record"] = structpb.NewBoolValue(true)

				return req
			},
			want: sharedv1.Effect_EFFECT_ALLOW,
		},
		{
			desc: "Donald Duck views leave_request [Principal policy cascades to resource policy]",
			request: func() *requestv1.CheckRequest {
				// Donald Duck trying to do something on a non-dev record
				// It should cascade down to resource policy because there's no explicit rule for Donald Duck
				req := test.MkRequest()
				req.Action = "view:public"
				req.Principal.Id = "donald_duck"

				return req
			},
			want: sharedv1.Effect_EFFECT_ALLOW,
		},
		{
			desc: "Donald Duck tries to view salary_record [Principal policy override]",
			request: func() *requestv1.CheckRequest {
				// Donald Duck has an explicit deny on salary_record
				req := test.MkRequest()
				req.Action = "view"
				req.Principal.Id = "donald_duck"
				req.Resource.Name = "salary_record"
				req.Resource.Attr["dev_record"] = structpb.NewBoolValue(true)

				return req
			},
			want: sharedv1.Effect_EFFECT_DENY,
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
			require.Equal(t, tc.want, resp)
		})
	}
}

func BenchmarkCheck(b *testing.B) {
	dir := test.PathToDir(b, "store")

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	store, err := disk.NewReadOnlyStore(ctx, dir)
	require.NoError(b, err)

	eng, err := New(ctx, store)
	require.NoError(b, err)

	b.Run("only_resource_policy", func(b *testing.B) {
		request := test.MkRequest()

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			effect, err := eng.Check(ctx, request)
			if err != nil {
				b.Errorf("ERROR: %v", err)
			}

			if effect != sharedv1.Effect_EFFECT_ALLOW {
				b.Errorf("Unexpected result: %v", effect)
			}
		}
	})

	b.Run("only_principal_policy", func(b *testing.B) {
		request := test.MkRequest()
		request.Action = "approve"
		request.Principal.Id = "donald_duck"
		request.Resource.Attr["dev_record"] = structpb.NewBoolValue(true)

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			effect, err := eng.Check(ctx, request)
			if err != nil {
				b.Errorf("ERROR: %v", err)
			}

			if effect != sharedv1.Effect_EFFECT_ALLOW {
				b.Errorf("Unexpected result: %v", effect)
			}
		}
	})

	b.Run("fallback_to_resource_policy", func(b *testing.B) {
		request := test.MkRequest()
		request.Action = "view:public"
		request.Principal.Id = "donald_duck"

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			effect, err := eng.Check(ctx, request)
			if err != nil {
				b.Errorf("ERROR: %v", err)
			}

			if effect != sharedv1.Effect_EFFECT_ALLOW {
				b.Errorf("Unexpected result: %v", effect)
			}
		}
	})

	b.Run("no_match", func(b *testing.B) {
		request := test.MkRequest()
		request.Resource.Name = "unknown"

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			effect, err := eng.Check(ctx, request)
			if !errors.Is(err, ErrNoPoliciesMatched) {
				b.Errorf("ERROR: %v", err)
			}

			if effect != sharedv1.Effect_EFFECT_DENY {
				b.Errorf("Unexpected result: %v", effect)
			}
		}
	})
}
