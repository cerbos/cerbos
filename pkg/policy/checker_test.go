package policy_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	requestv1 "github.com/charithe/menshen/pkg/generated/request/v1"
	sharedv1 "github.com/charithe/menshen/pkg/generated/shared/v1"
	"github.com/charithe/menshen/pkg/policy"
	"github.com/charithe/menshen/pkg/storage/disk"
	"github.com/charithe/menshen/pkg/test"
)

func TestChecker(t *testing.T) {
	dir := test.PathToDir(t, "store")

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	reg := policy.InitGlobal()

	_, err := disk.NewReadOnlyStore(ctx, reg, dir)
	require.NoError(t, err)

	c := reg.GetChecker()

	testCases := []struct {
		desc    string
		request func() *requestv1.Request
		want    sharedv1.Effect
		wantErr bool
	}{
		{
			desc:    "John views own leave request",
			request: mkRequest,
			want:    sharedv1.Effect_EFFECT_ALLOW,
		},
		{
			desc: "John tries to approve his own leave_request",
			request: func() *requestv1.Request {
				// John trying to approve his own leave request
				req := mkRequest()
				req.Action = "approve"

				return req
			},
			want: sharedv1.Effect_EFFECT_DENY,
		},
		{
			desc: "John's manager approves leave_request",
			request: func() *requestv1.Request {
				// John's manager approving his leave request
				req := mkRequest()
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
			request: func() *requestv1.Request {
				// Some other manager trying to approve John's leave request
				req := mkRequest()
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
			request: func() *requestv1.Request {
				// Donald Duck has a principal policy that lets him do anything on leave_request as long as it's a dev record
				req := mkRequest()
				req.Action = "approve"
				req.Principal.Id = "donald_duck"
				req.Resource.Attr["dev_record"] = structpb.NewBoolValue(true)

				return req
			},
			want: sharedv1.Effect_EFFECT_ALLOW,
		},
		{
			desc: "Donald Duck views leave_request [Principal policy cascades to resource policy]",
			request: func() *requestv1.Request {
				// Donald Duck trying to do something on a non-dev record
				// It should cascade down to resource policy because there's no explicit rule for Donald Duck
				req := mkRequest()
				req.Action = "view:public"
				req.Principal.Id = "donald_duck"

				return req
			},
			want: sharedv1.Effect_EFFECT_ALLOW,
		},
		{
			desc: "Donald Duck tries to view salary_record [Principal policy override]",
			request: func() *requestv1.Request {
				// Donald Duck has an explicit deny on salary_record
				req := mkRequest()
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
			//fmt.Println(protojson.Format(req))
			resp, err := c.Check(context.Background(), req)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, resp)
		})
	}
}

func mkRequest() *requestv1.Request {
	return &requestv1.Request{
		RequestId: "test",
		Action:    "view:public",
		Resource: &requestv1.Resource{
			Name:    "leave_request",
			Version: "20210210",
			Attr: map[string]*structpb.Value{
				"id":         structpb.NewStringValue("XX125"),
				"owner":      structpb.NewStringValue("john"),
				"geography":  structpb.NewStringValue("GB"),
				"department": structpb.NewStringValue("marketing"),
				"team":       structpb.NewStringValue("design"),
			},
		},
		Principal: &requestv1.Principal{
			Id:      "john",
			Version: "20210210",
			Roles:   []string{"employee"},
			Attr: map[string]*structpb.Value{
				"geography":  structpb.NewStringValue("GB"),
				"department": structpb.NewStringValue("marketing"),
				"team":       structpb.NewStringValue("design"),
			},
		},
	}
}
