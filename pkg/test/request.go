// +build tests

package test

import (
	"google.golang.org/protobuf/types/known/structpb"

	requestv1 "github.com/cerbos/cerbos/pkg/generated/request/v1"
)

func MkRequest() *requestv1.CheckRequest {
	return &requestv1.CheckRequest{
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
