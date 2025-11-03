// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package test

import (
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
)

func MkCheckResourceSetRequest() *requestv1.CheckResourceSetRequest {
	return &requestv1.CheckResourceSetRequest{
		RequestId: "test",
		Actions:   []string{"view:public", "approve", "create"},
		Principal: &enginev1.Principal{
			Id:            "donald_duck",
			PolicyVersion: "20210210",
			Roles:         []string{"employee"},
			Attr: map[string]*structpb.Value{
				"geography":  structpb.NewStringValue("GB"),
				"department": structpb.NewStringValue("marketing"),
				"team":       structpb.NewStringValue("design"),
			},
		},
		Resource: &requestv1.ResourceSet{
			Kind:          "leave_request",
			PolicyVersion: "20210210",
			Instances: map[string]*requestv1.AttributesMap{
				"XX125": {
					Attr: map[string]*structpb.Value{
						"id":         structpb.NewStringValue("XX125"),
						"owner":      structpb.NewStringValue("john"),
						"geography":  structpb.NewStringValue("GB"),
						"department": structpb.NewStringValue("marketing"),
						"team":       structpb.NewStringValue("design"),
					},
				},
			},
		},
	}
}
