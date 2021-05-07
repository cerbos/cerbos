// Copyright 2021 Zenauth Ltd.

// +build tests

package test

import (
	"google.golang.org/protobuf/types/known/structpb"

	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
)

func MkCheckRequest() *requestv1.CheckRequest {
	return &requestv1.CheckRequest{
		RequestId: "test",
		Actions:   []string{"view:public"},
		Resource: &requestv1.Resource{
			Name:          "leave_request",
			PolicyVersion: "20210210",
			Attr: map[string]*structpb.Value{
				"id":         structpb.NewStringValue("XX125"),
				"owner":      structpb.NewStringValue("john"),
				"geography":  structpb.NewStringValue("GB"),
				"department": structpb.NewStringValue("marketing"),
				"team":       structpb.NewStringValue("design"),
			},
		},
		Principal: &requestv1.Principal{
			Id:            "john",
			PolicyVersion: "20210210",
			Roles:         []string{"employee"},
			Attr: map[string]*structpb.Value{
				"geography":  structpb.NewStringValue("GB"),
				"department": structpb.NewStringValue("marketing"),
				"team":       structpb.NewStringValue("design"),
			},
		},
	}
}

func MkCheckResourceBatchRequest() *requestv1.CheckResourceBatchRequest {
	return &requestv1.CheckResourceBatchRequest{
		RequestId: "test",
		Actions:   []string{"view:public", "approve", "create"},
		Principal: &requestv1.Principal{
			Id:            "donald_duck",
			PolicyVersion: "20210210",
			Roles:         []string{"employee"},
			Attr: map[string]*structpb.Value{
				"geography":  structpb.NewStringValue("GB"),
				"department": structpb.NewStringValue("marketing"),
				"team":       structpb.NewStringValue("design"),
			},
		},
		Resource: &requestv1.ResourceBatch{
			Name:          "leave_request",
			PolicyVersion: "20210210",
			Instances: map[string]*requestv1.Attributes{
				"XX125": {
					Attr: map[string]*structpb.Value{
						"id":         structpb.NewStringValue("XX125"),
						"owner":      structpb.NewStringValue("john"),
						"geography":  structpb.NewStringValue("GB"),
						"department": structpb.NewStringValue("marketing"),
						"team":       structpb.NewStringValue("design"),
					},
				},
				/*
					"XX150": {
						Attr: map[string]*structpb.Value{
							"id":         structpb.NewStringValue("XX150"),
							"owner":      structpb.NewStringValue("mary"),
							"geography":  structpb.NewStringValue("GB"),
							"department": structpb.NewStringValue("marketing"),
							"team":       structpb.NewStringValue("design"),
						},
					},
					"XX250": {
						Attr: map[string]*structpb.Value{
							"id":         structpb.NewStringValue("XX250"),
							"owner":      structpb.NewStringValue("xenia"),
							"geography":  structpb.NewStringValue("GB"),
							"department": structpb.NewStringValue("marketing"),
							"team":       structpb.NewStringValue("design"),
						},
					},
					"YY100": {
						Attr: map[string]*structpb.Value{
							"id":         structpb.NewStringValue("YY100"),
							"owner":      structpb.NewStringValue("zach"),
							"geography":  structpb.NewStringValue("US"),
							"department": structpb.NewStringValue("marketing"),
							"team":       structpb.NewStringValue("comms"),
							"dev_record": structpb.NewBoolValue(true),
						},
					},
					"YY200": {
						Attr: map[string]*structpb.Value{
							"id":         structpb.NewStringValue("YY200"),
							"owner":      structpb.NewStringValue("christa"),
							"geography":  structpb.NewStringValue("GB"),
							"department": structpb.NewStringValue("engineering"),
							"team":       structpb.NewStringValue("cloud"),
							"dev_record": structpb.NewBoolValue(true),
						},
					},
				*/
			},
		},
	}
}
