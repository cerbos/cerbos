// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package test

import (
	"google.golang.org/protobuf/types/known/structpb"

	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
)

// GenSchema generates a sample schema.
func GenSchema() *schemav1.Schema {
	return &schemav1.Schema{
		ApiVersion: "api.cerbos.dev/v1",
		PrincipalSchema: &structpb.Value{
			Kind: &structpb.Value_StructValue{
				StructValue: &structpb.Struct{
					Fields: genFields(),
				},
			},
		},
		ResourceSchemas: map[string]*structpb.Value{
			"leave_request": {
				Kind: &structpb.Value_StructValue{
					StructValue: &structpb.Struct{
						Fields: genFields(),
					},
				},
			},
		},
	}
}

func genFields() map[string]*structpb.Value {
	return map[string]*structpb.Value{
		"type": {
			Kind: &structpb.Value_StringValue{
				StringValue: "object",
			},
		},
		"properties": {
			Kind: &structpb.Value_StructValue{
				StructValue: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"department": {
							Kind: &structpb.Value_StructValue{
								StructValue: &structpb.Struct{
									Fields: map[string]*structpb.Value{
										"type": {
											Kind: &structpb.Value_StringValue{
												StringValue: "string",
											},
										},
									},
								},
							},
						},
						"geography": {
							Kind: &structpb.Value_StructValue{
								StructValue: &structpb.Struct{
									Fields: map[string]*structpb.Value{
										"type": {
											Kind: &structpb.Value_StringValue{
												StringValue: "string",
											},
										},
									},
								},
							},
						},
						"team": {
							Kind: &structpb.Value_StructValue{
								StructValue: &structpb.Struct{
									Fields: map[string]*structpb.Value{
										"type": {
											Kind: &structpb.Value_StringValue{
												StringValue: "string",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}
