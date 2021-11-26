// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
)

func TestValidate(t *testing.T) {
	t.Run("schema.Manager.Validate", func(t *testing.T) {
		testCases := []struct {
			name    string
			input   enginev1.CheckInput
			wantErr bool
		}{
			{
				name: "Test 1",
				input: enginev1.CheckInput{
					Principal: &enginev1.Principal{
						Attr: map[string]*structpb.Value{
							"department": {
								Kind: &structpb.Value_StringValue{
									StringValue: "marketing",
								},
							},
							"geography": {
								Kind: &structpb.Value_StringValue{
									StringValue: "GB",
								},
							},
							"team": {
								Kind: &structpb.Value_StringValue{
									StringValue: "design",
								},
							},
						},
					},
					Resource: &enginev1.Resource{
						Attr: map[string]*structpb.Value{
							"department": {
								Kind: &structpb.Value_StringValue{
									StringValue: "marketing",
								},
							},
							"geography": {
								Kind: &structpb.Value_StringValue{
									StringValue: "GB",
								},
							},
							"team": {
								Kind: &structpb.Value_StringValue{
									StringValue: "design",
								},
							},
							"owner": {
								Kind: &structpb.Value_StringValue{
									StringValue: "harry",
								},
							},
						},
					},
					Actions: []string{"view"},
				},
				wantErr: false,
			},
			{
				name: "Test 2 - Nil Check",
				input: enginev1.CheckInput{
					Principal: &enginev1.Principal{
						Attr: nil,
					},
					Resource: &enginev1.Resource{
						Attr: nil,
					},
					Actions: []string{"view"},
				},
				wantErr: false,
			},
		}

		mgr := &Manager{
			conf: &Conf{
				IgnoreUnknownFields: false,
			},
		}

		for _, tc := range testCases {
			err := mgr.Validate(context.TODO(), &tc.input)

			if err == nil {
				continue
			}

			var validationErrorList *ValidationErrorList
			ok := errors.As(err, &validationErrorList)
			if !ok {
				t.Log("failed to assert type for ValidationErrorList")
				t.Fail()
			}

			if validationErrorList != nil && !tc.wantErr {
				t.Log("wanted no error, but error occurred")
				t.Fail()
			} else if validationErrorList == nil && tc.wantErr {
				t.Log("wanted error, but no error present")
				t.Fail()
			}
		}
	})
}

func TestMethods(t *testing.T) {
	t.Run("schema.Manager.walkInputProperties", func(t *testing.T) {
		mgr := &Manager{}

		testCases := []struct {
			name    string
			input   map[string]*structpb.Value
			want    map[string]string
			wantErr bool
		}{
			{
				name: "Test 1",
				input: map[string]*structpb.Value{
					"somekey": {
						Kind: &structpb.Value_StructValue{
							StructValue: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"somekey1": {
										Kind: &structpb.Value_StringValue{
											StringValue: "somevalue1",
										},
									},
									"somekey2": {
										Kind: &structpb.Value_NumberValue{
											NumberValue: 2,
										},
									},
								},
							},
						},
					},
					"somekey3": {
						Kind: &structpb.Value_BoolValue{
							BoolValue: true,
						},
					},
				},
				want: map[string]string{
					"/somekey/somekey1": "/somekey/somekey1",
					"/somekey/somekey2": "/somekey/somekey2",
					"/somekey3":         "/somekey3",
				},
				wantErr: false,
			},
			{
				name:    "Test 2 - Nil Check",
				input:   nil,
				want:    nil,
				wantErr: false,
			},
		}

		for _, tc := range testCases {
			have := make(map[string]string)
			mgr.walkInputProperties("", tc.input, have)

			eq := mapsEqual(tc.want, have)
			if !eq && !tc.wantErr {
				t.Log("wanted map is not equal to resulting map")
				t.Fail()
			} else if eq && tc.wantErr {
				t.Log("wanted map is equal to resulting map, but error expected")
				t.Fail()
			}
		}
	})

	t.Run("schema.Manager.walkSchemaProperties", func(t *testing.T) {
		mgr := &Manager{}

		testCases := []struct {
			name          string
			inputSchema   string
			wantPrincipal map[string]string
			wantResource  map[string]string
			wantErr       bool
		}{
			{
				name:        "Test 1",
				inputSchema: "LS0tCmFwaVZlcnNpb246ICJhcGkuY2VyYm9zLmRldi92MSIKZGVzY3JpcHRpb246IHwtCiBTY2hlbWEgZGVmaW5pdGlvbiBmaWxlCgpwcmluY2lwYWxTY2hlbWE6ICMgZGVmaW5lIHNjaGVtYSBmb3IgcmVxdWVzdC5wcmluY2lwYWwuYXR0cgogIHR5cGU6IG9iamVjdAogIHByb3BlcnRpZXM6CiAgICBwZXJtaXNzaW9uczoKICAgICAgdHlwZTogYXJyYXkKICAgICAgZGVzY3JpcHRpb246ICJwZXJtaXNzaW9ucyBkZWZpbmVkIGZvciB0aGlzIHVzZXIiCiAgICBlZGl0b3JfZm9yX2NhdGVnb3JpZXM6CiAgICAgIHR5cGU6IGFycmF5CiAgICBwZXJzb25hbF9kZXRhaWxzOgogICAgICB0eXBlOiBvYmplY3QKICAgICAgcHJvcGVydGllczoKICAgICAgICBuYW1lOgogICAgICAgICAgdHlwZTogc3RyaW5nCiAgICAgICAgbWFpbDoKICAgICAgICAgIHR5cGU6IHN0cmluZwoKcmVzb3VyY2VTY2hlbWFzOiAjIGRlZmluZSBzY2hlbWEgZm9yIHJlcXVlc3QucmVzb3VyY2UuYXR0cgogIHJlc291cmNlX2Jsb2c6CiAgICB0eXBlOiBvYmplY3QKICAgIHByb3BlcnRpZXM6CiAgICAgIGNhdGVnb3JpZXM6CiAgICAgICAgdHlwZTogc3RyaW5nCg==",
				wantPrincipal: map[string]string{
					"/permissions":           "/permissions",
					"/personal_details/mail": "/personal_details/mail",
					"/personal_details/name": "/personal_details/name",
					"/editor_for_categories": "/editor_for_categories",
				},
				wantResource: map[string]string{
					"/categories": "/categories",
				},
				wantErr: false,
			},
		}

		for _, tc := range testCases {
			schemaString, err := base64.StdEncoding.DecodeString(tc.inputSchema)
			require.NoError(t, err)

			sch, err := ReadSchema(bytes.NewReader(schemaString))
			require.NoError(t, err)

			havePrincipal := make(map[string]string)
			mgr.walkSchemaProperties("", sch.PrincipalSchema.Properties, havePrincipal)

			eq := mapsEqual(tc.wantPrincipal, havePrincipal)
			if !eq && !tc.wantErr {
				t.Log("wanted map is not equal to resulting map")
				t.Fail()
			} else if eq && tc.wantErr {
				t.Log("wanted map is equal to resulting map, but error expected")
				t.Fail()
			}

			haveResource := make(map[string]string)
			for _, resourceSchema := range sch.ResourceSchemas {
				mgr.walkSchemaProperties("", resourceSchema.Properties, haveResource)
				eq = mapsEqual(tc.wantResource, haveResource)
				if !eq && !tc.wantErr {
					t.Log("wanted map is not equal to resulting map")
					t.Fail()
				} else if eq && tc.wantErr {
					t.Log("wanted map is equal to resulting map, but error expected")
					t.Fail()
				}
			}
		}
	})

	t.Run("schema.Manager.validateInput", func(t *testing.T) {
		mgr := &Manager{
			conf: &Conf{
				IgnoreUnknownFields: false,
			},
		}

		testCases := []struct {
			name             string
			schemaProperties map[string]string
			inputProperties  map[string]*structpb.Value
			want             map[string]string
			wantErr          bool
		}{
			{
				name: "Test 1",
				inputProperties: map[string]*structpb.Value{
					"somekey": {
						Kind: &structpb.Value_StructValue{
							StructValue: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"somekey1": {
										Kind: &structpb.Value_StringValue{
											StringValue: "somevalue1",
										},
									},
									"somekey2": {
										Kind: &structpb.Value_NumberValue{
											NumberValue: 2,
										},
									},
								},
							},
						},
					},
					"somekey3": {
						Kind: &structpb.Value_BoolValue{
							BoolValue: true,
						},
					},
				},
				schemaProperties: map[string]string{
					"/somekey/somekey1": "/somekey/somekey1",
					"/somekey/somekey2": "/somekey/somekey2",
					"/somekey3":         "/somekey3",
				},
				wantErr: false,
			},
			{
				name: "Test 2 - Extra fields provided in input",
				inputProperties: map[string]*structpb.Value{
					"somekey": {
						Kind: &structpb.Value_StructValue{
							StructValue: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"somekey1": {
										Kind: &structpb.Value_StringValue{
											StringValue: "somevalue1",
										},
									},
									"somekey2": {
										Kind: &structpb.Value_NumberValue{
											NumberValue: 2,
										},
									},
								},
							},
						},
					},
					"somekey3": {
						Kind: &structpb.Value_BoolValue{
							BoolValue: true,
						},
					},
				},
				schemaProperties: map[string]string{
					"/somekey/somekey1": "/somekey/somekey1",
					"/somekey/somekey2": "/somekey/somekey2",
				},
				wantErr: true,
			},
		}

		for _, tc := range testCases {
			err := mgr.validateInput(tc.inputProperties, tc.schemaProperties, schemav1.ValidationError_SOURCE_PRINCIPAL)

			if err == nil {
				continue
			}

			var validationErrorList ValidationErrorList
			ok := errors.As(err, &validationErrorList)
			if !ok {
				t.Log("failed to assert type for ValidationErrorList")
				t.Fail()
			}

			if validationErrorList != nil && !tc.wantErr {
				t.Log("wanted no error, but error occurred")
				t.Fail()
			} else if validationErrorList == nil && tc.wantErr {
				t.Log("wanted error, but no error present")
				t.Fail()
			}
		}
	})
}

func mapsEqual(want, have map[string]string) bool {
	if want == nil && have == nil {
		return true
	}

	for keyWant, valueWant := range want {
		valueHave, ok := have[keyWant]
		if !ok {
			return false
		}

		if valueWant != valueHave {
			return false
		}
	}

	return true
}
