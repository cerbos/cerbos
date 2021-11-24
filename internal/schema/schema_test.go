package schema

import (
	"bytes"
	"encoding/base64"
	"errors"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"testing"
)

const (
	dummySchema = "LS0tCmFwaVZlcnNpb246ICJhcGkuY2VyYm9zLmRldi92MSIKZGVzY3JpcHRpb246IHwtCiBTY2hlbWEgZGVmaW5pdGlvbiBmaWxlCgpwcmluY2lwYWxTY2hlbWE6ICMgZGVmaW5lIHNjaGVtYSBmb3IgcmVxdWVzdC5wcmluY2lwYWwuYXR0cgogIHR5cGU6IG9iamVjdAogIHByb3BlcnRpZXM6CiAgICBwZXJtaXNzaW9uczoKICAgICAgdHlwZTogYXJyYXkKICAgICAgZGVzY3JpcHRpb246ICJwZXJtaXNzaW9ucyBkZWZpbmVkIGZvciB0aGlzIHVzZXIiCiAgICBlZGl0b3JfZm9yX2NhdGVnb3JpZXM6CiAgICAgIHR5cGU6IGFycmF5CiAgICBwZXJzb25hbERldGFpbHM6CiAgICAgIHR5cGU6IG9iamVjdAogICAgICBwcm9wZXJ0aWVzOgogICAgICAgIG5hbWU6CiAgICAgICAgICB0eXBlOiBzdHJpbmcKICAgICAgICBtYWlsOgogICAgICAgICAgdHlwZTogc3RyaW5nCgpyZXNvdXJjZVNjaGVtYXM6ICMgZGVmaW5lIHNjaGVtYSBmb3IgcmVxdWVzdC5yZXNvdXJjZS5hdHRyCiAgcmVzb3VyY2VfYmxvZzoKICAgIHR5cGU6IG9iamVjdAogICAgcHJvcGVydGllczoKICAgICAgY2F0ZWdvcmllczoKICAgICAgICB0eXBlOiBzdHJpbmcK"
)

func TestMethods(t *testing.T) {
	t.Run("schema.Manager.walkInputProperties", func(t *testing.T) {
		mgr := &Manager{}

		var testCases = []struct {
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
		}

		for _, tc := range testCases {
			var have = make(map[string]string)
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

		var testCases = []struct {
			name        string
			inputSchema string
			want        map[string]string
			wantErr     bool
		}{
			{
				name:        "Test 1",
				inputSchema: "LS0tCmFwaVZlcnNpb246ICJhcGkuY2VyYm9zLmRldi92MSIKZGVzY3JpcHRpb246IHwtCiBTY2hlbWEgZGVmaW5pdGlvbiBmaWxlCgpwcmluY2lwYWxTY2hlbWE6ICMgZGVmaW5lIHNjaGVtYSBmb3IgcmVxdWVzdC5wcmluY2lwYWwuYXR0cgogIHR5cGU6IG9iamVjdAogIHByb3BlcnRpZXM6CiAgICBwZXJtaXNzaW9uczoKICAgICAgdHlwZTogYXJyYXkKICAgICAgZGVzY3JpcHRpb246ICJwZXJtaXNzaW9ucyBkZWZpbmVkIGZvciB0aGlzIHVzZXIiCiAgICBlZGl0b3JfZm9yX2NhdGVnb3JpZXM6CiAgICAgIHR5cGU6IGFycmF5CiAgICBwZXJzb25hbF9kZXRhaWxzOgogICAgICB0eXBlOiBvYmplY3QKICAgICAgcHJvcGVydGllczoKICAgICAgICBuYW1lOgogICAgICAgICAgdHlwZTogc3RyaW5nCiAgICAgICAgbWFpbDoKICAgICAgICAgIHR5cGU6IHN0cmluZwoKcmVzb3VyY2VTY2hlbWFzOiAjIGRlZmluZSBzY2hlbWEgZm9yIHJlcXVlc3QucmVzb3VyY2UuYXR0cgogIHJlc291cmNlX2Jsb2c6CiAgICB0eXBlOiBvYmplY3QKICAgIHByb3BlcnRpZXM6CiAgICAgIGNhdGVnb3JpZXM6CiAgICAgICAgdHlwZTogc3RyaW5nCg==",
				want: map[string]string{
					"/permissions":           "/permissions",
					"/personal_details/mail": "/personal_details/mail",
					"/personal_details/name": "/personal_details/name",
					"/editor_for_categories": "/editor_for_categories",
				},
				wantErr: false,
			},
		}

		for _, tc := range testCases {
			schemaString, err := base64.StdEncoding.DecodeString(tc.inputSchema)
			require.NoError(t, err)

			sch, err := ReadSchema(bytes.NewReader(schemaString))
			require.NoError(t, err)

			var have = make(map[string]string)
			mgr.walkSchemaProperties("", sch.PrincipalSchema.Properties, have)

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

	t.Run("schema.Manager.validateInput", func(t *testing.T) {
		mgr := &Manager{
			conf: &Conf{
				IgnoreExtraFields: false,
			},
		}

		var testCases = []struct {
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
				want: map[string]string{
					"a": "a",
				},
				wantErr: false,
			},
		}

		for _, tc := range testCases {
			err := mgr.validateInput(tc.inputProperties, tc.schemaProperties, schemav1.ValidationError_SOURCE_PRINCIPAL)

			if err == nil {
				continue
			}

			var validationErrorList *ValidationErrorList
			ok := errors.As(err, &validationErrorList)
			if !ok {
				t.Log("failed to assert type for ValidationErrorList")
				t.Fail()
			}

			if validationErrorList.Errors != nil && !tc.wantErr {
				t.Log("wanted no error, but error occurred")
				t.Fail()
			} else if validationErrorList.Errors == nil && tc.wantErr {
				t.Log("wanted error, but no error present")
				t.Fail()
			}
		}
	})
}

func mapsEqual(want map[string]string, have map[string]string) bool {
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
