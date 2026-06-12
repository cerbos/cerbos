// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package parser_test

import (
	"go/types"
	"iter"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	sourcev1 "github.com/cerbos/cerbos/api/genpb/cerbos/source/v1"
	"github.com/cerbos/cerbos/internal/parser"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestUnmarshalWKT(t *testing.T) {
	want := &privatev1.WellKnownTypes{
		ListValue: must(structpb.NewList([]any{
			nil,
			nil,
			nil,
			1,
			"two",
			true,
			false,
			map[string]any{
				"three": "four",
				"five":  6,
			},
			[]any{
				"seven",
				8,
				map[string]any{
					"nine": 10,
				},
			},
		})),
		RepeatedListValue: []*structpb.ListValue{
			must(structpb.NewList([]any{
				nil,
				1,
				"two",
			})),
			must(structpb.NewList([]any{
				true,
				false,
			})),
			must(structpb.NewList([]any{
				map[string]any{
					"three": "four",
					"five":  6,
				},
				[]any{
					"seven",
					8,
					map[string]any{
						"nine": 10,
					},
				},
			})),
		},
		ListValueMap: map[string]*structpb.ListValue{
			"foo": must(structpb.NewList([]any{
				nil,
				1,
				"two",
			})),
			"bar": must(structpb.NewList([]any{
				true,
				false,
			})),
			"baz": must(structpb.NewList([]any{
				map[string]any{
					"three": "four",
					"five":  6,
				},
				[]any{
					"seven",
					8,
					map[string]any{
						"nine": 10,
					},
				},
			})),
		},
		NullValue: structpb.NullValue_NULL_VALUE,
		RepeatedNullValue: []structpb.NullValue{
			structpb.NullValue_NULL_VALUE,
			structpb.NullValue_NULL_VALUE,
			structpb.NullValue_NULL_VALUE,
		},
		NullValueMap: map[string]structpb.NullValue{
			"foo": structpb.NullValue_NULL_VALUE,
			"bar": structpb.NullValue_NULL_VALUE,
			"baz": structpb.NullValue_NULL_VALUE,
		},
		Struct: must(structpb.NewStruct(map[string]any{
			"one":   nil,
			"two":   3,
			"four":  "five",
			"six":   true,
			"seven": false,
			"eight": map[string]any{
				"nine":   10,
				"eleven": "twelve",
			},
			"thirteen": []any{
				14,
				"fifteen",
			},
		})),
		RepeatedStruct: []*structpb.Struct{
			must(structpb.NewStruct(map[string]any{
				"one":  nil,
				"two":  3,
				"four": "five",
			})),
			must(structpb.NewStruct(map[string]any{
				"six":   true,
				"seven": false,
			})),
			must(structpb.NewStruct(map[string]any{
				"eight": map[string]any{
					"nine":   10,
					"eleven": "twelve",
				},
			})),
			must(structpb.NewStruct(map[string]any{
				"thirteen": []any{
					14,
					"fifteen",
				},
			})),
		},
		StructMap: map[string]*structpb.Struct{
			"foo": must(structpb.NewStruct(map[string]any{
				"one":  nil,
				"two":  3,
				"four": "five",
			})),
			"bar": must(structpb.NewStruct(map[string]any{
				"six":   true,
				"seven": false,
			})),
			"baz": must(structpb.NewStruct(map[string]any{
				"eight": map[string]any{
					"nine":   10,
					"eleven": "twelve",
				},
			})),
			"qux": must(structpb.NewStruct(map[string]any{
				"thirteen": []any{
					14,
					"fifteen",
				},
			})),
		},
		ValueNull:   structpb.NewNullValue(),
		ValueNumber: structpb.NewNumberValue(1),
		ValueString: structpb.NewStringValue("two"),
		ValueBool:   structpb.NewBoolValue(true),
		ValueStruct: structpb.NewStructValue(must(structpb.NewStruct(map[string]any{
			"three": 4,
			"five":  "six",
		}))),
		ValueList: structpb.NewListValue(must(structpb.NewList([]any{
			7,
			"eight",
		}))),
		RepeatedValue: []*structpb.Value{
			structpb.NewNullValue(),
			structpb.NewNumberValue(1),
			structpb.NewStringValue("two"),
			structpb.NewBoolValue(true),
			structpb.NewBoolValue(false),
			structpb.NewStructValue(must(structpb.NewStruct(map[string]any{
				"three": "four",
				"five":  6,
			}))),
			structpb.NewListValue(must(structpb.NewList([]any{
				"seven",
				8,
				map[string]any{
					"nine": 10,
				},
			}))),
		},
		ValueMap: map[string]*structpb.Value{
			"foo":  structpb.NewNullValue(),
			"bar":  structpb.NewNumberValue(1),
			"baz":  structpb.NewStringValue("two"),
			"qux":  structpb.NewBoolValue(true),
			"quux": structpb.NewBoolValue(false),
			"quuux": structpb.NewStructValue(must(structpb.NewStruct(map[string]any{
				"three": "four",
				"five":  6,
			}))),
			"quuuux": structpb.NewListValue(must(structpb.NewList([]any{
				"seven",
				8,
				map[string]any{
					"nine": 10,
				},
			}))),
		},
		Uint64WrapperNumber: wrapperspb.UInt64(1),
		Uint64WrapperString: wrapperspb.UInt64(2),
		RepeatedUint64Wrapper: []*wrapperspb.UInt64Value{
			wrapperspb.UInt64(1),
			wrapperspb.UInt64(2),
		},
		Uint64WrapperMap: map[string]*wrapperspb.UInt64Value{
			"foo": wrapperspb.UInt64(1),
			"bar": wrapperspb.UInt64(2),
		},
	}

	want.Nested = proto.CloneOf(want)

	testCases := []struct {
		name     string
		input    string
		want     []*privatev1.WellKnownTypes
		wantErrs []*sourcev1.Error
	}{
		{
			name:  "Valid YAML",
			input: "valid.yaml",
			want:  []*privatev1.WellKnownTypes{want},
		},
		{
			name:  "Valid JSON",
			input: "valid.json",
			want:  []*privatev1.WellKnownTypes{want},
		},
		{
			name:  "YAML with incorrect value type",
			input: "invalid.yaml",
			wantErrs: []*sourcev1.Error{
				{
					Kind:     sourcev1.Error_KIND_PARSE_ERROR,
					Message:  `failed to parse value: proto: syntax error (line 1:1): unexpected token "wat"`,
					Position: &sourcev1.Position{Line: 2, Column: 9, Path: "$.struct"},
				},
			},
		},
		{
			name:  "JSON with incorrect value type",
			input: "invalid.json",
			wantErrs: []*sourcev1.Error{
				{
					Kind:     sourcev1.Error_KIND_PARSE_ERROR,
					Message:  `failed to parse value: proto: syntax error (line 1:1): unexpected token "wat"`,
					Position: &sourcev1.Position{Line: 2, Column: 13, Path: "$.struct"},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			inputFile := filepath.Join(test.PathToDir(t, "parser_wkt"), tc.input)
			input, err := os.ReadFile(inputFile)
			require.NoError(t, err, "Failed to read %s", inputFile)

			have, _, err := parser.UnmarshalBytes[privatev1.WellKnownTypes](input)
			if len(tc.wantErrs) > 0 {
				requireErrors(t, tc.wantErrs, err)
				return
			}

			require.NoError(t, err)
			require.Len(t, have, len(tc.want))
			require.Empty(t, cmp.Diff(tc.want, have, protocmp.Transform()))
		})
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// We only use a handful of well-known types in our policies and tests, so we don't need to be able to parse every possible type.
// This test checks that we can parse all the well-known types we actually use.
//
// It works by looking for concrete instances of generic types that have parser.ProtoMessage as a type parameter's constraint as a
// way to find all the message types we pass into the parsing functions. This assumes that we don't define a generic function with
// a different constraint (e.g. an interface embedding parser.ProtoMessage) that calls a parsing function.
func TestWKTUsage(t *testing.T) {
	t.Helper()

	pkgs, err := packages.Load(&packages.Config{
		Mode:       packages.LoadSyntax,
		BuildFlags: []string{"-tags=tests"},
		Tests:      true,
	}, "github.com/cerbos/cerbos/...")
	require.NoError(t, err, "Failed to load packages")

	topLevelMessages := make(map[*types.Named]*types.Struct)
	ignores := make(map[types.Object]struct{})
	for _, pkg := range pkgs {
		info := pkg.TypesInfo

		for id, instance := range info.Instances {
			obj := info.ObjectOf(id)

			if _, ok := ignores[obj]; ok {
				continue
			}

			ignore := true
			if parameterized, ok := obj.Type().(interface{ TypeParams() *types.TypeParamList }); ok {
				params := parameterized.TypeParams()
				for i := range params.Len() {
					if strings.HasPrefix(params.At(i).Constraint().String(), "github.com/cerbos/cerbos/internal/parser.ProtoMessage[") {
						ignore = false
						named, underlying, ok := messageType(instance.TypeArgs.At(i))
						if ok && named.String() != "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1.WellKnownTypes" {
							topLevelMessages[named] = underlying
						}
					}
				}
			}

			if ignore {
				ignores[obj] = struct{}{}
			}
		}
	}

	messages := maps.Clone(topLevelMessages)

	for _, underlying := range topLevelMessages {
		findReferencedMessageTypes(messages, underlying)
	}

	var wellKnownTypes []string
	for named := range messages {
		if name, ok := strings.CutPrefix(named.String(), "google.golang.org/protobuf/types/known/"); ok {
			wellKnownTypes = append(wellKnownTypes, name)
		}
	}
	slices.Sort(wellKnownTypes)

	require.Equal(t, []string{
		"structpb.ListValue",
		"structpb.Struct",
		"structpb.Value",
		"structpb.Value_BoolValue",
		"structpb.Value_ListValue",
		"structpb.Value_NullValue",
		"structpb.Value_NumberValue",
		"structpb.Value_StringValue",
		"structpb.Value_StructValue",
		"wrapperspb.UInt64Value",
	}, wellKnownTypes)
}

func findReferencedMessageTypes(messages map[*types.Named]*types.Struct, underlying *types.Struct) {
	for field := range underlying.Fields() {
		if !field.Exported() {
			continue
		}

		for n, u := range referencedMessageTypes(field.Type()) {
			if _, ok := messages[n]; !ok {
				messages[n] = u
				findReferencedMessageTypes(messages, u)
			}
		}
	}
}

func referencedMessageTypes(typ types.Type) iter.Seq2[*types.Named, *types.Struct] {
	return func(yield func(*types.Named, *types.Struct) bool) {
		switch t := typ.(type) {
		case *types.Named:
			if iface, ok := t.Underlying().(*types.Interface); ok { //nolint:nestif
				scope := t.Obj().Pkg().Scope()
				for _, name := range scope.Names() {
					if named, ok := scope.Lookup(name).Type().(*types.Named); ok {
						if underlying, ok := named.Underlying().(*types.Struct); ok {
							if types.Implements(types.NewPointer(named), iface) {
								if !yield(named, underlying) {
									return
								}
							}
						}
					}
				}
			}

		case *types.Map:
			named, underlying, ok := messageType(t.Elem())
			if ok {
				yield(named, underlying)
			}

		case *types.Slice:
			named, underlying, ok := messageType(t.Elem())
			if ok {
				yield(named, underlying)
			}

		default:
			named, underlying, ok := messageType(typ)
			if ok {
				yield(named, underlying)
			}
		}
	}
}

func messageType(typ types.Type) (*types.Named, *types.Struct, bool) {
	pointer, ok := typ.(*types.Pointer)
	if !ok {
		return nil, nil, false
	}

	named, ok := pointer.Elem().(*types.Named)
	if !ok {
		return nil, nil, false
	}

	underlying, ok := named.Underlying().(*types.Struct)
	return named, underlying, ok
}
