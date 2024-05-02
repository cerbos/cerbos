// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package parser_test

import (
	"bytes"
	"errors"
	"io"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bufbuild/protovalidate-go"
	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	sourcev1 "github.com/cerbos/cerbos/api/genpb/cerbos/source/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/parser"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestUnmarshal(t *testing.T) {
	testCases := test.LoadTestCases(t, "parser")
	validator, err := protovalidate.New(protovalidate.WithMessages(&policyv1.Policy{}))
	require.NoError(t, err)

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			tc, input := loadTestCase(t, testCase)
			haveMsg, haveSrc, err := parser.Unmarshal(input, func() *policyv1.Policy { return &policyv1.Policy{} }, parser.WithValidator(validator))

			t.Cleanup(func() {
				if t.Failed() {
					if err != nil {
						t.Logf("GOT ERR: %v", err)
					}

					for i, hm := range haveMsg {
						t.Logf("GOT MSG:\n%s", protojson.Format(hm))
						t.Logf("GOT SRC:\n%s", protojson.Format(haveSrc[i]))
					}
				}
			})

			if len(tc.WantErrors) > 0 {
				require.Error(t, err)
				requireErrors(t, tc.WantErrors, err)
			} else {
				require.NoError(t, err)
			}

			if len(tc.Want) > 0 {
				require.Len(t, haveSrc, len(tc.Want))
				require.Len(t, haveMsg, len(tc.Want))

				for i, want := range tc.Want {
					hm := haveMsg[i]
					require.Empty(t, cmp.Diff(want.Message, hm, protocmp.Transform()))
					if len(want.Errors) > 0 {
						requireErrorsEqual(t, want.Errors, haveSrc[i].Errors)
					}
				}
			}
		})
	}
}

func requireErrors(t *testing.T, wantErrors []*sourcev1.Error, have error) {
	t.Helper()

	haveErrors := unwrapErrors(t, have)
	requireErrorsEqual(t, wantErrors, haveErrors)
}

func unwrapErrors(t *testing.T, err error) (allErrs []*sourcev1.Error) {
	t.Helper()

	u, ok := err.(interface{ Unwrap() []error }) //nolint:errorlint
	if ok {
		unwrapped := u.Unwrap()
		for _, ue := range unwrapped {
			children := unwrapErrors(t, ue)
			allErrs = append(allErrs, children...)
		}

		return allErrs
	}

	var unmarshalErr parser.UnmarshalError
	if errors.As(err, &unmarshalErr) {
		allErrs = append(allErrs, unmarshalErr.Err)
	} else {
		t.Fatalf("unexpected error: %v", err)
	}

	return allErrs
}

func requireErrorsEqual(t *testing.T, wantErrors, haveErrors []*sourcev1.Error) {
	t.Helper()

	require.Len(t, haveErrors, len(wantErrors))

	sortErrors(haveErrors)
	sortErrors(wantErrors)
	for i, want := range wantErrors {
		require.Empty(t, cmp.Diff(want, haveErrors[i], protocmp.Transform(), protocmp.IgnoreFields(&sourcev1.Error{}, "context")))
	}
}

func sortErrors(errs []*sourcev1.Error) {
	sort.Slice(errs, func(i, j int) bool {
		if errs[i].Position.Line == errs[j].Position.Line {
			return errs[i].Position.Column > errs[j].Position.Column
		}

		return errs[i].Position.Line > errs[j].Position.Line
	})
}

func loadTestCase(t *testing.T, tc test.Case) (*privatev1.ProtoYamlTestCase, io.Reader) {
	t.Helper()

	var pytc privatev1.ProtoYamlTestCase
	require.NoError(t, protojson.Unmarshal(tc.Input, &pytc), "Failed to read test case")

	return &pytc, bytes.NewReader(tc.Want["input"])
}

func TestUnmarshalWKT(t *testing.T) {
	structVal, err := structpb.NewStruct(map[string]any{"foo": "bar", "wibble": "wobble"})
	require.NoError(t, err)
	timestampVal, err := time.Parse(time.RFC3339, "2022-08-02T15:00:00Z")
	require.NoError(t, err)
	listVal1, err := structpb.NewList([]any{"x", "y"})
	require.NoError(t, err)
	listVal2, err := structpb.NewList([]any{1, 2})
	require.NoError(t, err)

	want := &privatev1.WellKnownTypes{
		BoolWrapper:   wrapperspb.Bool(true),
		Int32Wrapper:  wrapperspb.Int32(42),
		Int64Wrapper:  wrapperspb.Int64(42),
		Uint32Wrapper: wrapperspb.UInt32(42),
		Uint64Wrapper: wrapperspb.UInt64(42),
		FloatWrapper:  wrapperspb.Float(32.5),
		DoubleWrapper: wrapperspb.Double(32.5),
		StringWrapper: wrapperspb.String("foo"),
		BytesWrapper:  wrapperspb.Bytes([]byte("foo")),
		RepeatedBoolWrapper: []*wrapperspb.BoolValue{
			wrapperspb.Bool(true),
			wrapperspb.Bool(false),
		},
		RepeatedInt32Wrapper: []*wrapperspb.Int32Value{
			wrapperspb.Int32(42),
			wrapperspb.Int32(43),
		},
		RepeatedInt64Wrapper: []*wrapperspb.Int64Value{
			wrapperspb.Int64(43),
			wrapperspb.Int64(44),
		},
		RepeatedUint32Wrapper: []*wrapperspb.UInt32Value{
			wrapperspb.UInt32(44),
			wrapperspb.UInt32(45),
		},
		RepeatedUint64Wrapper: []*wrapperspb.UInt64Value{
			wrapperspb.UInt64(45),
			wrapperspb.UInt64(46),
		},
		RepeatedFloatWrapper: []*wrapperspb.FloatValue{
			wrapperspb.Float(3.14),
			wrapperspb.Float(3.5),
		},
		RepeatedDoubleWrapper: []*wrapperspb.DoubleValue{
			wrapperspb.Double(6.14),
			wrapperspb.Double(6.5),
		},
		RepeatedStringWrapper: []*wrapperspb.StringValue{
			wrapperspb.String("foo"),
			wrapperspb.String("bar"),
		},
		RepeatedBytesWrapper: []*wrapperspb.BytesValue{
			wrapperspb.Bytes([]byte("foo")),
			wrapperspb.Bytes([]byte("foo")),
		},
		Duration:  durationpb.New(10 * time.Second),
		Timestamp: timestamppb.New(timestampVal),
		Struct:    structVal,
		Value:     structpb.NewStringValue("bar"),
		NullValue: structpb.NullValue_NULL_VALUE,
		RepeatedDuration: []*durationpb.Duration{
			durationpb.New(5 * time.Second),
			durationpb.New(10 * time.Second),
		},
		RepeatedTimestamp: []*timestamppb.Timestamp{
			timestamppb.New(timestampVal),
			timestamppb.New(timestampVal),
		},
		RepeatedStruct: []*structpb.Struct{
			structVal,
			structVal,
		},
		RepeatedValue: []*structpb.Value{
			structpb.NewNumberValue(12),
			structpb.NewStringValue("foo"),
		},
		RepeatedListValue: []*structpb.ListValue{
			listVal1,
			listVal2,
		},
		OptionalNestedMsg: &privatev1.WellKnownTypes_Nested{
			StringField: "baz",
			ValueField:  structpb.NewNumberValue(12),
		},
	}

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
					Message:  "failed to parse value: invalid value for string type: {",
					Position: &sourcev1.Position{Line: 3, Column: 25, Path: "$.repeatedStringWrapper[0]"},
				},
			},
		},
		{
			name:  "JSON with incorrect value type",
			input: "invalid.json",
			wantErrs: []*sourcev1.Error{
				{
					Kind:     sourcev1.Error_KIND_PARSE_ERROR,
					Message:  "failed to parse value: invalid value for string type: {",
					Position: &sourcev1.Position{Line: 4, Column: 9, Path: "$.repeatedStringWrapper[0]"},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			inputFile := filepath.Join(test.PathToDir(t, "parser_wkt"), tc.input)
			input, err := os.ReadFile(inputFile)
			require.NoError(t, err, "Failed to read %s", inputFile)

			have, _, err := parser.UnmarshalBytes(input, func() *privatev1.WellKnownTypes { return &privatev1.WellKnownTypes{} })
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

func TestFind(t *testing.T) {
	rnd := rand.New(rand.NewSource(42)) //nolint:gosec
	testCases := test.LoadTestCases(t, "parser")
	for _, testCase := range testCases {
		tc, input := loadTestCase(t, testCase)
		if len(tc.Want) == 0 {
			continue
		}

		t.Run(testCase.Name, func(t *testing.T) {
			want, match := findCandidate(t, rnd, tc.Want)
			havePolicy := &policyv1.Policy{}
			haveSrcCtx, err := parser.Find(input, match, havePolicy)
			require.NoError(t, err)
			require.NotNil(t, haveSrcCtx.SourceContext)
			require.Empty(t, cmp.Diff(want, havePolicy, protocmp.Transform()))
		})
	}
}

func findCandidate(t *testing.T, rnd *rand.Rand, items []*privatev1.ProtoYamlTestCase_Want) (*policyv1.Policy, func(*policyv1.Policy) bool) {
	t.Helper()

	for i := 0; i < 5; i++ {
		idx := rnd.Intn(len(items))
		if m := items[idx].Message; m != nil && m.GetPolicyType() != nil {
			fqn := namer.FQN(m)
			t.Logf("Selected: index=%d FQN=%s", idx, fqn)
			match := func(msg *policyv1.Policy) bool {
				return namer.FQN(msg) == fqn
			}
			return m, match
		}
	}

	t.Skip("Unable to find candidate")
	return nil, nil
}

func TestWalkAST(t *testing.T) {
	file := os.Getenv("CERBOS_PROTOYAML_WALK")
	if file == "" {
		t.Skip()
	}

	f, err := yamlparser.ParseFile(file, 0)
	require.NoError(t, err)

	for _, doc := range f.Docs {
		t.Log(">>Doc start")
		ast.Walk(astWalker(walkAST), doc)
		t.Log(">>Doc end")
	}
}

type astWalker func(ast.Node) ast.Visitor

func (a astWalker) Visit(n ast.Node) ast.Visitor {
	return a(n)
}

func walkAST(node ast.Node) ast.Visitor {
	if node == nil {
		return nil
	}

	tok := node.GetToken()
	log.Printf("%s %s: %s -> %s", strings.Repeat(">", tok.Position.IndentNum+1), tok.Position, node.GetPath(), node.Type())
	return astWalker(walkAST)
}

var Dummy uint64

func BenchmarkUnmarshal(b *testing.B) {
	factory := func() *policyv1.Policy { return &policyv1.Policy{} }
	benchCases := []struct {
		policy   *policyv1.Policy
		numRules int
	}{
		{
			numRules: 10,
			policy:   generatePolicy(b, 10),
		},
		{
			numRules: 50,
			policy:   generatePolicy(b, 50),
		},
		{
			numRules: 100,
			policy:   generatePolicy(b, 100),
		},
		{
			numRules: 500,
			policy:   generatePolicy(b, 500),
		},
	}

	for _, bc := range benchCases {
		b.Run(strconv.Itoa(bc.numRules), func(b *testing.B) {
			b.ReportAllocs()
			for i := range b.N {
				b.StopTimer()
				bc.policy.Metadata = &policyv1.Metadata{
					Annotations: map[string]string{"iteration": strconv.Itoa(i)},
					Hash:        wrapperspb.UInt64(rand.Uint64()), //nolint:gosec
				}
				buf := new(bytes.Buffer)
				require.NoError(b, util.WriteYAML(buf, bc.policy))
				b.SetBytes(int64(buf.Len()))
				b.StartTimer()

				policies, srcContexts, err := parser.Unmarshal(buf, factory)
				require.NoError(b, err)
				require.Len(b, policies, 1)
				require.Len(b, srcContexts, 1)
				Dummy |= bc.policy.GetMetadata().GetHash().GetValue()
			}
		})
	}
}

func generatePolicy(b *testing.B, numRules int) *policyv1.Policy {
	b.Helper()

	pb := test.NewResourcePolicyBuilder("resource", "version")
	pb = pb.WithDerivedRolesImports("a", "b", "c", "d", "e", "f")
	for range numRules {
		pb = pb.WithRules(test.NewResourceRule("create", "read", "update", "delete").
			WithRoles("role_a", "role_b", "role_c", "role_d", "role_e").
			WithMatchExpr("a == b", "c == d", "e == f", "g == h", "i == j").
			WithEffect(effectv1.Effect_EFFECT_ALLOW).
			Build())
	}
	return pb.Build()
}
