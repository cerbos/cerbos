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
	"sort"
	"strings"
	"testing"

	"github.com/bufbuild/protovalidate-go"
	"github.com/goccy/go-yaml/ast"
	yamlparser "github.com/goccy/go-yaml/parser"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	sourcev1 "github.com/cerbos/cerbos/api/genpb/cerbos/source/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/parser"
	"github.com/cerbos/cerbos/internal/test"
)

func TestUnmarshal(t *testing.T) {
	testCases := test.LoadTestCases(t, "protoyaml")
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

func TestFind(t *testing.T) {
	rnd := rand.New(rand.NewSource(42)) //nolint:gosec
	testCases := test.LoadTestCases(t, "protoyaml")
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
