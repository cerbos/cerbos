// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package protoyaml_test

import (
	"bytes"
	"io"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/bufbuild/protovalidate-go"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	sourcev1 "github.com/cerbos/cerbos/api/genpb/cerbos/source/v1"
	"github.com/cerbos/cerbos/internal/protoyaml"
	"github.com/cerbos/cerbos/internal/test"
)

func TestUnmarshaler(t *testing.T) {
	testCases := test.LoadTestCases(t, "protoyaml")
	validator, err := protovalidate.New(protovalidate.WithMessages(&policyv1.Policy{}))
	require.NoError(t, err)

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			tc, input := loadTestCase(t, testCase)
			u := protoyaml.NewUnmarshaler(func() *policyv1.Policy { return &policyv1.Policy{} }, protoyaml.WithFixInvalidStrings(), protoyaml.WithValidator(validator))
			haveMsg, haveSrc, err := u.UnmarshalReader(input)

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

			if tc.WantError {
				require.Error(t, err)
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
						require.Empty(t, cmp.Diff(want.Errors, haveSrc[i].Errors, protocmp.Transform(), protocmp.SortRepeated(func(a, b *sourcev1.Error) bool {
							if a.Position.Line == b.Position.Line {
								return a.Position.Column > b.Position.Column
							}
							return a.Position.Line > b.Position.Line
						})))
					}
				}
			}
		})
	}
}

func loadTestCase(t *testing.T, tc test.Case) (*privatev1.ProtoYamlTestCase, io.Reader) {
	t.Helper()

	var pytc privatev1.ProtoYamlTestCase
	require.NoError(t, protojson.Unmarshal(tc.Input, &pytc), "Failed to read test case")

	return &pytc, bytes.NewReader(tc.Want["input"])
}

func TestWalkAST(t *testing.T) {
	file := os.Getenv("CERBOS_PROTOYAML_WALK")
	if file == "" {
		t.Skip()
	}

	f, err := parser.ParseFile(file, 0)
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
