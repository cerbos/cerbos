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

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	"github.com/cerbos/cerbos/internal/protoyaml"
	"github.com/cerbos/cerbos/internal/test"
)

func TestUnmarshaler(t *testing.T) {
	testCases := test.LoadTestCases(t, "protoyaml")
	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			tc, input := loadTestCase(t, testCase)
			u := protoyaml.NewUnmarshaler(func() *policyv1.Policy { return &policyv1.Policy{} })
			have, err := u.UnmarshalReader(input)

			t.Cleanup(func() {
				if t.Failed() {
					if err != nil {
						t.Logf("GOT ERR: %v", err)
					}

					for _, h := range have {
						t.Logf("GOT:\n%s", protojson.Format(h))
					}
				}
			})

			if len(tc.WantErrors) > 0 {
				require.Error(t, err, "Expected error")
				require.Equal(t, strings.Join(tc.WantErrors, "\n"), err.Error())
			} else {
				require.NoError(t, err)
			}

			if len(tc.Want) > 0 {
				require.Empty(t, cmp.Diff(tc.Want, have, protocmp.Transform()))
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

	/*
		switch n := node.(type) {
		case *ast.CommentNode:
			log.Println(">>> comment")
		case *ast.NullNode:
			log.Println(">>> null")
		case *ast.IntegerNode:
			log.Println(">>> integer")
		case *ast.FloatNode:
			log.Println(">>> float")
		case *ast.StringNode:
			log.Println(">>> string")
		case *ast.MergeKeyNode:
			log.Println(">>> merge_key")
		case *ast.BoolNode:
			log.Println(">>> bool")
		case *ast.InfinityNode:
			log.Println(">>> infinity")
		case *ast.NanNode:
			log.Println(">>> nan")
		case *ast.LiteralNode:
			log.Printf(">>> literal: %s", n.Value)
		case *ast.DirectiveNode:
			log.Printf(">>> directive: %s", n.Value)
		case *ast.TagNode:
			log.Printf(">>> tag: %s", n.Value)
		case *ast.DocumentNode:
			log.Println(">>> document")
		case *ast.MappingNode:
			log.Println(">>> mapping")
			for _, value := range n.Values {
				log.Printf(">>> --- %s", value)
			}
		case *ast.MappingKeyNode:
			log.Printf(">>> mapping_key: %s", n.Value)
		case *ast.MappingValueNode:
			log.Printf(">>> mapping_value: %s -> %s", n.Key, n.Value)
		case *ast.SequenceNode:
			log.Println(">>> sequence")
			for _, value := range n.Values {
				log.Printf(">>> --- %s", value)
			}
		case *ast.AnchorNode:
			log.Printf(">>> anchor: %s -> %s", n.Name, n.Value)
		case *ast.AliasNode:
			log.Printf(">>> alias: %s", n.Value)
		}
	*/

	tok := node.GetToken()
	log.Printf("%s %s: %s -> %s", strings.Repeat(">", tok.Position.IndentNum+1), tok.Position, node.GetPath(), node.Type())
	return astWalker(walkAST)
}
