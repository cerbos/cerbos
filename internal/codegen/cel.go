// Copyright 2021 Zenauth Ltd.

package codegen

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/ext"

	policyv1 "github.com/cerbos/cerbos/internal/genpb/policy/v1"
)

const (
	CELRequestIdent    = "request"
	CELResourceAbbrev  = "R"
	CELPrincipalAbbrev = "P"
)

func GenerateCELProgram(parent string, m *policyv1.Match) (cel.Program, error) {
	env, err := cel.NewEnv(
		cel.CustomTypeAdapter(NewCustomCELTypeAdapter()),
		cel.Declarations(
			decls.NewVar(CELRequestIdent, decls.NewMapType(decls.String, decls.Dyn)),
			decls.NewVar(CELResourceAbbrev, decls.NewMapType(decls.String, decls.Dyn)),
			decls.NewVar(CELPrincipalAbbrev, decls.NewMapType(decls.String, decls.Dyn)),
		),
		ext.Strings(),
		ext.Encoders(),
		CerbosCELLib(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	celExpr, err := generateMatchCode(m)
	if err != nil {
		return nil, err
	}

	celAST, issues := env.Compile(celExpr)
	if issues != nil && issues.Err() != nil {
		return nil, &CELCompileError{Parent: parent, Issues: issues}
	}

	return env.Program(celAST)
}

func generateMatchCode(m *policyv1.Match) (string, error) {
	cg := &celGen{Builder: new(strings.Builder)}
	if err := cg.addMatch(m); err != nil {
		return "", err
	}

	return cg.String(), nil
}

type celGen struct {
	*strings.Builder
}

func (cg *celGen) addMatch(m *policyv1.Match) error {
	switch t := m.Op.(type) {
	case *policyv1.Match_Expr:
		cg.WriteString(t.Expr)
	case *policyv1.Match_All:
		cg.WriteString("(")
		if err := cg.join("&&", t.All.Of); err != nil {
			return err
		}
		cg.WriteString(")")
	case *policyv1.Match_Any:
		cg.WriteString("(")
		if err := cg.join("||", t.Any.Of); err != nil {
			return err
		}
		cg.WriteString(")")
	case *policyv1.Match_None:
		cg.WriteString("!(")
		if err := cg.join("||", t.None.Of); err != nil {
			return err
		}
		cg.WriteString(")")
	default:
		return fmt.Errorf("unknown match operation: %T", t)
	}

	return nil
}

func (cg *celGen) join(operator string, expr []*policyv1.Match) error {
	n := len(expr) - 1
	for i := 0; i < n; i++ {
		if err := cg.addMatch(expr[i]); err != nil {
			return fmt.Errorf("failed to generate code for %v: %w", expr[i], err)
		}
		cg.WriteString(" ")
		cg.WriteString(operator)
		cg.WriteString(" ")
	}

	if err := cg.addMatch(expr[n]); err != nil {
		return fmt.Errorf("failed to generate code for %v: %w", expr[n], err)
	}

	return nil
}
