// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/open-policy-agent/opa/ast"

	"github.com/cerbos/cerbos/internal/codegen"
)

var (
	ErrAmbiguousDerivedRole = errors.New("ambiguous derived role")
	ErrCodeGenFailure       = errors.New("code generation failure")
	ErrCompileError         = errors.New("compile error")
	ErrImportNotFound       = errors.New("import not found")
	ErrInvalidImport        = errors.New("invalid import")
	ErrInvalidMatchExpr     = errors.New("invalid match expression")
	ErrNoEvaluator          = errors.New("no evaluator available")
	ErrUnknownDerivedRole   = errors.New("unknown derived role")
)

type ErrorList []*Error

func (e ErrorList) ErrOrNil() error {
	if len(e) > 0 {
		return e
	}

	return nil
}

func (e ErrorList) Error() string {
	errs := make([]string, len(e))
	for i, err := range e {
		errs[i] = err.Error()
	}

	return fmt.Sprintf("%d compilation errors:\n%s", len(e), strings.Join(errs, "\n"))
}

func (e ErrorList) Display() string {
	d := make([]string, len(e))
	for i, err := range e {
		d[i] = err.Display()
	}

	return strings.Join(d, "\n")
}

// Error describes an error encountered during compilation.
type Error struct {
	File        string
	Err         error
	Description string
}

func (e *Error) Display() string {
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	return fmt.Sprintf("%s: %s (%v)", yellow(e.File), red(e.Description), e.Err)
}

func (e *Error) MarshalJSON() ([]byte, error) {
	m := map[string]string{
		"file":        e.File,
		"error":       e.Err.Error(),
		"description": e.Description,
	}

	return json.Marshal(m)
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: [%v] %s", e.File, e.Err, e.Description)
}

func (e *Error) Unwrap() error {
	return e.Err
}

func newError(file string, err error, desc string) *Error {
	return &Error{File: file, Err: err, Description: desc}
}

func newCodeGenErrors(file string, err error) ErrorList {
	var errs []*Error

	celErr := &codegen.CELCompileError{}
	if errors.As(err, &celErr) {
		for _, ce := range celErr.Issues.Errors() {
			errs = append(errs, newError(file, ErrInvalidMatchExpr, fmt.Sprintf("Invalid match expression in '%s': %s", celErr.Parent, ce.Message)))
		}

		return errs
	}

	regoErrs := new(ast.Errors) //nolint:ifshort
	if errors.As(err, regoErrs) {
		for _, re := range *regoErrs {
			fileName := file
			if re.Location != nil && re.Location.File != "" {
				fileName = re.Location.File
			}
			errs = append(errs, newError(fileName, ErrCompileError, fmt.Sprintf("%s: %s", re.Code, re.Message)))
		}

		return errs
	}

	errs = append(errs, newError(file, ErrCompileError, err.Error()))

	return errs
}
