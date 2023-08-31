// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"errors"
	"fmt"
	"strings"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/fatih/color"
	"github.com/google/cel-go/cel"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	errAmbiguousDerivedRole   = errors.New("ambiguous derived role")
	errCyclicalVariables      = errors.New("cyclical variable definitions")
	errImportNotFound         = errors.New("import not found")
	errInvalidCompilationUnit = errors.New("invalid compilation unit")
	errInvalidResourceRule    = errors.New("invalid resource rule")
	errInvalidSchema          = errors.New("invalid schema")
	errMissingDefinition      = errors.New("missing policy definition")
	errScriptsUnsupported     = errors.New("scripts in conditions are no longer supported")
	errUndefinedVariable      = errors.New("undefined variable")
	errUnexpectedErr          = errors.New("unexpected error")
	errUnknownDerivedRole     = errors.New("unknown derived role")
	errVariableRedefined      = errors.New("variable redefined")
)

type ErrorList struct {
	*runtimev1.CompileErrors
}

func newErrorList() *ErrorList {
	return &ErrorList{CompileErrors: &runtimev1.CompileErrors{}}
}

func (e *ErrorList) ErrOrNil() error {
	if e.CompileErrors != nil && len(e.Errors) > 0 {
		return e
	}

	return nil
}

func (e *ErrorList) Error() string {
	errs := make([]string, len(e.Errors))
	for i, err := range e.Errors {
		errs[i] = errorString(err)
	}

	return fmt.Sprintf("%d compilation errors:\n%s", len(errs), strings.Join(errs, "\n"))
}

func (e *ErrorList) Display() string {
	d := make([]string, len(e.Errors))
	for i, err := range e.Errors {
		d[i] = errorDisplay(err)
	}

	return strings.Join(d, "\n")
}

func (e *ErrorList) Add(err error) {
	if errList := new(ErrorList); errors.As(err, &errList) {
		e.Errors = append(e.Errors, errList.Errors...)
		return
	}

	tmpErr := new(Error)
	if errors.As(err, &tmpErr) {
		e.Errors = append(e.Errors, tmpErr.CompileErrors_Err)
		return
	}

	e.Errors = append(e.Errors, newError("-", "", err).CompileErrors_Err)
}

// Error describes an error encountered during compilation.
type Error struct {
	*runtimev1.CompileErrors_Err
}

func (e *Error) Display() string {
	return errorDisplay(e.CompileErrors_Err)
}

func errorDisplay(err *runtimev1.CompileErrors_Err) string {
	if err == nil {
		return ""
	}

	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	if err.Description != "" {
		return fmt.Sprintf("%s: %s (%s)", yellow(err.File), red(err.Description), err.Error)
	}
	return fmt.Sprintf("%s: %s", yellow(err.File), red(err.Error))
}

func (e *Error) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(e.CompileErrors_Err)
}

func (e *Error) Error() string {
	return errorString(e.CompileErrors_Err)
}

func errorString(err *runtimev1.CompileErrors_Err) string {
	if err.Description != "" {
		return fmt.Sprintf("%s: %s (%s)", err.File, err.Description, err.Error)
	}
	return fmt.Sprintf("%s: %s", err.File, err.Error)
}

func newError(file, desc string, err error) *Error {
	return &Error{CompileErrors_Err: &runtimev1.CompileErrors_Err{File: file, Error: err.Error(), Description: desc}}
}

// CELCompileError holds CEL compilation errors.
type CELCompileError struct {
	issues *cel.Issues
	expr   string
}

func newCELCompileError(expr string, issues *cel.Issues) *CELCompileError {
	return &CELCompileError{expr: expr, issues: issues}
}

func (cce *CELCompileError) Error() string {
	errList := make([]string, len(cce.issues.Errors()))
	for i, ce := range cce.issues.Errors() {
		errList[i] = ce.Message
	}

	return fmt.Sprintf("failed to compile `%s` [%s]", cce.expr, strings.Join(errList, ", "))
}

func (cce *CELCompileError) Unwrap() error {
	return cce.issues.Err()
}
