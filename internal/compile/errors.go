// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/google/cel-go/cel"
	"google.golang.org/protobuf/encoding/protojson"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/util"
)

var (
	errAmbiguousDerivedRole   = errors.New("ambiguous derived role")
	errConstantRedefined      = errors.New("constant redefined")
	errCyclicalVariables      = errors.New("cyclical variable definitions")
	errImportNotFound         = errors.New("import not found")
	errInvalidCompilationUnit = errors.New("invalid compilation unit")
	errInvalidResourceRule    = errors.New("invalid resource rule")
	errInvalidSchema          = errors.New("invalid schema")
	errMissingDefinition      = errors.New("missing policy definition")
	errScriptsUnsupported     = errors.New("scripts in conditions are no longer supported")
	errUndefinedConstant      = errors.New("undefined constant")
	errUndefinedVariable      = errors.New("undefined variable")
	errUnexpectedErr          = errors.New("unexpected error")
	errUnknownDerivedRole     = errors.New("unknown derived role")
	errVariableRedefined      = errors.New("variable redefined")
)

type ErrorSet struct {
	CompileErrors map[uint64]*runtimev1.CompileErrors_Err
}

func newErrorSet() *ErrorSet {
	return &ErrorSet{CompileErrors: make(map[uint64]*runtimev1.CompileErrors_Err)}
}

func (e *ErrorSet) Errors() *runtimev1.CompileErrors {
	if e == nil || len(e.CompileErrors) == 0 {
		return nil
	}

	out := &runtimev1.CompileErrors{Errors: make([]*runtimev1.CompileErrors_Err, len(e.CompileErrors))}
	i := 0
	for _, err := range e.CompileErrors {
		out.Errors[i] = err
		i++
	}

	sort.Slice(out.Errors, func(i, j int) bool {
		a, b := out.Errors[i], out.Errors[j]
		if a.GetFile() == b.GetFile() {
			ap, bp := a.GetPosition(), b.GetPosition()
			if ap.GetLine() == bp.GetLine() {
				if ap.GetColumn() == bp.GetColumn() {
					return a.GetDescription() < b.GetDescription()
				}
				return ap.GetColumn() < bp.GetColumn()
			}
			return ap.GetLine() < bp.GetLine()
		}

		return a.GetFile() < b.GetFile()
	})

	return out
}

func (e *ErrorSet) ErrOrNil() error {
	if e != nil && len(e.CompileErrors) > 0 {
		return e
	}

	return nil
}

func (e *ErrorSet) Error() string {
	errs := make([]string, len(e.CompileErrors))
	i := 0
	for _, err := range e.CompileErrors {
		errs[i] = errorString(err)
		i++
	}

	sort.Strings(errs)
	return fmt.Sprintf("%d compilation errors:\n%s", len(errs), strings.Join(errs, "\n"))
}

func (e *ErrorSet) Add(err error) {
	if errList := new(ErrorSet); errors.As(err, &errList) {
		maps.Copy(e.CompileErrors, errList.CompileErrors)
		return
	}

	tmpErr := new(Error)
	if errors.As(err, &tmpErr) {
		key := util.HashStr(fmt.Sprintf("%s:%d:%d:%s", tmpErr.GetFile(), tmpErr.GetPosition().GetLine(), tmpErr.GetPosition().GetColumn(), tmpErr.GetDescription()))
		e.CompileErrors[key] = tmpErr.CompileErrors_Err
		return
	}

	key := util.HashStr(err.Error())
	e.CompileErrors[key] = newError("-", "", err).CompileErrors_Err
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
		if err.Position != nil {
			return fmt.Sprintf("%s:%d:%d: %s (%s)", err.File, err.Position.GetLine(), err.Position.GetColumn(), err.Description, err.Error)
		}
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
	return "invalid expression"
}

func (cce *CELCompileError) Unwrap() error {
	return cce.issues.Err()
}
