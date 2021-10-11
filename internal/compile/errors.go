// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/google/cel-go/cel"
)

var (
	errAmbiguousDerivedRole = errors.New("ambiguous derived role")
	errImportNotFound       = errors.New("import not found")
	errInvalidResourceRule  = errors.New("invalid resource rule")
	errScriptsUnsupported   = errors.New("scripts in conditions are no longer supported")
	errUnexpectedErr        = errors.New("unexpected error")
	errUnknownDerivedRole   = errors.New("unknown derived role")
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

func (e *ErrorList) Add(err error) {
	if errList := new(ErrorList); errors.As(err, errList) {
		*e = append(*e, (*errList)...)
		return
	}

	tmpErr := &Error{}
	if errors.As(err, &tmpErr) {
		*e = append(*e, tmpErr)
		return
	}

	*e = append(*e, newError("-", "", err))
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

	if e.Description != "" {
		return fmt.Sprintf("%s: %s (%v)", yellow(e.File), red(e.Description), e.Err)
	}
	return fmt.Sprintf("%s: %v", yellow(e.File), red(e.Err))
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
	if e.Description != "" {
		return fmt.Sprintf("%s: %s (%v)", e.File, e.Description, e.Err)
	}
	return fmt.Sprintf("%s: %v", e.File, e.Err)
}

func (e *Error) Unwrap() error {
	return e.Err
}

func newError(file, desc string, err error) *Error {
	return &Error{File: file, Err: err, Description: desc}
}

// CELCompileError holds CEL compilation errors.
type CELCompileError struct {
	expr   string
	issues *cel.Issues
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
