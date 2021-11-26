// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"fmt"
	"strings"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"

	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
)

type ErrSource string

const (
	ErrSourcePrincipal ErrSource = "P.attr"
	ErrSourceResource  ErrSource = "R.attr"
)

func (e ErrSource) toProto() schemav1.ValidationError_Source {
	switch e {
	case ErrSourcePrincipal:
		return schemav1.ValidationError_SOURCE_PRINCIPAL
	case ErrSourceResource:
		return schemav1.ValidationError_SOURCE_RESOURCE
	default:
		return schemav1.ValidationError_SOURCE_UNSPECIFIED
	}
}

func newValidationError(err jsonschema.Detailed, source ErrSource) ValidationError {
	return ValidationError{
		Path:    err.InstanceLocation,
		Message: err.Error,
		Source:  source,
	}
}

func newValidationErrorList(validationErr *jsonschema.ValidationError, source ErrSource) ValidationErrorList {
	if validationErr == nil {
		return nil
	}

	details := validationErr.DetailedOutput()
	if details.Valid {
		return nil
	}

	errs := make([]ValidationError, len(details.Errors))
	for i, err := range details.Errors {
		errs[i] = newValidationError(err, source)
	}

	return errs
}

func mergeErrLists(el1, el2 ValidationErrorList) error {
	if len(el1)+len(el2) == 0 {
		return nil
	}

	return append(el1, el2...)
}

type ValidationError struct {
	Path    string
	Message string
	Source  ErrSource
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s[%s]: %s", e.Source, e.Path, e.Message)
}

func (e ValidationError) toProto() *schemav1.ValidationError {
	return &schemav1.ValidationError{
		Path:    e.Path,
		Message: e.Message,
		Source:  e.Source.toProto(),
	}
}

type ValidationErrorList []ValidationError

func (e ValidationErrorList) ErrOrNil() error {
	if len(e) == 0 {
		return nil
	}

	return e
}

func (e ValidationErrorList) Error() string {
	return fmt.Sprintf("Validation errors: [%s]", strings.Join(e.ErrorMessages(), ", "))
}

func (e ValidationErrorList) ErrorMessages() []string {
	if len(e) == 0 {
		return nil
	}

	msgs := make([]string, len(e))
	for i, err := range e {
		msgs[i] = err.Error()
	}

	return msgs
}

func (e ValidationErrorList) SchemaErrors() []*schemav1.ValidationError {
	numErrs := len(e)
	if numErrs == 0 {
		return nil
	}

	schemaErrs := make([]*schemav1.ValidationError, numErrs)
	for i, vErr := range e {
		schemaErrs[i] = vErr.toProto()
	}

	return schemaErrs
}
