// Copyright 2021-2026 Zenauth Ltd.
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

func newValidationError(err *jsonschema.ValidationError, source ErrSource) ValidationError {
	path := "/"
	if err.InstanceLocation != "" {
		path = err.InstanceLocation
	}

	return ValidationError{
		Path:    path,
		Message: err.Message,
		Source:  source,
	}
}

type validationErrorFilter func(*jsonschema.ValidationError) bool

func newValidationErrorList(validationErr *jsonschema.ValidationError, source ErrSource, filter validationErrorFilter) ValidationErrorList {
	if validationErr == nil {
		return nil
	}

	if len(validationErr.Causes) == 0 {
		if filter == nil || filter(validationErr) {
			return ValidationErrorList{newValidationError(validationErr, source)}
		}

		return nil
	}

	var errs ValidationErrorList
	for _, err := range validationErr.Causes {
		errs = append(errs, newValidationErrorList(err, source, filter)...)
	}

	return errs
}

func NewLoadErr(source ErrSource, schema string, err error) ValidationErrorList {
	switch source {
	case ErrSourcePrincipal:
		return newLoadErr(source, fmt.Sprintf("Failed to load principal schema %q: %v", schema, err))
	case ErrSourceResource:
		return newLoadErr(source, fmt.Sprintf("Failed to load resource schema %q: %v", schema, err))
	default:
		return newLoadErr(source, fmt.Sprintf("Failed to load schema %q: %v", schema, err))
	}
}

func newLoadErr(source ErrSource, message string) ValidationErrorList {
	return ValidationErrorList{{Source: source, Message: message}}
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
