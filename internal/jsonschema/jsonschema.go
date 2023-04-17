// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package jsonschema

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"

	"github.com/cerbos/cerbos/schema"
)

var (
	policySchema *jsonschema.Schema
	testSchema   *jsonschema.Schema
)

func init() {
	var err error
	if policySchema, err = jsonschema.CompileString("Policy.schema.json", schema.PolicyJSONSchema); err != nil {
		log.Fatalf("failed to compile policy schema: %v", err)
	}

	if testSchema, err = jsonschema.CompileString("TestSuite.schema.json", schema.TestSuiteJSONSchema); err != nil {
		log.Fatalf("failed to compile test schema: %v", err)
	}
}

// ValidatePolicy validates the policy in the fsys with the JSON schema.
func ValidatePolicy(fsys fs.FS, path string) error {
	return validate(policySchema, fsys, path)
}

// ValidateTest validates the test in the fsys with the JSON schema.
func ValidateTest(fsys fs.FS, path string) error {
	return validate(testSchema, fsys, path)
}

func validate(s *jsonschema.Schema, fsys fs.FS, path string) error {
	f, err := fsys.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", path, err)
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", path, err)
	}

	var y any
	if err := yaml.Unmarshal(data, &y); err != nil {
		return fmt.Errorf("failed to unmarshal file %s: %w", path, err)
	}

	if err := s.Validate(y); err != nil {
		var validationErr *jsonschema.ValidationError
		if ok := errors.As(err, &validationErr); !ok {
			return fmt.Errorf("unable to validate file %s: %w", path, err)
		}

		return newValidationErrorList(validationErr)
	}

	return nil
}

func newValidationError(err *jsonschema.ValidationError) validationError {
	return validationError{
		Path:    err.InstanceLocation,
		Message: err.Message,
	}
}

func newValidationErrorList(validationErr *jsonschema.ValidationError) validationErrorList {
	if validationErr == nil {
		return nil
	}

	if len(validationErr.Causes) == 0 {
		return validationErrorList{newValidationError(validationErr)}
	}

	var errs validationErrorList
	for _, err := range validationErr.Causes {
		errs = append(errs, newValidationErrorList(err)...)
	}

	return errs
}

type validationError struct {
	Path    string
	Message string
}

func (e validationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Path, e.Message)
}

type validationErrorList []validationError

func (e validationErrorList) ErrOrNil() error {
	if len(e) == 0 {
		return nil
	}

	return e
}

func (e validationErrorList) Error() string {
	return fmt.Sprintf("[%s]", strings.Join(e.ErrorMessages(), ", "))
}

func (e validationErrorList) ErrorMessages() []string {
	if len(e) == 0 {
		return nil
	}

	msgs := make([]string, len(e))
	for i, err := range e {
		msgs[i] = err.Error()
	}

	return msgs
}
