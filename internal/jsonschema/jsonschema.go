// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package jsonschema

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"sort"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/cerbos/cerbos/schema"
)

var (
	ErrEmptyFile = errors.New("empty file")

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
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", path, err)
	}

	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("%w: %s", ErrEmptyFile, path)
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

		return newValidationError(validationErr)
	}

	return nil
}

func newValidationError(err *jsonschema.ValidationError) error {
	toVisit := err.Causes
	var leaves []validationError
	for ; len(toVisit) > 0; toVisit = toVisit[1:] {
		ve := toVisit[0]
		if ve == nil {
			continue
		}

		if len(ve.Causes) > 0 {
			toVisit = append(toVisit, ve.Causes...)
			continue
		}

		path := "/"
		if ve.InstanceLocation != "" {
			path = ve.InstanceLocation
		}
		leaves = append(leaves, validationError{path: path, message: ve.Message})
	}

	// sort the leaves by path and message, group by path and take the first message for each path to produce a stable set of errors

	sort.Slice(leaves, func(i, j int) bool {
		if leaves[i].path == leaves[j].path {
			return leaves[i].message < leaves[j].message
		}

		return leaves[i].path < leaves[j].path
	})

	var msgs []string
	currPath := ""
	for _, l := range leaves {
		if l.path != currPath {
			msgs = append(msgs, fmt.Sprintf("%s: %s", l.path, l.message))
		}
		currPath = l.path
	}

	return fmt.Errorf("file is not valid: [%s]", strings.Join(msgs, "|"))
}

type validationError struct {
	path    string
	message string
}
