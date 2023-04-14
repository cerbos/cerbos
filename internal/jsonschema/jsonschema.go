// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package jsonschema

import (
	"fmt"
	"io"
	"io/fs"
	"log"

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
	if policySchema, err = jsonschema.CompileString("Policy.schema.json", string(schema.PolicyJSONSchema)); err != nil {
		log.Fatalf("failed to compile policy schema: %v", err)
	}

	if testSchema, err = jsonschema.CompileString("TestSuite.schema.json", string(schema.TestSuiteJSONSchema)); err != nil {
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

	var y interface{}
	if err := yaml.Unmarshal(data, &y); err != nil {
		return fmt.Errorf("failed to unmarshal file %s: %w", path, err)
	}

	return s.Validate(y)
}
