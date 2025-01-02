// Copyright 2021-2025 Zenauth Ltd.
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

	testSchema              *jsonschema.Schema
	principalFixturesSchema *jsonschema.Schema
	resourceFixturesSchema  *jsonschema.Schema
	auxDataFixturesSchema   *jsonschema.Schema
)

func init() {
	var err error

	if testSchema, err = jsonschema.CompileString("TestSuite.schema.json", schema.TestSuiteJSONSchema); err != nil {
		log.Fatalf("failed to compile test schema: %v", err)
	}

	if principalFixturesSchema, err = jsonschema.CompileString("Principals.schema.json", schema.PrincipalFixturesJSONSchema); err != nil {
		log.Fatalf("failed to compile principal fixtures schema: %v", err)
	}

	if resourceFixturesSchema, err = jsonschema.CompileString("Resources.schema.json", schema.ResourceFixturesJSONSchema); err != nil {
		log.Fatalf("failed to compile resource fixtures schema: %v", err)
	}

	if auxDataFixturesSchema, err = jsonschema.CompileString("AuxData.schema.json", schema.AuxDataFixturesJSONSchema); err != nil {
		log.Fatalf("failed to compile aux data fixtures schema: %v", err)
	}
}

// ValidateTest validates the test in the fsys with the JSON schema.
func ValidateTest(fsys fs.FS, path string) error {
	return validate(testSchema, fsys, path)
}

// ValidatePrincipalFixtures validates the principal fixtures file in the fsys with the JSON schema.
func ValidatePrincipalFixtures(fsys fs.FS, path string) error {
	return validate(principalFixturesSchema, fsys, path)
}

// ValidateResourceFixtures validates the resource fixtures file in the fsys with the JSON schema.
func ValidateResourceFixtures(fsys fs.FS, path string) error {
	return validate(resourceFixturesSchema, fsys, path)
}

// ValidatePrincipalFixtures validates the aux data fixtures file in the fsys with the JSON schema.
func ValidateAuxDataFixtures(fsys fs.FS, path string) error {
	return validate(auxDataFixturesSchema, fsys, path)
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

func newValidationError(ve *jsonschema.ValidationError) error {
	toVisit := ve.Causes
	leaves := make(map[string]map[string]struct{})
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

		if leaves[path] == nil {
			leaves[path] = make(map[string]struct{})
		}
		leaves[path][ve.Message] = struct{}{}
	}

	verrs := make([]string, len(leaves))
	i := 0
	for path, issues := range leaves {
		verrs[i] = fmt.Sprintf("%s: [%s]", path, sortIssues(issues))
		i++
	}

	sort.Strings(verrs)
	return fmt.Errorf("file is not valid: { %s }", strings.Join(verrs, ","))
}

func sortIssues(m map[string]struct{}) string {
	values := make([]string, len(m))
	i := 0
	for v := range m {
		values[i] = v
		i++
	}

	sort.Strings(values)
	return strings.Join(values, " | ")
}
