// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package jsonschema

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path"

	"github.com/cerbos/cerbos/schema"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"

	internalschema "github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/util"
)

// ValidatePolicies validates the policies in the fsys with the given schema.
func ValidatePolicies(ctx context.Context, fsys fs.FS) error {
	s, err := jsonschema.CompileString("Policy.schema.json", string(schema.PolicyJSONSchema))
	if err != nil {
		return fmt.Errorf("failed to compile policy schema: %w", err)
	}

	if err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err != nil {
			return err
		}

		if d.IsDir() {
			if p == path.Join(".", internalschema.Directory) ||
				d.Name() == util.TestDataDirectory ||
				util.IsHidden(d.Name()) {
				return fs.SkipDir
			}

			return nil
		}

		if !util.IsSupportedFileType(d.Name()) ||
			util.IsSupportedTestFile(d.Name()) ||
			util.IsHidden(d.Name()) {
			return nil
		}

		f, err := fsys.Open(p)
		if err != nil {
			return err
		}

		data, err := io.ReadAll(f)
		if err != nil {
			return err
		}

		var y interface{}
		if err := yaml.Unmarshal(data, &y); err != nil {
			return err
		}

		return s.Validate(y)
	}); err != nil {
		return fmt.Errorf("failed to walk policy directory: %w", err)
	}

	return nil
}

// ValidateTests validates the tests in the fsys with the given schema.
func ValidateTests(ctx context.Context, fsys fs.FS) error {
	s, err := jsonschema.CompileString("TestSuite.schema.json", string(schema.TestSuiteJSONSchema))
	if err != nil {
		return fmt.Errorf("failed to compile test schema: %w", err)
	}

	if err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err != nil {
			return err
		}

		if d.IsDir() {
			if d.Name() == util.TestDataDirectory {
				return fs.SkipDir
			}

			return nil
		}

		if util.IsSupportedTestFile(p) {
			f, err := fsys.Open(p)
			if err != nil {
				return err
			}

			data, err := io.ReadAll(f)
			if err != nil {
				return err
			}

			var y interface{}
			if err := yaml.Unmarshal(data, &y); err != nil {
				return err
			}

			if err := s.Validate(y); err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to walk test directory: %w", err)
	}

	return nil
}
