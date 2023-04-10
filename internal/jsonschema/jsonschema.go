// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package jsonschema

import (
	"context"
	"io"
	"io/fs"
	"path"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"

	internalschema "github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/util"
)

// ValidatePolicies validates the policies in the fsys with the given schema.
func ValidatePolicies(ctx context.Context, s *jsonschema.Schema, fsys fs.FS) error {
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
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
	})
	return err
}

// ValidateTests validates the tests in the fsys with the given schema.
func ValidateTests(ctx context.Context, s *jsonschema.Schema, fsys fs.FS) error {
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err != nil {
			return err
		}

		if d.IsDir() && d.Name() == util.TestDataDirectory {
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
	})
	return err
}
