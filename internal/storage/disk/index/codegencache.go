// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"fmt"
	"os"

	"github.com/spf13/afero"
	"go.uber.org/multierr"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/codegen"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
)

const codegenCacheDir = "cerbos_codegen"

type codegenCache struct {
	parentFS afero.Fs
	fs       afero.Fs
}

func newCodegenCache(fsys afero.Fs) (*codegenCache, error) {
	if fsys == nil {
		fsys = afero.NewBasePathFs(afero.NewOsFs(), os.TempDir())
	}

	if err := fsys.MkdirAll(codegenCacheDir, 0o744); err != nil { //nolint:gomnd
		return nil, fmt.Errorf("failed to create work directory: %w", err)
	}

	return &codegenCache{parentFS: fsys, fs: afero.NewBasePathFs(fsys, codegenCacheDir)}, nil
}

func (cc *codegenCache) put(p policy.Wrapper) error {
	genPol, err := codegen.GenerateRepr(p.Policy)
	if err != nil {
		return err
	}

	f, err := cc.fs.Create(p.ID.String())
	if err != nil {
		return fmt.Errorf("failed to create codegen file: %w", err)
	}

	defer multierr.AppendInvoke(&err, multierr.Close(f))

	return policy.WriteGeneratedPolicy(f, genPol)
}

func (cc *codegenCache) get(id namer.ModuleID) (*policyv1.GeneratedPolicy, error) {
	f, err := cc.fs.Open(id.String())
	if err != nil {
		return nil, err
	}

	defer f.Close()

	return policy.ReadGeneratedPolicy(f)
}

func (cc *codegenCache) delete(id namer.ModuleID) error {
	return cc.fs.Remove(id.String())
}

func (cc *codegenCache) clear() error {
	return cc.parentFS.RemoveAll(codegenCacheDir)
}
