// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"fmt"
	"io"
	"io/fs"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	sourcev1 "github.com/cerbos/cerbos/api/genpb/cerbos/source/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
)

type ReadError struct {
	Errors []*sourcev1.Error
}

func (ReadError) Error() string {
	return "failed to parse"
}

func Wrap(p *policyv1.Policy) *sourcev1.PolicyWrapper {
	return policy.Wrap(p).ToProto()
}

func ReadFromFile(fsys fs.FS, path string) (*policyv1.Policy, error) {
	return policy.ReadPolicyFromFile(fsys, path)
}

func Read(src io.Reader) (*policyv1.Policy, error) {
	p, sc, err := policy.ReadPolicyWithSourceContextFromReader(src)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy: %w", err)
	}

	if errs := sc.GetErrors(); len(errs) > 0 {
		return nil, ReadError{Errors: errs}
	}

	if err := policy.Validate(p, sc); err != nil {
		var verr policy.ValidationError
		if errors.As(err, &verr) {
			return nil, ReadError{Errors: []*sourcev1.Error{verr.Err}}
		}

		return nil, fmt.Errorf("failed to validate policy: %w", err)
	}

	return p, nil
}

func IDFromPolicyKey(key string) uint64 {
	return namer.GenModuleIDFromFQN(namer.FQNFromPolicyKey(key)).RawValue()
}
