// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"io/fs"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	sourcev1 "github.com/cerbos/cerbos/api/genpb/cerbos/source/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
)

func Wrap(p *policyv1.Policy) *sourcev1.PolicyWrapper {
	return policy.Wrap(p).ToProto()
}

func ReadFromFile(fsys fs.FS, path string) (*policyv1.Policy, error) {
	return policy.ReadPolicyFromFile(fsys, path)
}

func IDFromPolicyKey(key string) uint64 {
	return namer.GenModuleIDFromFQN(namer.FQNFromPolicyKey(key)).RawValue()
}
