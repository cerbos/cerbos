// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"strings"

	"github.com/cerbos/cerbos/internal/policy"
)

type filterDef struct {
	names           map[string]struct{}
	versions        map[string]struct{}
	kind            policy.Kind
	includeDisabled bool
}

func newFilterDef(kind policy.Kind, names, versions []string, includeDisabled bool) *filterDef {
	f := &filterDef{
		kind:            kind,
		includeDisabled: includeDisabled,
	}
	if len(names) > 0 {
		f.names = make(map[string]struct{}, len(names))
		for _, n := range names {
			f.names[strings.ToLower(n)] = struct{}{}
		}
	}

	if len(versions) > 0 {
		f.versions = make(map[string]struct{}, len(versions))
		for _, v := range versions {
			f.versions[strings.ToLower(v)] = struct{}{}
		}
	}

	return f
}

func (fd *filterDef) filter(p policy.Wrapper) bool {
	if !fd.includeDisabled && p.Disabled {
		return false
	}

	if p.Kind != fd.kind {
		return false
	}

	if len(fd.names) > 0 {
		if _, ok := fd.names[strings.ToLower(p.Name)]; !ok {
			return false
		}
	}

	if len(fd.versions) > 0 {
		if _, ok := fd.versions[strings.ToLower(p.Version)]; !ok {
			return false
		}
	}

	return true
}
