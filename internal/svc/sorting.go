// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

type sortType uint8

const (
	byName sortType = iota
	byVersion
)

type alphabetical struct {
	sortType sortType
	reverse  bool
	items    []*policyv1.Policy
}

// Len is the interface implementation for alphabetical sorting function
func (s *alphabetical) Len() int { return len(s.items) }

// Swap is the interface implementation for alphabetical sorting function
func (s *alphabetical) Swap(i, j int) { s.items[i], s.items[j] = s.items[j], s.items[i] }

// Less is the interface implementation for alphabetical sorting function
func (s *alphabetical) Less(i, j int) bool {
	switch s.sortType {
	case byName:
		return !s.reverse == (getPolicyName(s.items[i]) < getPolicyName(s.items[j]))
	case byVersion:
		return !s.reverse == (getPolicyVersion(s.items[i]) < getPolicyVersion(s.items[j]))
	default:
		return false
	}
}

func getPolicyName(p *policyv1.Policy) string {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return pt.ResourcePolicy.Resource
	case *policyv1.Policy_PrincipalPolicy:
		return pt.PrincipalPolicy.Principal
	case *policyv1.Policy_DerivedRoles:
		return pt.DerivedRoles.Name
	default:
		return "-"
	}
}

func getPolicyVersion(p *policyv1.Policy) string {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return pt.ResourcePolicy.Version
	case *policyv1.Policy_PrincipalPolicy:
		return pt.PrincipalPolicy.Version
	default:
		return "-"
	}
}
