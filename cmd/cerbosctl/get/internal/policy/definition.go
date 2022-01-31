// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import "github.com/cerbos/cerbos/internal/policy"

type KeyPolicyPair struct {
	Key    string
	Policy policy.Wrapper
}

type ResourceType uint

const (
	Unspecified ResourceType = iota
	DerivedRoles
	PrincipalPolicy
	ResourcePolicy
)
