// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package scopeperms tracks the scopePermissions setting of every resource and principal
// policy present in a scope and detects disagreements between them. All resource and
// principal policies that share a scope must use the same setting, and the tracker is the
// single implementation of that rule for every policy source.
package scopeperms

import (
	"fmt"
	"sort"
	"strings"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

// PolicySetting is the (normalised) scope permissions setting of one policy.
type PolicySetting struct {
	PolicyKey   string
	Permissions policyv1.ScopePermissions
}

// Conflict describes a scope whose policies disagree on their scope permissions.
type Conflict struct {
	Scope          string
	PolicySettings []PolicySetting // sorted by policy key
}

func (c Conflict) String() string {
	parts := make([]string, len(c.PolicySettings))
	for i, p := range c.PolicySettings {
		parts[i] = fmt.Sprintf("%s=%s", p.PolicyKey, p.Permissions)
	}

	return fmt.Sprintf("scope %q: [%s]", c.Scope, strings.Join(parts, ", "))
}

// ConflictsError is returned when one or more scopes have conflicting scope permissions.
type ConflictsError struct {
	Conflicts []Conflict
}

func (e *ConflictsError) Error() string {
	parts := make([]string, len(e.Conflicts))
	for i, c := range e.Conflicts {
		parts[i] = c.String()
	}

	return "policies sharing a scope have conflicting scopePermissions: " + strings.Join(parts, "; ")
}

// Normalise maps the unspecified setting to the documented default.
func Normalise(sp policyv1.ScopePermissions) policyv1.ScopePermissions {
	if sp == policyv1.ScopePermissions_SCOPE_PERMISSIONS_UNSPECIFIED {
		return policyv1.ScopePermissions_SCOPE_PERMISSIONS_OVERRIDE_PARENT
	}

	return sp
}

func Constrained(kind policyv1.Kind) bool {
	return kind == policyv1.Kind_KIND_RESOURCE || kind == policyv1.Kind_KIND_PRINCIPAL
}

// Tracker records the scope permissions of policies grouped by scope. It is not safe for concurrent use.
type Tracker struct {
	scopes   map[string]map[string]policyv1.ScopePermissions // scope -> policy key -> setting
	policies map[string]string                               // policy key -> scope
}

func NewTracker() *Tracker {
	return &Tracker{
		scopes:   make(map[string]map[string]policyv1.ScopePermissions),
		policies: make(map[string]string),
	}
}

// Add records the setting of a policy. Adding the same policy again replaces its setting.
func (t *Tracker) Add(kind policyv1.Kind, policyKey, scope string, sp policyv1.ScopePermissions) {
	if !Constrained(kind) {
		return
	}

	t.Remove(policyKey)

	settings, ok := t.scopes[scope]
	if !ok {
		settings = make(map[string]policyv1.ScopePermissions)
		t.scopes[scope] = settings
	}

	settings[policyKey] = Normalise(sp)
	t.policies[policyKey] = scope
}

func (t *Tracker) Remove(policyKey string) {
	scope, ok := t.policies[policyKey]
	if !ok {
		return
	}

	delete(t.policies, policyKey)
	if settings, ok := t.scopes[scope]; ok {
		delete(settings, policyKey)
		if len(settings) == 0 {
			delete(t.scopes, scope)
		}
	}
}

// Check reports the conflict that adding the given policy would create, without recording it. It returns nil when
// there is none. The policy identified by ignoredPolicyKey (for example, one about to be removed) is not considered.
func (t *Tracker) Check(kind policyv1.Kind, policyKey, scope string, sp policyv1.ScopePermissions, ignoredPolicyKey string) *Conflict {
	if !Constrained(kind) {
		return nil
	}

	want := Normalise(sp)
	var others []PolicySetting
	for key, have := range t.scopes[scope] {
		if key == policyKey || key == ignoredPolicyKey || have == want {
			continue
		}
		others = append(others, PolicySetting{PolicyKey: key, Permissions: have})
	}

	if len(others) == 0 {
		return nil
	}

	others = append(others, PolicySetting{PolicyKey: policyKey, Permissions: want})
	sortSettings(others)

	return &Conflict{Scope: scope, PolicySettings: others}
}

// Permissions returns the setting shared by the policies in the scope. It returns the unspecified
// value when the scope is unknown or its policies disagree.
func (t *Tracker) Permissions(scope string) policyv1.ScopePermissions {
	result := policyv1.ScopePermissions_SCOPE_PERMISSIONS_UNSPECIFIED
	for _, sp := range t.scopes[scope] {
		if result != policyv1.ScopePermissions_SCOPE_PERMISSIONS_UNSPECIFIED && result != sp {
			return policyv1.ScopePermissions_SCOPE_PERMISSIONS_UNSPECIFIED
		}
		result = sp
	}

	return result
}

// Conflicts returns every scope whose policies disagree, sorted by scope.
func (t *Tracker) Conflicts() []Conflict {
	var conflicts []Conflict
	for scope, settings := range t.scopes {
		if !disagree(settings) {
			continue
		}

		c := Conflict{Scope: scope, PolicySettings: make([]PolicySetting, 0, len(settings))}
		for key, sp := range settings {
			c.PolicySettings = append(c.PolicySettings, PolicySetting{PolicyKey: key, Permissions: sp})
		}
		sortSettings(c.PolicySettings)
		conflicts = append(conflicts, c)
	}

	sort.Slice(conflicts, func(i, j int) bool { return conflicts[i].Scope < conflicts[j].Scope })

	return conflicts
}

// Err returns a ConflictsError if there are any conflicts and nil otherwise.
func (t *Tracker) Err() error {
	conflicts := t.Conflicts()
	if len(conflicts) == 0 {
		return nil
	}

	return &ConflictsError{Conflicts: conflicts}
}

func disagree(settings map[string]policyv1.ScopePermissions) bool {
	var first policyv1.ScopePermissions
	for _, sp := range settings {
		if first == policyv1.ScopePermissions_SCOPE_PERMISSIONS_UNSPECIFIED {
			first = sp
		} else if sp != first {
			return true
		}
	}

	return false
}

func sortSettings(s []PolicySetting) {
	sort.Slice(s, func(i, j int) bool { return s[i].PolicyKey < s[j].PolicyKey })
}
