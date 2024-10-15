// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

func checkGroupDefinitions[G any](groups map[string]G, members func(G) []string, exists func(string) bool) (map[string][]string, error) {
	resolved := make(map[string][]string, len(groups))

	for groupName, groupDef := range groups {
		fixtureNames := members(groupDef)

		for _, fixtureName := range fixtureNames {
			if !exists(fixtureName) {
				return nil, fmt.Errorf("missing fixture %q referenced in group %q", fixtureName, groupName)
			}
		}

		resolved[groupName] = fixtureNames
	}

	return resolved, nil
}

func principalGroupMembers(group *policyv1.TestFixtureGroup_Principals) []string {
	return group.Principals
}

func resourceGroupMembers(group *policyv1.TestFixtureGroup_Resources) []string {
	return group.Resources
}

func existsInMap[F any](fixtures map[string]F) func(string) bool {
	return func(name string) bool {
		_, ok := fixtures[name]
		return ok
	}
}

func existsFromLookup[F any](lookup func(string) (F, error)) func(string) bool {
	return func(name string) bool {
		_, err := lookup(name)
		return err == nil
	}
}
