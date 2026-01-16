// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"
	"strings"
)

// FilterDimension represents the valid filter dimensions for test filtering.
type FilterDimension string

const (
	FilterDimensionTest      FilterDimension = "test"
	FilterDimensionPrincipal FilterDimension = "principal"
	FilterDimensionResource  FilterDimension = "resource"
	FilterDimensionAction    FilterDimension = "action"

	expectedKeyValueParts = 2
)

var validDimensions = map[FilterDimension]struct{}{
	FilterDimensionTest:      {},
	FilterDimensionPrincipal: {},
	FilterDimensionResource:  {},
	FilterDimensionAction:    {},
}

// FilterConfig holds the parsed test filter configuration.
// Each dimension contains a list of glob patterns that must match for a test to be included.
type FilterConfig struct {
	Test      []string
	Principal []string
	Resource  []string
	Action    []string
}

func (fc *FilterConfig) IsEmpty() bool {
	return len(fc.Test) == 0 && len(fc.Principal) == 0 && len(fc.Resource) == 0 && len(fc.Action) == 0
}

func toFilterDimension(s string) FilterDimension {
	return FilterDimension(strings.TrimSpace(strings.ToLower(s)))
}

func parseDimension(s string) (FilterDimension, []string, error) {
	parts := strings.SplitN(s, "=", expectedKeyValueParts)
	if len(parts) != expectedKeyValueParts {
		return "", nil, fmt.Errorf("invalid filter dimension format %q: expected 'dimension=glob1,glob2'", s)
	}
	name := toFilterDimension(parts[0])
	if _, ok := validDimensions[name]; !ok {
		return "", nil, fmt.Errorf("unknown filter dimension %q: valid dimensions are test, principal, resource, action", parts[0])
	}
	globs := parseGlobs(parts[1])

	return name, globs, nil
}

// ParseFilterConfig parses a filter string in the format:
// "test=glob1,glob2;principal=glob3;resource=glob4;action=glob5"
func ParseFilterConfig(filter string) (*FilterConfig, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return &FilterConfig{}, nil
	}

	fc := &FilterConfig{}

	for dimension := range strings.SplitSeq(filter, ";") {
		dimension = strings.TrimSpace(dimension)
		if dimension == "" {
			continue
		}
		name, globs, err := parseDimension(dimension)
		if err != nil {
			return nil, err
		}
		if len(globs) == 0 {
			continue
		}

		switch name {
		case FilterDimensionTest:
			fc.Test = append(fc.Test, globs...)
		case FilterDimensionPrincipal:
			fc.Principal = append(fc.Principal, globs...)
		case FilterDimensionResource:
			fc.Resource = append(fc.Resource, globs...)
		case FilterDimensionAction:
			fc.Action = append(fc.Action, globs...)
		}
	}

	if fc.IsEmpty() {
		return nil, fmt.Errorf("filter must contain at least one glob pattern in at least one dimension")
	}

	return fc, nil
}

func parseGlobs(s string) []string {
	var globs []string
	for g := range strings.SplitSeq(s, ",") {
		g = strings.TrimSpace(g)
		if g != "" {
			globs = append(globs, g)
		}
	}
	return globs
}

func (fc *FilterConfig) Merge(other *FilterConfig) *FilterConfig {
	if other == nil {
		return fc
	}
	if fc == nil {
		return other
	}
	return &FilterConfig{
		Test:      append(fc.Test, other.Test...),
		Principal: append(fc.Principal, other.Principal...),
		Resource:  append(fc.Resource, other.Resource...),
		Action:    append(fc.Action, other.Action...),
	}
}
