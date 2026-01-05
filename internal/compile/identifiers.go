// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"fmt"
	"regexp"
)

// https://github.com/google/cel-spec/blob/v0.25.1/doc/langdef.md#syntax

var (
	keywords = map[string]struct{}{
		"false": {},
		"in":    {},
		"null":  {},
		"true":  {},
	}

	identifierPattern = regexp.MustCompile(`^[_a-zA-Z][_a-zA-Z0-9]*$`)
)

func ValidateIdentifier(identifier string) error {
	if _, ok := keywords[identifier]; ok {
		return fmt.Errorf("%q is a reserved keyword and can't be used as an identifier", identifier)
	}

	if !identifierPattern.MatchString(identifier) {
		return fmt.Errorf("%q is not a valid identifier", identifier)
	}

	return nil
}
