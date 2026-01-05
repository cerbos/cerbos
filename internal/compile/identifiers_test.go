// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile_test

import (
	"testing"

	"github.com/cerbos/cerbos/internal/compile"
	"github.com/stretchr/testify/assert"
)

func TestValidateIdentifiers(t *testing.T) {
	valid := []string{
		"_",
		"_0",
		"_x",
		"foo",
		"foo_bar",
		"foo42bar",
		"fooBar",
		"no",
		"x_",
		"x0",
		"yes",
	}

	for _, identifier := range valid {
		assert.NoError(t, compile.ValidateIdentifier(identifier), "Expected %q to be valid", identifier)
	}

	invalid := []string{
		"",
		"0",
		"123",
		"false",
		"foo?",
		"in",
		"null",
		"true",
	}

	for _, identifier := range invalid {
		assert.Error(t, compile.ValidateIdentifier(identifier), "Expected %q to be invalid", identifier)
	}
}
