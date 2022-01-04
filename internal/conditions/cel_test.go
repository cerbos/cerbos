// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResourceAttributeNames(t *testing.T) {
	name := "a"
	fqns := ResourceAttributeNames(name)
	require.Equal(t, []string{"R.attr.a", "request.resource.attr.a"}, fqns)
}
