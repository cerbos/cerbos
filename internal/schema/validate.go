// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
)

func Validate(s *schemav1.Schema) error {
	if err := s.Validate(); err != nil {
		return err
	}

	return nil
}
