// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/namer"
)

// Wrapper is a convenience layer over the schema definition.
type Wrapper struct {
	ID            namer.ModuleID
	Name          string
	FQN           string
	SchemaVersion string
	*schemav1.Schema
}

func Wrap(s *schemav1.Schema, fileName string) Wrapper {
	fqn := namer.SchemaFQN(fileName, s.SchemaVersion)
	w := Wrapper{
		ID:            namer.GenModuleIDFromFQN(fqn),
		Name:          fileName,
		FQN:           fqn,
		SchemaVersion: s.SchemaVersion,
		Schema:        s,
	}

	return w
}
