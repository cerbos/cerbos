// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package internal

import (
	"database/sql/driver"
	"fmt"
	"time"

	"github.com/jackc/pgtype"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
)

const (
	PolicyTbl              = "policy"
	PolicyTblIDCol         = "id"
	PolicyTblKindCol       = "kind"
	PolicyTblNameCol       = "name"
	PolicyTblVerCol        = "version"
	PolicyTblScopeCol      = "scope"
	PolicyTblDescCol       = "description"
	PolicyTblDefinitionCol = "definition"
	PolicyTblDisabledCol   = "disabled"

	PolicyDepTbl            = "policy_dependency"
	PolicyDepTblPolicyIDCol = "policy_id"
	PolicyDepTblDepIDCol    = "dependency_id"

	PolicyAncestorTbl              = "policy_ancestor"
	PolicyAncestorTblPolicyIDCol   = "policy_id"
	PolicyAncestorTblAncestorIDCol = "ancestor_id"

	PolicyRevisionTbl              = "policy_revision"
	PolicyRevisionTblRevisionIDCol = "revision_id"

	SchemaTbl              = "attr_schema_defs"
	SchemaTblIDCol         = "id"
	SchemaTblDefinitionCol = "definition"
)

var requiredTables = []string{PolicyTbl, PolicyDepTbl, PolicyAncestorTbl, PolicyRevisionTbl, SchemaTbl}

type Schema struct {
	Definition *pgtype.JSON
	ID         string
}

type Policy struct {
	Definition  PolicyDefWrapper
	Kind        string
	Name        string
	Version     string
	Scope       string
	Description string
	ID          namer.ModuleID
	Disabled    bool
}

type PolicyDependency struct {
	PolicyID     namer.ModuleID `db:"policy_id"`
	DependencyID namer.ModuleID `db:"dependency_id"`
}

type PolicyAncestor struct {
	PolicyID   namer.ModuleID `db:"policy_id"`
	AncestorID namer.ModuleID `db:"ancestor_id"`
}

type PolicyDefWrapper struct {
	*policyv1.Policy
}

func (pdw PolicyDefWrapper) Value() (driver.Value, error) {
	return pdw.MarshalVT()
}

func (pdw *PolicyDefWrapper) Scan(src any) error {
	var source []byte
	switch t := src.(type) {
	case nil:
		return nil
	case string:
		source = []byte(t)
	case []byte:
		source = t
	default:
		return fmt.Errorf("unexpected type for policy definition: %T", src)
	}

	pdw.Policy = &policyv1.Policy{}
	if err := pdw.UnmarshalVT(source); err != nil {
		return fmt.Errorf("failed to unmarshal policy definition: %w", err)
	}

	return nil
}

type PolicyRevision struct {
	Timestamp   time.Time `db:"update_timestamp"`
	Definition  PolicyDefWrapper
	Action      string
	Version     string
	Scope       string
	Description string
	Kind        string
	Name        string
	ID          namer.ModuleID
	RevisionID  int64 `db:"revision_id"`
	Disabled    bool
}

type PolicyCount struct {
	Kind  string
	Count int
}
