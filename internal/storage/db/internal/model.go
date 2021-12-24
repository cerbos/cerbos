// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

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
	PolicyTblDefinitionCol = "definition"
	PolicyTblDisabledCol   = "disabled"

	PolicyDepTbl            = "policy_dependency"
	PolicyDepTblPolicyIDCol = "policy_id"
	PolicyDepTblDepIDCol    = "dependency_id"

	SchemaTbl              = "attr_schema_defs"
	SchemaTblIDCol         = "id"
	SchemaTblDefinitionCol = "definition"
)

type Schema struct {
	Definition *pgtype.JSON
	ID         string
}

type Policy struct {
	Definition  PolicyDefWrapper
	Kind        string
	Name        string
	Version     string
	Description string
	ID          namer.ModuleID
	Disabled    bool
}

type PolicyDependency struct {
	PolicyID     namer.ModuleID `db:"policy_id"`
	DependencyID namer.ModuleID `db:"dependency_id"`
}

type PolicyDefWrapper struct {
	*policyv1.Policy
}

func (pdw PolicyDefWrapper) Value() (driver.Value, error) {
	return pdw.Policy.MarshalVT()
}

func (pdw *PolicyDefWrapper) Scan(src interface{}) error {
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
	if err := pdw.Policy.UnmarshalVT(source); err != nil {
		return fmt.Errorf("failed to unmarshal policy definition: %w", err)
	}

	return nil
}

type PolicyRevision struct {
	Timestamp   time.Time `db:"update_timestamp"`
	Definition  PolicyDefWrapper
	Action      string
	Version     string
	Description string
	Kind        string
	Name        string
	ID          namer.ModuleID
	RevisionID  int64 `db:"revision_id"`
	Disabled    bool
}
