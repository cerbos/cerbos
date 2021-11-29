// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"database/sql/driver"
	"fmt"
	"google.golang.org/protobuf/encoding/protojson"
	"time"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
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

	SchemaTbl              = "schema"
	SchemaTblIDCol         = "id"
	SchemaTblDefinitionCol = "definition"
	SchemaDefaultID        = 1
)

type Schema struct {
	ID          uint64
	Description string
	Disabled    bool
	Definition  SchemaDefWrapper
}

type SchemaDefWrapper struct {
	*schemav1.Schema
}

func (sdw SchemaDefWrapper) Value() (driver.Value, error) {
	return protojson.Marshal(sdw.Schema)
}

func (sdw *SchemaDefWrapper) Scan(src interface{}) error {
	var source []byte
	switch t := src.(type) {
	case nil:
		return nil
	case string:
		source = []byte(t)
	case []byte:
		source = t
	default:
		return fmt.Errorf("unexpected type for schema definition: %T", src)
	}

	sdw.Schema = &schemav1.Schema{}
	if err := protojson.Unmarshal(source, sdw.Schema); err != nil {
		return fmt.Errorf("failed to unmarshal schema definition: %w", err)
	}

	return nil
}

type Policy struct {
	ID          namer.ModuleID
	Kind        string
	Name        string
	Version     string
	Description string
	Disabled    bool
	Definition  PolicyDefWrapper
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
	RevisionID  int64 `db:"revision_id"`
	ID          namer.ModuleID
	Kind        string
	Name        string
	Version     string
	Description string
	Action      string
	Disabled    bool
	Definition  PolicyDefWrapper
	Timestamp   time.Time `db:"update_timestamp"`
}
