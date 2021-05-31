// Copyright 2021 Zenauth Ltd.

package internal

import (
	"database/sql/driver"
	"fmt"

	"google.golang.org/protobuf/proto"

	policyv1 "github.com/cerbos/cerbos/internal/genpb/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
)

const (
	PolicyTbl              = "policy"
	PolicyTblIDCol         = "id"
	PolicyTblDefinitionCol = "definition"
	PolicyTblDisabledCol   = "disabled"
	PolicyTblGeneratedCol  = "generated"

	PolicyDepTbl            = "policy_dependency"
	PolicyDepTblPolicyIDCol = "policy_id"
	PolicyDepTblDepIDCol    = "dependency_id"
)

type Policy struct {
	ID          namer.ModuleID
	Kind        string
	Name        string
	Version     string
	Description string
	Disabled    bool
	Definition  PolicyDefWrapper
	Generated   GeneratedPolicyWrapper
}

type PolicyDependency struct {
	PolicyID     namer.ModuleID `db:"policy_id"`
	DependencyID namer.ModuleID `db:"dependency_id"`
}

type PolicyDefWrapper struct {
	*policyv1.Policy
}

func (pdw PolicyDefWrapper) Value() (driver.Value, error) {
	return proto.Marshal(pdw.Policy)
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
	if err := proto.Unmarshal(source, pdw.Policy); err != nil {
		return fmt.Errorf("failed to unmarshal policy definition: %w", err)
	}

	return nil
}

type GeneratedPolicyWrapper struct {
	*policyv1.GeneratedPolicy
}

func (gpw GeneratedPolicyWrapper) Value() (driver.Value, error) {
	return proto.Marshal(gpw.GeneratedPolicy)
}

func (gpw *GeneratedPolicyWrapper) Scan(src interface{}) error {
	var source []byte
	switch t := src.(type) {
	case nil:
		return nil
	case string:
		source = []byte(t)
	case []byte:
		source = t
	default:
		return fmt.Errorf("unexpected type for generated policy: %T", src)
	}

	gpw.GeneratedPolicy = &policyv1.GeneratedPolicy{}
	if err := proto.Unmarshal(source, gpw.GeneratedPolicy); err != nil {
		return fmt.Errorf("failed to unmarshal generated policy: %w", err)
	}

	return nil
}
