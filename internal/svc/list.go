// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"fmt"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/schema"
	"regexp"
	"sort"
	"strings"

	"github.com/PaesslerAG/jsonpath"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	"github.com/cerbos/cerbos/internal/policy"
)

func filterPolicies(filters []*requestv1.ListPoliciesRequest_Filter, policies []*policy.Wrapper) ([]*policyv1.Policy, error) {
	if len(filters) == 0 {
		ps := make([]*policyv1.Policy, 0, len(policies))
		for _, unit := range policies {
			ps = append(ps, unit.Policy)
		}

		return ps, nil
	}
	pMap := make(map[int]*policyv1.Policy)
	for i, unit := range policies {
		pMap[i] = unit.Policy
	}

	sMap := make(map[int]map[string]interface{})
	rMap := make(map[string]*regexp.Regexp)
	for _, filter := range filters {
		for i := range pMap {
			if _, ok := sMap[i]; !ok {
				v, err := protoMessageToStringMap(pMap[i])
				if err != nil {
					return nil, status.Error(codes.Internal, fmt.Sprintf("could not parse policy: %s", err))
				}
				sMap[i] = v
			}

			val, err := jsonpath.Get(filter.FieldPath, sMap[i])
			if err != nil {
				// the lib throws an error if the key is not found, we continue here.
				// but we need to return errors for the cases like syntax errors
				if strings.HasPrefix(err.Error(), "unknown key") {
					delete(pMap, i)
					continue
				}
				return nil, status.Error(codes.Internal, fmt.Sprintf("could not query policy: %s", err))
			}
			value := getStringValue(val)

			switch filter.Type {
			case requestv1.ListPoliciesRequest_MATCH_TYPE_EXACT:
				if value == filter.Value {
					continue
				}
				delete(pMap, i)
			case requestv1.ListPoliciesRequest_MATCH_TYPE_WILDCARD:
				exp := filter.Value
				if _, ok := rMap[exp]; !ok {
					r, err := regexp.Compile(exp)
					if err != nil {
						return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("could not compile regex: %s", err))
					}
					rMap[exp] = r
				}

				if rMap[exp].MatchString(value) {
					continue
				}
				delete(pMap, i)
			default:
				return nil, status.Error(codes.InvalidArgument, "invalid filter type")
			}
		}
	}

	ps := make([]*policyv1.Policy, 0, len(pMap))
	for _, p := range pMap {
		ps = append(ps, p)
	}

	return ps, nil
}

func filterSchemas(filters []*requestv1.ListSchemasRequest_Filter, schemas []*schema.Wrapper) ([]*schemav1.Schema, error) {
	if len(filters) == 0 {
		ss := make([]*schemav1.Schema, 0, len(schemas))
		for _, unit := range schemas {
			ss = append(ss, unit.Schema)
		}

		return ss, nil
	}
	schMap := make(map[int]*schemav1.Schema)
	for i, unit := range schemas {
		schMap[i] = unit.Schema
	}

	sMap := make(map[int]map[string]interface{})
	rMap := make(map[string]*regexp.Regexp)
	for _, filter := range filters {
		for i := range schMap {
			if _, ok := sMap[i]; !ok {
				v, err := protoMessageToStringMap(schMap[i])
				if err != nil {
					return nil, status.Error(codes.Internal, fmt.Sprintf("could not parse schema: %s", err))
				}
				sMap[i] = v
			}

			val, err := jsonpath.Get(filter.FieldPath, sMap[i])
			if err != nil {
				// the lib throws an error if the key is not found, we continue here.
				// but we need to return errors for the cases like syntax errors
				if strings.HasPrefix(err.Error(), "unknown key") {
					delete(schMap, i)
					continue
				}
				return nil, status.Error(codes.Internal, fmt.Sprintf("could not query schema: %s", err))
			}
			value := getStringValue(val)

			switch filter.Type {
			case requestv1.ListSchemasRequest_MATCH_TYPE_EXACT:
				if value == filter.Value {
					continue
				}
				delete(schMap, i)
			case requestv1.ListSchemasRequest_MATCH_TYPE_WILDCARD:
				exp := filter.Value
				if _, ok := rMap[exp]; !ok {
					r, err := regexp.Compile(exp)
					if err != nil {
						return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("could not compile regex: %s", err))
					}
					rMap[exp] = r
				}

				if rMap[exp].MatchString(value) {
					continue
				}
				delete(schMap, i)
			default:
				return nil, status.Error(codes.InvalidArgument, "invalid filter type")
			}
		}
	}

	ss := make([]*schemav1.Schema, 0, len(schMap))
	for _, s := range schMap {
		ss = append(ss, s)
	}

	return ss, nil
}

func sortPolicies(sortOptions *requestv1.ListPoliciesRequest_SortOptions, policies []*policyv1.Policy) {
	if sortOptions == nil {
		return
	}

	var data sort.Interface

	switch sortOptions.Column {
	case requestv1.ListPoliciesRequest_SortOptions_COLUMN_VERSION:
		data = versionOrder(policies)
	default:
		data = nameOrder(policies)
	}

	if sortOptions.Order == requestv1.ListPoliciesRequest_SortOptions_ORDER_DESCENDING {
		sort.Sort(sort.Reverse(data))
	} else {
		sort.Sort(data)
	}
}

func sortSchemas(sortOptions *requestv1.ListSchemasRequest_SortOptions, schemas []*schemav1.Schema) {
	if sortOptions == nil {
		return
	}

	var data sort.Interface

	switch sortOptions.Column {
	case requestv1.ListSchemasRequest_SortOptions_COLUMN_VERSION:
		data = versionOrderSchema(schemas)
	default:
		data = nameOrderSchema(schemas)
	}

	if sortOptions.Order == requestv1.ListSchemasRequest_SortOptions_ORDER_DESCENDING {
		sort.Sort(sort.Reverse(data))
	} else {
		sort.Sort(data)
	}
}

type nameOrder []*policyv1.Policy

func (s nameOrder) Len() int { return len(s) }

func (s nameOrder) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s nameOrder) Less(i, j int) bool {
	in, jn := getPolicyName(s[i]), getPolicyName(s[j])
	if in == jn {
		return getPolicyVersion(s[i]) < getPolicyVersion(s[j])
	}

	return in < jn
}

type versionOrder []*policyv1.Policy

func (s versionOrder) Len() int { return len(s) }

func (s versionOrder) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s versionOrder) Less(i, j int) bool {
	iv, jv := getPolicyVersion(s[i]), getPolicyVersion(s[j])
	if iv == jv {
		return getPolicyName(s[i]) < getPolicyName(s[j])
	}

	return iv < jv
}

type nameOrderSchema []*schemav1.Schema

func (s nameOrderSchema) Len() int { return len(s) }

func (s nameOrderSchema) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s nameOrderSchema) Less(i, j int) bool {
	in, jn := getSchemaName(s[i]), getSchemaName(s[j])
	if in == jn {
		return getSchemaVersion(s[i]) < getSchemaVersion(s[j])
	}

	return in < jn
}

type versionOrderSchema []*schemav1.Schema

func (s versionOrderSchema) Len() int { return len(s) }

func (s versionOrderSchema) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s versionOrderSchema) Less(i, j int) bool {
	iv, jv := getSchemaVersion(s[i]), getSchemaVersion(s[j])
	if iv == jv {
		return getSchemaName(s[i]) < getSchemaName(s[j])
	}

	return iv < jv
}

func getPolicyName(p *policyv1.Policy) string {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return pt.ResourcePolicy.Resource
	case *policyv1.Policy_PrincipalPolicy:
		return pt.PrincipalPolicy.Principal
	case *policyv1.Policy_DerivedRoles:
		return pt.DerivedRoles.Name
	default:
		return "-"
	}
}

func getPolicyVersion(p *policyv1.Policy) string {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return pt.ResourcePolicy.Version
	case *policyv1.Policy_PrincipalPolicy:
		return pt.PrincipalPolicy.Version
	default:
		return "-"
	}
}

func getSchemaName(s *schemav1.Schema) string {
	return s.Name
}

func getSchemaVersion(s *schemav1.Schema) string {
	return s.SchemaVersion
}
