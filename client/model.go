// Copyright 2021 Zenauth Ltd.

package client

import (
	"fmt"
	"reflect"

	"go.uber.org/multierr"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
)

// Principal is a container for principal data.
type Principal struct {
	*enginev1.Principal
	err error
}

// NewPrincipal creates a new principal object with the given ID and roles.
func NewPrincipal(id string, roles ...string) *Principal {
	return &Principal{
		Principal: &enginev1.Principal{
			Id:    id,
			Roles: roles,
		},
	}
}

// WithPolicyVersion sets the policy version for this principal.
func (p *Principal) WithPolicyVersion(policyVersion string) *Principal {
	p.PolicyVersion = policyVersion
	return p
}

// WithRoles appends the set of roles to principal's existing roles.
func (p *Principal) WithRoles(roles ...string) *Principal {
	p.Roles = append(p.Roles, roles...)
	return p
}

// WithAttributes merges the given attributes to principal's existing attributes.
func (p *Principal) WithAttributes(attr map[string]interface{}) *Principal {
	if p.Attr == nil {
		p.Attr = make(map[string]*structpb.Value, len(attr))
	}

	for k, v := range attr {
		pbVal, err := toStructPB(v)
		if err != nil {
			p.err = multierr.Append(p.err, fmt.Errorf("invalid attribute value for '%s': %w", k, err))
			continue
		}
		p.Attr[k] = pbVal
	}

	return p
}

// WithAttr adds a new attribute to the principal.
// It will overwrite any existing attribute having the same key.
func (p *Principal) WithAttr(key string, value interface{}) *Principal {
	if p.Attr == nil {
		p.Attr = make(map[string]*structpb.Value)
	}

	pbVal, err := toStructPB(value)
	if err != nil {
		p.err = multierr.Append(p.err, fmt.Errorf("invalid attribute value for '%s': %w", key, err))
		return p
	}

	p.Attr[key] = pbVal
	return p
}

// Err returns any errors accumulated during the construction of the principal.
func (p *Principal) Err() error {
	return p.err
}

// Resource is a single resource.
type Resource struct {
	*enginev1.Resource
	err error
}

// NewResource creates a new instance of a resource.
func NewResource(kind, id string) *Resource {
	return &Resource{
		Resource: &enginev1.Resource{Kind: kind, Id: id},
	}
}

// WithPolicyVersion sets the policy version for this resource.
func (r *Resource) WithPolicyVersion(policyVersion string) *Resource {
	r.PolicyVersion = policyVersion
	return r
}

// WithAttributes merges the given attributes to the resource's existing attributes.
func (r *Resource) WithAttributes(attr map[string]interface{}) *Resource {
	if r.Attr == nil {
		r.Attr = make(map[string]*structpb.Value, len(attr))
	}

	for k, v := range attr {
		pbVal, err := toStructPB(v)
		if err != nil {
			r.err = multierr.Append(r.err, fmt.Errorf("invalid attribute value for '%s': %w", k, err))
			continue
		}
		r.Attr[k] = pbVal
	}

	return r
}

// WithAttr adds a new attribute to the resource.
// It will overwrite any existing attribute having the same key.
func (r *Resource) WithAttr(key string, value interface{}) *Resource {
	if r.Attr == nil {
		r.Attr = make(map[string]*structpb.Value)
	}

	pbVal, err := toStructPB(value)
	if err != nil {
		r.err = multierr.Append(r.err, fmt.Errorf("invalid attribute value for '%s': %w", key, err))
		return r
	}

	r.Attr[key] = pbVal
	return r
}

// Err returns any errors accumulated during the construction of the resource.
func (r *Resource) Err() error {
	return r.err
}

// ResourceSet is a container for a set of resources.
type ResourceSet struct {
	*requestv1.ResourceSet
	err error
}

// NewResourceSet creates a new resource set.
func NewResourceSet(kind string) *ResourceSet {
	return &ResourceSet{
		ResourceSet: &requestv1.ResourceSet{Kind: kind},
	}
}

// WithPolicyVersion sets the policy version for this resource set.
func (rs *ResourceSet) WithPolicyVersion(policyVersion string) *ResourceSet {
	rs.PolicyVersion = policyVersion
	return rs
}

// WithResourceInstance adds a new resource instance to the resource set.
func (rs *ResourceSet) WithResourceInstance(id string, attr map[string]interface{}) *ResourceSet {
	if rs.Instances == nil {
		rs.Instances = make(map[string]*requestv1.AttributesMap)
	}

	pbAttr := make(map[string]*structpb.Value, len(attr))
	for k, v := range attr {
		pbVal, err := structpb.NewValue(v)
		if err != nil {
			rs.err = multierr.Append(rs.err, fmt.Errorf("invalid attribute value for '%s': %w", k, err))
			continue
		}
		pbAttr[k] = pbVal
	}

	rs.Instances[id] = &requestv1.AttributesMap{Attr: pbAttr}
	return rs
}

// Err returns any errors accumulated during the construction of this resource set.
func (rs *ResourceSet) Err() error {
	return rs.err
}

// CheckResourceSetResponse is the response from the CheckResourceSet API call.
type CheckResourceSetResponse struct {
	*responsev1.CheckResourceSetResponse
}

// IsAllowed returns true if the response indicates that the given action on the given resource is allowed.
func (crsr *CheckResourceSetResponse) IsAllowed(resourceID, action string) bool {
	res, ok := crsr.ResourceInstances[resourceID]
	if !ok {
		return false
	}

	effect, ok := res.Actions[action]
	if !ok {
		return false
	}

	return effect == effectv1.Effect_EFFECT_ALLOW
}

func (crsr *CheckResourceSetResponse) String() string {
	return protojson.Format(crsr.CheckResourceSetResponse)
}

func toStructPB(v interface{}) (*structpb.Value, error) {
	val, err := structpb.NewValue(v)
	if err == nil {
		return val, nil
	}

	vv := reflect.ValueOf(v)
	switch vv.Kind() {
	case reflect.Array, reflect.Slice:
		arr := make([]interface{}, vv.Len())
		for i := 0; i < vv.Len(); i++ {
			el := vv.Index(i)
			// TODO: (cell) Recurse
			arr[i] = el.Interface()
		}

		return structpb.NewValue(arr)
	case reflect.Map:
		if vv.Type().Key().Kind() == reflect.String {
			m := make(map[string]interface{})

			iter := vv.MapRange()
			for iter.Next() {
				m[iter.Key().String()] = iter.Value().Interface()
			}

			return structpb.NewValue(m)
		}
	default:
		return nil, err
	}

	return nil, err
}
