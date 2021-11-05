// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sync"
	"time"

	"go.uber.org/multierr"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/policy"
)

const apiVersion = "api.cerbos.dev/v1"

// Principal is a container for principal data.
type Principal struct {
	p   *enginev1.Principal
	err error
}

// NewPrincipal creates a new principal object with the given ID and roles.
func NewPrincipal(id string, roles ...string) *Principal {
	return &Principal{
		p: &enginev1.Principal{
			Id:    id,
			Roles: roles,
		},
	}
}

// WithPolicyVersion sets the policy version for this principal.
func (p *Principal) WithPolicyVersion(policyVersion string) *Principal {
	p.p.PolicyVersion = policyVersion
	return p
}

// WithRoles appends the set of roles to principal's existing roles.
func (p *Principal) WithRoles(roles ...string) *Principal {
	p.p.Roles = append(p.p.Roles, roles...)
	return p
}

// WithAttributes merges the given attributes to principal's existing attributes.
func (p *Principal) WithAttributes(attr map[string]interface{}) *Principal {
	if p.p.Attr == nil {
		p.p.Attr = make(map[string]*structpb.Value, len(attr))
	}

	for k, v := range attr {
		pbVal, err := toStructPB(v)
		if err != nil {
			p.err = multierr.Append(p.err, fmt.Errorf("invalid attribute value for '%s': %w", k, err))
			continue
		}
		p.p.Attr[k] = pbVal
	}

	return p
}

// WithAttr adds a new attribute to the principal.
// It will overwrite any existing attribute having the same key.
func (p *Principal) WithAttr(key string, value interface{}) *Principal {
	if p.p.Attr == nil {
		p.p.Attr = make(map[string]*structpb.Value)
	}

	pbVal, err := toStructPB(value)
	if err != nil {
		p.err = multierr.Append(p.err, fmt.Errorf("invalid attribute value for '%s': %w", key, err))
		return p
	}

	p.p.Attr[key] = pbVal
	return p
}

// Err returns any errors accumulated during the construction of the principal.
func (p *Principal) Err() error {
	return p.err
}

// Validate checks whether the principal object is valid.
func (p *Principal) Validate() error {
	if p.err != nil {
		return p.err
	}

	return p.p.Validate()
}

// Resource is a single resource instance.
type Resource struct {
	r   *enginev1.Resource
	err error
}

// NewResource creates a new instance of a resource.
func NewResource(kind, id string) *Resource {
	return &Resource{
		r: &enginev1.Resource{Kind: kind, Id: id},
	}
}

// WithPolicyVersion sets the policy version for this resource.
func (r *Resource) WithPolicyVersion(policyVersion string) *Resource {
	r.r.PolicyVersion = policyVersion
	return r
}

// WithAttributes merges the given attributes to the resource's existing attributes.
func (r *Resource) WithAttributes(attr map[string]interface{}) *Resource {
	if r.r.Attr == nil {
		r.r.Attr = make(map[string]*structpb.Value, len(attr))
	}

	for k, v := range attr {
		pbVal, err := toStructPB(v)
		if err != nil {
			r.err = multierr.Append(r.err, fmt.Errorf("invalid attribute value for '%s': %w", k, err))
			continue
		}
		r.r.Attr[k] = pbVal
	}

	return r
}

// WithAttr adds a new attribute to the resource.
// It will overwrite any existing attribute having the same key.
func (r *Resource) WithAttr(key string, value interface{}) *Resource {
	if r.r.Attr == nil {
		r.r.Attr = make(map[string]*structpb.Value)
	}

	pbVal, err := toStructPB(value)
	if err != nil {
		r.err = multierr.Append(r.err, fmt.Errorf("invalid attribute value for '%s': %w", key, err))
		return r
	}

	r.r.Attr[key] = pbVal
	return r
}

// Err returns any errors accumulated during the construction of the resource.
func (r *Resource) Err() error {
	return r.err
}

// Validate checks whether the resource is valid.
func (r *Resource) Validate() error {
	if r.err != nil {
		return r.err
	}

	return r.r.Validate()
}

// ResourceSet is a container for a set of resources of the same kind.
type ResourceSet struct {
	rs  *requestv1.ResourceSet
	err error
}

// NewResourceSet creates a new resource set.
func NewResourceSet(kind string) *ResourceSet {
	return &ResourceSet{
		rs: &requestv1.ResourceSet{Kind: kind},
	}
}

// WithPolicyVersion sets the policy version for this resource set.
func (rs *ResourceSet) WithPolicyVersion(policyVersion string) *ResourceSet {
	rs.rs.PolicyVersion = policyVersion
	return rs
}

// AddResourceInstance adds a new resource instance to the resource set.
func (rs *ResourceSet) AddResourceInstance(id string, attr map[string]interface{}) *ResourceSet {
	if rs.rs.Instances == nil {
		rs.rs.Instances = make(map[string]*requestv1.AttributesMap)
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

	rs.rs.Instances[id] = &requestv1.AttributesMap{Attr: pbAttr}
	return rs
}

// Err returns any errors accumulated during the construction of this resource set.
func (rs *ResourceSet) Err() error {
	return rs.err
}

// Validate checks whether this resource set is valid.
func (rs *ResourceSet) Validate() error {
	if rs.err != nil {
		return rs.err
	}

	return rs.rs.Validate()
}

// CheckResourceSetResponse is the response from the CheckResourceSet API call.
type CheckResourceSetResponse struct {
	*responsev1.CheckResourceSetResponse
}

// IsAllowed returns true if the response indicates that the given action on the given resource is allowed.
// If the resource or action is not contained in the response, the return value will always be false.
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

// ResourceBatch is a container for a batch of heterogeneous resources.
type ResourceBatch struct {
	batch []*requestv1.CheckResourceBatchRequest_BatchEntry
	err   error
}

// NewResourceBatch creates a new resource batch.
func NewResourceBatch() *ResourceBatch {
	return &ResourceBatch{}
}

// Add a new resource to the batch.
func (rb *ResourceBatch) Add(resource *Resource, actions ...string) *ResourceBatch {
	if resource == nil || len(actions) == 0 {
		return rb
	}

	entry := &requestv1.CheckResourceBatchRequest_BatchEntry{
		Actions:  actions,
		Resource: resource.r,
	}

	if err := entry.Validate(); err != nil {
		rb.err = multierr.Append(rb.err, fmt.Errorf("invalid resource '%s': %w", resource.r.Id, err))
		return rb
	}

	rb.batch = append(rb.batch, entry)
	return rb
}

// Err returns any errors accumulated during the construction of the resource batch.
func (rb *ResourceBatch) Err() error {
	return rb.err
}

// Validate checks whether the resource batch is valid.
func (rb *ResourceBatch) Validate() error {
	if rb.err != nil {
		return rb.err
	}

	if len(rb.batch) == 0 {
		return errors.New("empty batch")
	}

	var errList error
	for _, entry := range rb.batch {
		if err := entry.Validate(); err != nil {
			errList = multierr.Append(errList, err)
		}
	}

	return errList
}

// CheckResourceBatchResponse is the response from the CheckResourceBatch API call.
type CheckResourceBatchResponse struct {
	*responsev1.CheckResourceBatchResponse
	once sync.Once
	idx  map[string][]int
}

func (crbr *CheckResourceBatchResponse) buildIdx() {
	crbr.once.Do(func() {
		crbr.idx = make(map[string][]int, len(crbr.Results))
		for i, r := range crbr.Results {
			v := crbr.idx[r.ResourceId]
			crbr.idx[r.ResourceId] = append(v, i)
		}
	})
}

// IsAllowed returns true if the given resource and action is allowed.
// If the resource or the action is not included in the response, the result will always be false.
func (crbr *CheckResourceBatchResponse) IsAllowed(resourceID, action string) bool {
	crbr.buildIdx()
	indexes, ok := crbr.idx[resourceID]
	if !ok {
		return false
	}

	for _, i := range indexes {
		r := crbr.Results[i]
		if r == nil {
			continue
		}

		if effect, ok := r.Actions[action]; ok {
			return effect == effectv1.Effect_EFFECT_ALLOW
		}
	}

	return false
}

func (crbr *CheckResourceBatchResponse) String() string {
	return protojson.Format(crbr.CheckResourceBatchResponse)
}

// TODO (cell) replace with util.ToStructPB.
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

// PolicySet is a container for a set of policies.
type PolicySet struct {
	policies []*policyv1.Policy
	err      error
}

// NewPolicySet creates a new policy set.
func NewPolicySet() *PolicySet {
	return &PolicySet{}
}

// AddPolicyFromFile adds a policy from the given file to the set.
func (ps *PolicySet) AddPolicyFromFile(file string) *PolicySet {
	f, err := os.Open(file)
	if err != nil {
		ps.err = multierr.Append(ps.err, fmt.Errorf("failed to add policy from file '%s': %w", file, err))
		return ps
	}

	defer f.Close()
	return ps.AddPolicyFromReader(f)
}

// AddPolicyFromReader adds a policy from the given reader to the set.
func (ps *PolicySet) AddPolicyFromReader(r io.Reader) *PolicySet {
	p, err := policy.ReadPolicy(r)
	if err != nil {
		ps.err = multierr.Append(ps.err, fmt.Errorf("failed to add policy from reader: %w", err))
		return ps
	}

	ps.policies = append(ps.policies, p)
	return nil
}

// AddResourcePolicies adds the given resource policies to the set.
func (ps *PolicySet) AddResourcePolicies(policies ...*ResourcePolicy) *PolicySet {
	for _, p := range policies {
		if p == nil {
			continue
		}

		if err := ps.add(p); err != nil {
			ps.err = multierr.Append(ps.err, fmt.Errorf("failed to add resource policy [%s:%s]: %w", p.p.Resource, p.p.Version, err))
		}
	}

	return ps
}

// AddPrincipalPolicies adds the given principal policies to the set.
func (ps *PolicySet) AddPrincipalPolicies(policies ...*PrincipalPolicy) *PolicySet {
	for _, p := range policies {
		if p == nil {
			continue
		}

		if err := ps.add(p); err != nil {
			ps.err = multierr.Append(ps.err, fmt.Errorf("failed to add principal policy [%s:%s]: %w", p.pp.Principal, p.pp.Version, err))
		}
	}

	return ps
}

// AddDerivedRoles adds the given derived roles to the set.
func (ps *PolicySet) AddDerivedRoles(policies ...*DerivedRoles) *PolicySet {
	for _, p := range policies {
		if p == nil {
			continue
		}

		if err := ps.add(p); err != nil {
			ps.err = multierr.Append(ps.err, fmt.Errorf("failed to add derived roles [%s]: %w", p.dr.Name, err))
		}
	}

	return ps
}

func (ps *PolicySet) add(b interface {
	build() (*policyv1.Policy, error)
}) error {
	p, err := b.build()
	if err != nil {
		return err
	}

	ps.policies = append(ps.policies, p)
	return nil
}

// Err returns the errors accumulated during the construction of the policy set.
func (ps *PolicySet) Err() error {
	return ps.err
}

// Validate checks whether the policy set is valid.
func (ps *PolicySet) Validate() error {
	if ps.err != nil {
		return ps.err
	}

	if len(ps.policies) == 0 {
		return errors.New("empty policy set")
	}

	return nil
}

// ResourcePolicy is a builder for resource policies.
type ResourcePolicy struct {
	p   *policyv1.ResourcePolicy
	err error
}

// NewResourcePolicy creates a new resource policy builder.
func NewResourcePolicy(resource, version string) *ResourcePolicy {
	return &ResourcePolicy{
		p: &policyv1.ResourcePolicy{
			Resource: resource,
			Version:  version,
		},
	}
}

// WithDerivedRolesImports adds import statements for derived roles.
func (rp *ResourcePolicy) WithDerivedRolesImports(imp ...string) *ResourcePolicy {
	rp.p.ImportDerivedRoles = append(rp.p.ImportDerivedRoles, imp...)
	return rp
}

// AddResourceRules adds resource rules to the policy.
func (rp *ResourcePolicy) AddResourceRules(rules ...*ResourceRule) *ResourcePolicy {
	for _, r := range rules {
		if r == nil {
			continue
		}

		if err := r.Validate(); err != nil {
			rp.err = multierr.Append(rp.err, fmt.Errorf("invalid rule: %w", err))
			continue
		}

		rp.p.Rules = append(rp.p.Rules, r.rule)
	}

	return rp
}

// Err returns any errors accumulated during the construction of the policy.
func (rp *ResourcePolicy) Err() error {
	return rp.err
}

// Validate checks whether the policy is valid.
func (rp *ResourcePolicy) Validate() error {
	if rp.err != nil {
		return rp.err
	}

	_, err := rp.build()
	return err
}

func (rp *ResourcePolicy) build() (*policyv1.Policy, error) {
	if err := rp.Validate(); err != nil {
		return nil, err
	}

	return &policyv1.Policy{
		ApiVersion: apiVersion,
		PolicyType: &policyv1.Policy_ResourcePolicy{
			ResourcePolicy: rp.p,
		},
	}, nil
}

// ResourceRules is a rule in a resource policy.
type ResourceRule struct {
	rule *policyv1.ResourceRule
}

// NewAllowResourceRule creates a resource rule that allows the actions when matched.
func NewAllowResourceRule(actions ...string) *ResourceRule {
	return &ResourceRule{
		rule: &policyv1.ResourceRule{
			Actions: actions,
			Effect:  effectv1.Effect_EFFECT_ALLOW,
		},
	}
}

// NewDenyResourceRule creates a resource rule that denies the actions when matched.
func NewDenyResourceRule(actions ...string) *ResourceRule {
	return &ResourceRule{
		rule: &policyv1.ResourceRule{
			Actions: actions,
			Effect:  effectv1.Effect_EFFECT_DENY,
		},
	}
}

// WithRoles adds roles to which this rule applies.
func (rr *ResourceRule) WithRoles(roles ...string) *ResourceRule {
	rr.rule.Roles = append(rr.rule.Roles, roles...)
	return rr
}

// WithDerivedRoles adds derived roles to which this rule applies.
func (rr *ResourceRule) WithDerivedRoles(roles ...string) *ResourceRule {
	rr.rule.DerivedRoles = append(rr.rule.DerivedRoles, roles...)
	return rr
}

// WithCondition sets the condition that applies to this rule.
func (rr *ResourceRule) WithCondition(m match) *ResourceRule {
	rr.rule.Condition = &policyv1.Condition{
		Condition: &policyv1.Condition_Match{
			Match: m.build(),
		},
	}

	return rr
}

// Err returns errors accumulated during the construction of the resource rule.
func (rr *ResourceRule) Err() error {
	return nil
}

// Validate checks whether the resource rule is valid.
func (rr *ResourceRule) Validate() error {
	return rr.rule.Validate()
}

// PrincipalPolicy is a builder for principal policies.
type PrincipalPolicy struct {
	pp  *policyv1.PrincipalPolicy
	err error
}

// NewPrincipalPolicy creates a new principal policy.
func NewPrincipalPolicy(principal, version string) *PrincipalPolicy {
	return &PrincipalPolicy{
		pp: &policyv1.PrincipalPolicy{
			Principal: principal,
			Version:   version,
		},
	}
}

// AddPrincipalRules adds rules to this policy.
func (pp *PrincipalPolicy) AddPrincipalRules(rules ...*PrincipalRule) *PrincipalPolicy {
	for _, r := range rules {
		if r == nil {
			continue
		}

		if err := r.Validate(); err != nil {
			pp.err = multierr.Append(pp.err, fmt.Errorf("invalid rule: %w", err))
			continue
		}

		pp.pp.Rules = append(pp.pp.Rules, r.rule)
	}

	return pp
}

// Err returns the errors accumulated during the construction of this policy.
func (pp *PrincipalPolicy) Err() error {
	return pp.err
}

// Validate checks whether the policy is valid.
func (pp *PrincipalPolicy) Validate() error {
	if pp.err != nil {
		return pp.err
	}

	_, err := pp.build()
	return err
}

func (pp *PrincipalPolicy) build() (*policyv1.Policy, error) {
	p := &policyv1.Policy{
		ApiVersion: apiVersion,
		PolicyType: &policyv1.Policy_PrincipalPolicy{
			PrincipalPolicy: pp.pp,
		},
	}

	return p, policy.Validate(p)
}

// PrincipalRule is a builder for principal rules.
type PrincipalRule struct {
	rule *policyv1.PrincipalRule
}

// NewPrincipalRule creates a new rule for the specified resource.
func NewPrincipalRule(resource string) *PrincipalRule {
	return &PrincipalRule{
		rule: &policyv1.PrincipalRule{
			Resource: resource,
		},
	}
}

// AllowAction sets the action as allowed on the resource.
func (pr *PrincipalRule) AllowAction(action string) *PrincipalRule {
	return pr.addAction(action, effectv1.Effect_EFFECT_ALLOW, nil)
}

// DenyAction sets the action as denied on the resource.
func (pr *PrincipalRule) DenyAction(action string) *PrincipalRule {
	return pr.addAction(action, effectv1.Effect_EFFECT_DENY, nil)
}

// AllowActionOnCondition sets the action as allowed if the condition is fulfilled.
func (pr *PrincipalRule) AllowActionOnCondition(action string, m match) *PrincipalRule {
	cond := &policyv1.Condition{Condition: &policyv1.Condition_Match{Match: m.build()}}
	return pr.addAction(action, effectv1.Effect_EFFECT_ALLOW, cond)
}

// DenyActionOnCondition sets the action as denied if the condition is fulfilled.
func (pr *PrincipalRule) DenyActionOnCondition(action string, m match) *PrincipalRule {
	cond := &policyv1.Condition{Condition: &policyv1.Condition_Match{Match: m.build()}}
	return pr.addAction(action, effectv1.Effect_EFFECT_DENY, cond)
}

func (pr *PrincipalRule) addAction(action string, effect effectv1.Effect, comp *policyv1.Condition) *PrincipalRule {
	pr.rule.Actions = append(pr.rule.Actions, &policyv1.PrincipalRule_Action{
		Action:    action,
		Effect:    effect,
		Condition: comp,
	})

	return pr
}

// Err returns errors accumulated during the construction of the rule.
func (pr *PrincipalRule) Err() error {
	return nil
}

// Vaidate checks whether the rule is valid.
func (pr *PrincipalRule) Validate() error {
	return pr.rule.Validate()
}

// DerivedRoles is a builder for derived roles.
type DerivedRoles struct {
	dr *policyv1.DerivedRoles
}

// NewDerivedRoles creates a new derived roles set with the given name.
func NewDerivedRoles(name string) *DerivedRoles {
	return &DerivedRoles{
		dr: &policyv1.DerivedRoles{Name: name},
	}
}

// AddRole adds a new derived role with the given name which is an alias for the set of parent roles.
func (dr *DerivedRoles) AddRole(name string, parentRoles []string) *DerivedRoles {
	return dr.addRoleDef(name, parentRoles, nil)
}

// AddRoleWithCondition adds a derived role with a condition attached.
func (dr *DerivedRoles) AddRoleWithCondition(name string, parentRoles []string, m match) *DerivedRoles {
	cond := &policyv1.Condition{Condition: &policyv1.Condition_Match{Match: m.build()}}
	return dr.addRoleDef(name, parentRoles, cond)
}

func (dr *DerivedRoles) addRoleDef(name string, parentRoles []string, comp *policyv1.Condition) *DerivedRoles {
	dr.dr.Definitions = append(dr.dr.Definitions, &policyv1.RoleDef{Name: name, ParentRoles: parentRoles, Condition: comp})
	return dr
}

// Err returns any errors accumulated during the construction of the derived roles.
func (dr *DerivedRoles) Err() error {
	return nil
}

// Validate checks whether the derived roles are valid.
func (dr *DerivedRoles) Validate() error {
	_, err := dr.build()
	return err
}

func (dr *DerivedRoles) build() (*policyv1.Policy, error) {
	p := &policyv1.Policy{
		ApiVersion: apiVersion,
		PolicyType: &policyv1.Policy_DerivedRoles{
			DerivedRoles: dr.dr,
		},
	}

	return p, policy.Validate(p)
}

// MatchExpr matches a single expression.
func MatchExpr(expr string) match {
	return matchExpr(expr)
}

// MatchAllOf  matches all of the expressions (logical AND).
func MatchAllOf(m ...match) match {
	return matchList{
		list: m,
		cons: func(exprList []*policyv1.Match) *policyv1.Match {
			return &policyv1.Match{Op: &policyv1.Match_All{All: &policyv1.Match_ExprList{Of: exprList}}}
		},
	}
}

// MatchAnyOf  matches any of the expressions (logical OR).
func MatchAnyOf(m ...match) match {
	return matchList{
		list: m,
		cons: func(exprList []*policyv1.Match) *policyv1.Match {
			return &policyv1.Match{Op: &policyv1.Match_Any{Any: &policyv1.Match_ExprList{Of: exprList}}}
		},
	}
}

// MatchNoneOf  matches none of the expressions (logical NOT).
func MatchNoneOf(m ...match) match {
	return matchList{
		list: m,
		cons: func(exprList []*policyv1.Match) *policyv1.Match {
			return &policyv1.Match{Op: &policyv1.Match_None{None: &policyv1.Match_ExprList{Of: exprList}}}
		},
	}
}

type match interface {
	build() *policyv1.Match
}

type matchExpr string

func (me matchExpr) build() *policyv1.Match {
	expr := string(me)
	return &policyv1.Match{Op: &policyv1.Match_Expr{Expr: expr}}
}

type matchList struct {
	list []match
	cons func([]*policyv1.Match) *policyv1.Match
}

func (ml matchList) build() *policyv1.Match {
	exprList := make([]*policyv1.Match, len(ml.list))
	for i, expr := range ml.list {
		exprList[i] = expr.build()
	}

	return ml.cons(exprList)
}

type ServerInfo struct {
	*responsev1.ServerInfoResponse
}

type AuditLogType uint8

const (
	AccessLogs AuditLogType = iota
	DecisionLogs
)

// AuditLogOptions is used to filter audit logs.
type AuditLogOptions struct {
	Type      AuditLogType
	Tail      uint32
	StartTime time.Time
	EndTime   time.Time
	Lookup    string
}

type AuditLogEntry struct {
	accessLog   *auditv1.AccessLogEntry
	decisionLog *auditv1.DecisionLogEntry
	err         error
}

func (e *AuditLogEntry) AccessLog() (*auditv1.AccessLogEntry, error) {
	return e.accessLog, e.err
}

func (e *AuditLogEntry) DecisionLog() (*auditv1.DecisionLogEntry, error) {
	return e.decisionLog, e.err
}

type ListPoliciesSortingType uint8

const (
	SortByName    ListPoliciesSortingType = 1
	SortByVersion ListPoliciesSortingType = 2
)

type sortingOptions struct {
	descending bool
	field      ListPoliciesSortingType
}

type policyListOptions struct {
	filters        []*requestv1.ListPoliciesRequest_Filter
	sortingOptions *sortingOptions
}

// ListOpt is used to specify options for ListPolicies method.
type ListOpt func(*policyListOptions)

// FieldEqualsFilter adds a exact match filter for the field.
func FieldEqualsFilter(path, value string) ListOpt {
	return func(pf *policyListOptions) {
		pf.filters = append(pf.filters, &requestv1.ListPoliciesRequest_Filter{
			Type:      requestv1.ListPoliciesRequest_MATCH_TYPE_EXACT,
			FieldPath: path,
			Value:     value,
		})
	}
}

// FieldEqualsFilter adds a regex match filter for the field.
func FieldMatchesFilter(path, value string) ListOpt {
	return func(pf *policyListOptions) {
		pf.filters = append(pf.filters, &requestv1.ListPoliciesRequest_Filter{
			Type:      requestv1.ListPoliciesRequest_MATCH_TYPE_WILDCARD,
			FieldPath: path,
			Value:     value,
		})
	}
}

// SortAscending enables sorting the policies by ascending order with given field.
func SortAscending(field ListPoliciesSortingType) ListOpt {
	return func(pf *policyListOptions) {
		pf.sortingOptions = &sortingOptions{
			field: field,
		}
	}
}

// SortDescending enables sorting the policies by descending order with given field.
func SortDescending(field ListPoliciesSortingType) ListOpt {
	return func(pf *policyListOptions) {
		pf.sortingOptions = &sortingOptions{
			descending: true,
			field:      field,
		}
	}
}
