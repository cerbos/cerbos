// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests || e2e

package client

import (
	"context"
	"testing"
	"time"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/stretchr/testify/require"
)

const timeout = 15 * time.Second

func RunE2ETests(addr string, opts ...Opt) func(*testing.T) {
	c, err := New(addr, opts...)
	if err != nil {
		panic(err)
	}

	return TestGRPCClient(c)
}

func TestGRPCClient(c Client) func(*testing.T) {
	return func(t *testing.T) {
		t.Run("CheckResourceSet", func(t *testing.T) {
			ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
			defer cancelFunc()

			have, err := c.CheckResourceSet(
				ctx,
				NewPrincipal("john").
					WithRoles("employee").
					WithPolicyVersion("20210210").
					WithAttributes(map[string]any{
						"department": "marketing",
						"geography":  "GB",
						"team":       "design",
					}),
				NewResourceSet("leave_request").
					WithPolicyVersion("20210210").
					AddResourceInstance("XX125", map[string]any{
						"department": "marketing",
						"geography":  "GB",
						"id":         "XX125",
						"owner":      "john",
						"team":       "design",
					}),
				"view:public", "approve", "defer")

			require.NoError(t, err)
			require.True(t, have.IsAllowed("XX125", "view:public"))
			require.False(t, have.IsAllowed("XX125", "approve"))
			require.True(t, have.IsAllowed("XX125", "defer"))
		})

		t.Run("CheckResourceBatch", func(t *testing.T) {
			ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
			defer cancelFunc()

			have, err := c.CheckResourceBatch(
				ctx,
				NewPrincipal("john").
					WithRoles("employee").
					WithPolicyVersion("20210210").
					WithAttributes(map[string]any{
						"department": "marketing",
						"geography":  "GB",
						"team":       "design",
					}),
				NewResourceBatch().
					Add(
						NewResource("leave_request", "XX125").
							WithPolicyVersion("20210210").
							WithAttributes(map[string]any{
								"department": "marketing",
								"geography":  "GB",
								"id":         "XX125",
								"owner":      "john",
								"team":       "design",
							}), "view:public", "defer").
					Add(
						NewResource("leave_request", "XX125").
							WithPolicyVersion("20210210").
							WithAttributes(map[string]any{
								"department": "marketing",
								"geography":  "GB",
								"id":         "XX125",
								"owner":      "john",
								"team":       "design",
							}), "approve").
					Add(
						NewResource("leave_request", "XX225").
							WithPolicyVersion("20210210").
							WithAttributes(map[string]any{
								"department": "engineering",
								"geography":  "GB",
								"id":         "XX225",
								"owner":      "mary",
								"team":       "frontend",
							}), "approve"),
			)

			require.NoError(t, err)
			require.True(t, have.IsAllowed("XX125", "view:public"))
			require.False(t, have.IsAllowed("XX125", "approve"))
			require.True(t, have.IsAllowed("XX125", "defer"))
			require.False(t, have.IsAllowed("XX225", "approve"))
		})

		t.Run("CheckResources", func(t *testing.T) {
			principal := NewPrincipal("john").
				WithRoles("employee").
				WithPolicyVersion("20210210").
				WithAttributes(map[string]any{
					"department": "marketing",
					"geography":  "GB",
					"team":       "design",
				})

			resources := NewResourceBatch().
				Add(
					NewResource("leave_request", "XX125").
						WithPolicyVersion("20210210").
						WithAttributes(map[string]any{
							"department": "marketing",
							"geography":  "GB",
							"id":         "XX125",
							"owner":      "john",
							"team":       "design",
						}), "view:public", "defer").
				Add(
					NewResource("leave_request", "XX125").
						WithPolicyVersion("20210210").
						WithAttributes(map[string]any{
							"department": "marketing",
							"geography":  "GB",
							"id":         "XX125",
							"owner":      "john",
							"team":       "design",
						}), "approve").
				Add(
					NewResource("leave_request", "XX225").
						WithPolicyVersion("20210210").
						WithAttributes(map[string]any{
							"department": "engineering",
							"geography":  "GB",
							"id":         "XX225",
							"owner":      "mary",
							"team":       "frontend",
						}), "approve")

			check := func(t *testing.T, have *CheckResourcesResponse, err error) {
				t.Helper()
				require.NoError(t, err)

				haveXX125 := have.GetResource("XX125", MatchResourceKind("leave_request"))
				require.NoError(t, haveXX125.Err())
				require.True(t, haveXX125.IsAllowed("view:public"))
				require.False(t, haveXX125.IsAllowed("approve"))
				require.True(t, haveXX125.IsAllowed("defer"))

				haveXX225 := have.GetResource("XX225")
				require.NoError(t, haveXX225.Err())
				require.False(t, haveXX225.IsAllowed("approve"))
			}

			t.Run("Direct", func(t *testing.T) {
				ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
				defer cancelFunc()

				have, err := c.CheckResources(ctx, principal, resources)
				check(t, have, err)
			})

			t.Run("WithPrincipal", func(t *testing.T) {
				ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
				defer cancelFunc()

				have, err := c.WithPrincipal(principal).CheckResources(ctx, resources)
				check(t, have, err)
			})
		})

		t.Run("CheckResourcesScoped", func(t *testing.T) {
			principal := NewPrincipal("john").
				WithRoles("employee").
				WithScope("acme.hr").
				WithAttributes(map[string]any{
					"department": "marketing",
					"geography":  "GB",
					"team":       "design",
					"ip_address": "10.20.5.5",
				})

			resources := NewResourceBatch().
				Add(
					NewResource("leave_request", "XX125").
						WithScope("acme.hr.uk").
						WithAttributes(map[string]any{
							"department": "marketing",
							"geography":  "GB",
							"id":         "XX125",
							"owner":      "john",
							"team":       "design",
						}), "view:public", "delete", "create").
				Add(
					NewResource("leave_request", "XX225").
						WithScope("acme.hr").
						WithAttributes(map[string]any{
							"department": "marketing",
							"geography":  "GB",
							"id":         "XX225",
							"owner":      "john",
							"team":       "design",
						}), "view:public", "delete", "create")

			check := func(t *testing.T, have *CheckResourcesResponse, err error) {
				t.Helper()
				require.NoError(t, err)

				haveXX125 := have.GetResource("XX125", MatchResourceKind("leave_request"))
				require.NoError(t, haveXX125.Err())
				require.True(t, haveXX125.IsAllowed("view:public"))
				require.True(t, haveXX125.IsAllowed("delete"))
				require.True(t, haveXX125.IsAllowed("create"))
				require.Equal(t, "acme.hr.uk", haveXX125.Resource.Scope)

				haveXX225 := have.GetResource("XX225", MatchResourceKind("leave_request"))
				require.NoError(t, haveXX225.Err())
				require.True(t, haveXX225.IsAllowed("view:public"))
				require.False(t, haveXX225.IsAllowed("delete"))
				require.True(t, haveXX225.IsAllowed("create"))
				require.Equal(t, "acme.hr", haveXX225.Resource.Scope)
			}

			t.Run("Direct", func(t *testing.T) {
				ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
				defer cancelFunc()

				have, err := c.CheckResources(ctx, principal, resources)
				check(t, have, err)
			})

			t.Run("WithPrincipal", func(t *testing.T) {
				ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
				defer cancelFunc()

				have, err := c.WithPrincipal(principal).CheckResources(ctx, resources)
				check(t, have, err)
			})
		})

		t.Run("IsAllowed", func(t *testing.T) {
			principal := NewPrincipal("john").
				WithRoles("employee").
				WithPolicyVersion("20210210").
				WithAttributes(map[string]any{
					"department": "marketing",
					"geography":  "GB",
					"team":       "design",
				})

			resource := NewResource("leave_request", "XX125").
				WithPolicyVersion("20210210").
				WithAttributes(map[string]any{
					"department": "marketing",
					"geography":  "GB",
					"id":         "XX125",
					"owner":      "john",
					"team":       "design",
				})

			t.Run("Direct", func(t *testing.T) {
				ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
				defer cancelFunc()

				have, err := c.IsAllowed(ctx, principal, resource, "defer")
				require.NoError(t, err)
				require.True(t, have)
			})

			t.Run("WithPrincipal", func(t *testing.T) {
				ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
				defer cancelFunc()

				have, err := c.WithPrincipal(principal).IsAllowed(ctx, resource, "defer")
				require.NoError(t, err)
				require.True(t, have)
			})
		})

		t.Run("ResourcesQueryPlan", func(t *testing.T) {
			principal := NewPrincipal("maggie").
				WithRoles("manager").
				WithAttr("geography", "US").
				WithAttr("managed_geographies", "US").
				WithAttr("reader", false)

			resource := NewResource("leave_request", "").
				WithPolicyVersion("20210210").
				WithAttr("geography", "US")

			cc := c.With(IncludeMeta(true))

			check := func(t *testing.T, have *PlanResourcesResponse, err error) {
				t.Helper()
				is := require.New(t)

				is.NoError(err)
				is.Equal(have.Filter.Kind, enginev1.PlanResourcesFilter_KIND_CONDITIONAL)
				expression := have.Filter.Condition.GetExpression()
				is.NotNil(expression)
				is.Equal(expression.Operator, "eq")
				is.Equal(expression.Operands[0].GetVariable(), "request.resource.attr.status")
				is.Equal(expression.Operands[1].GetValue().GetStringValue(), "PENDING_APPROVAL")
				t.Log(have.Meta.FilterDebug)
			}

			t.Run("Direct", func(t *testing.T) {
				ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
				defer cancelFunc()

				have, err := cc.PlanResources(ctx, principal, resource, "approve")
				check(t, have, err)
			})

			t.Run("WithPrincipal", func(t *testing.T) {
				ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
				defer cancelFunc()

				have, err := cc.WithPrincipal(principal).PlanResources(ctx, resource, "approve")
				check(t, have, err)
			})
		})
	}
}
