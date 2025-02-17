// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests || e2e

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/test"
)

const timeout = 30 * time.Second

func TestSDKClient(addr string, opts ...cerbos.Opt) func(*testing.T) {
	c, err := cerbos.New(addr, opts...)
	if err != nil {
		panic(err)
	}

	//nolint:thelper
	return func(t *testing.T) {
		token := generateToken(t, time.Now().Add(5*time.Minute)) //nolint:mnd
		c := c.With(
			cerbos.AuxDataJWT(token, ""),
			cerbos.IncludeMeta(true),
		)

		t.Run("CheckResources", func(t *testing.T) {
			principal := cerbos.NewPrincipal("john").
				WithRoles("employee").
				WithPolicyVersion("20210210").
				WithAttributes(map[string]any{
					"department": "marketing",
					"geography":  "GB",
					"team":       "design",
				})

			resources := cerbos.NewResourceBatch().
				Add(
					cerbos.NewResource("leave_request", "XX125").
						WithPolicyVersion("20210210").
						WithAttributes(map[string]any{
							"department": "marketing",
							"geography":  "GB",
							"id":         "XX125",
							"owner":      "john",
							"team":       "design",
						}), "view:public", "defer").
				Add(
					cerbos.NewResource("leave_request", "XX125").
						WithPolicyVersion("20210210").
						WithAttributes(map[string]any{
							"department": "marketing",
							"geography":  "GB",
							"id":         "XX125",
							"owner":      "john",
							"team":       "design",
						}), "approve").
				Add(
					cerbos.NewResource("leave_request", "XX225").
						WithPolicyVersion("20210210").
						WithAttributes(map[string]any{
							"department": "engineering",
							"geography":  "GB",
							"id":         "XX225",
							"owner":      "mary",
							"team":       "frontend",
						}), "approve")

			check := func(t *testing.T, have *cerbos.CheckResourcesResponse, err error) {
				t.Helper()
				require.NoError(t, err)

				haveXX125 := have.GetResource("XX125", cerbos.MatchResourceKind("leave_request"))
				require.NoError(t, haveXX125.Err())
				require.True(t, haveXX125.IsAllowed("view:public"))
				require.False(t, haveXX125.IsAllowed("approve"))
				require.True(t, haveXX125.IsAllowed("defer"))

				haveXX225 := have.GetResource("XX225")
				require.NoError(t, haveXX225.Err())
				require.False(t, haveXX225.IsAllowed("approve"))
			}

			t.Run("Direct", func(t *testing.T) {
				ctx, cancelFunc := context.WithTimeout(t.Context(), timeout)
				defer cancelFunc()

				have, err := c.CheckResources(ctx, principal, resources)
				check(t, have, err)

				require.NotNil(t, have.Results[0].Meta, "no metadata found in the result")
			})

			t.Run("WithPrincipal", func(t *testing.T) {
				ctx, cancelFunc := context.WithTimeout(t.Context(), timeout)
				defer cancelFunc()

				have, err := c.WithPrincipal(principal).CheckResources(ctx, resources)
				check(t, have, err)

				require.NotNil(t, have.Results[0].Meta, "no metadata found in the result")
			})
		})

		t.Run("CheckResourcesScoped", func(t *testing.T) {
			principal := cerbos.NewPrincipal("john").
				WithRoles("employee").
				WithScope("acme.hr").
				WithAttributes(map[string]any{
					"department": "marketing",
					"geography":  "GB",
					"team":       "design",
					"ip_address": "10.20.5.5",
				})

			resources := cerbos.NewResourceBatch().
				Add(
					cerbos.NewResource("leave_request", "XX125").
						WithScope("acme.hr.uk").
						WithAttributes(map[string]any{
							"department": "marketing",
							"geography":  "GB",
							"id":         "XX125",
							"owner":      "john",
							"team":       "design",
						}), "view:public", "delete", "create").
				Add(
					cerbos.NewResource("leave_request", "XX225").
						WithScope("acme.hr").
						WithAttributes(map[string]any{
							"department": "marketing",
							"geography":  "GB",
							"id":         "XX225",
							"owner":      "john",
							"team":       "design",
						}), "view:public", "delete", "create")

			check := func(t *testing.T, have *cerbos.CheckResourcesResponse, err error) {
				t.Helper()
				require.NoError(t, err)

				haveXX125 := have.GetResource("XX125", cerbos.MatchResourceKind("leave_request"))
				require.NoError(t, haveXX125.Err())
				require.True(t, haveXX125.IsAllowed("view:public"))
				require.True(t, haveXX125.IsAllowed("delete"))
				require.True(t, haveXX125.IsAllowed("create"))
				require.Equal(t, "acme.hr.uk", haveXX125.Resource.Scope)

				haveXX225 := have.GetResource("XX225", cerbos.MatchResourceKind("leave_request"))
				require.NoError(t, haveXX225.Err())
				require.True(t, haveXX225.IsAllowed("view:public"))
				require.False(t, haveXX225.IsAllowed("delete"))
				require.True(t, haveXX225.IsAllowed("create"))
				require.Equal(t, "acme.hr", haveXX225.Resource.Scope)
			}

			t.Run("Direct", func(t *testing.T) {
				ctx, cancelFunc := context.WithTimeout(t.Context(), timeout)
				defer cancelFunc()

				have, err := c.CheckResources(ctx, principal, resources)
				check(t, have, err)
			})

			t.Run("WithPrincipal", func(t *testing.T) {
				ctx, cancelFunc := context.WithTimeout(t.Context(), timeout)
				defer cancelFunc()

				have, err := c.WithPrincipal(principal).CheckResources(ctx, resources)
				check(t, have, err)
			})
		})

		t.Run("CheckResourcesOutput", func(t *testing.T) {
			principal := cerbos.NewPrincipal("john").
				WithRoles("employee").
				WithAttributes(map[string]any{
					"department": "marketing",
					"geography":  "GB",
					"team":       "design",
				})

			resources := cerbos.NewResourceBatch().Add(
				cerbos.NewResource("equipment_request", "XX125").
					WithScope("acme").
					WithAttributes(map[string]any{
						"department": "marketing",
						"geography":  "GB",
						"id":         "XX125",
						"owner":      "john",
						"team":       "design",
					}), "view:public", "approve", "create",
			)

			check := func(t *testing.T, have *cerbos.CheckResourcesResponse, err error) {
				t.Helper()
				require.NoError(t, err)

				haveXX125 := have.GetResource("XX125")
				require.NoError(t, haveXX125.Err())
				require.True(t, haveXX125.IsAllowed("view:public"))
				require.False(t, haveXX125.IsAllowed("approve"))
				require.True(t, haveXX125.IsAllowed("create"))
				require.Equal(t, "acme", haveXX125.Resource.Scope)

				wantStruct, err := structpb.NewStruct(map[string]any{
					"id":               "john",
					"keys":             "XX125",
					"formatted_string": "id:john",
					"some_bool":        true,
					"some_list":        []any{"foo", "bar"},
					"something_nested": map[string]any{
						"nested_str":              "foo",
						"nested_bool":             false,
						"nested_list":             []any{"nest_foo", 1.01},
						"nested_formatted_string": "id:john",
					},
				})
				require.NoError(t, err, "Failed to create wanted output")
				wantOutput1 := structpb.NewStructValue(wantStruct)
				haveOutput1 := haveXX125.Output("resource.equipment_request.vdefault#public-view")
				require.Empty(t, cmp.Diff(wantOutput1, haveOutput1, protocmp.Transform()))

				wantOutput2 := structpb.NewStringValue("create_allowed:john")
				haveOutput2 := haveXX125.Output("resource.equipment_request.vdefault/acme#rule-001")
				require.Empty(t, cmp.Diff(wantOutput2, haveOutput2, protocmp.Transform()))
			}

			t.Run("Direct", func(t *testing.T) {
				ctx, cancelFunc := context.WithTimeout(t.Context(), timeout)
				defer cancelFunc()

				have, err := c.CheckResources(ctx, principal, resources)
				check(t, have, err)
			})

			t.Run("WithPrincipal", func(t *testing.T) {
				ctx, cancelFunc := context.WithTimeout(t.Context(), timeout)
				defer cancelFunc()

				have, err := c.WithPrincipal(principal).CheckResources(ctx, resources)
				check(t, have, err)
			})
		})

		t.Run("IsAllowed", func(t *testing.T) {
			principal := cerbos.NewPrincipal("john").
				WithRoles("employee").
				WithPolicyVersion("20210210").
				WithAttributes(map[string]any{
					"department": "marketing",
					"geography":  "GB",
					"team":       "design",
				})

			resource := cerbos.NewResource("leave_request", "XX125").
				WithPolicyVersion("20210210").
				WithAttributes(map[string]any{
					"department": "marketing",
					"geography":  "GB",
					"id":         "XX125",
					"owner":      "john",
					"team":       "design",
				})

			t.Run("Direct", func(t *testing.T) {
				ctx, cancelFunc := context.WithTimeout(t.Context(), timeout)
				defer cancelFunc()

				have, err := c.IsAllowed(ctx, principal, resource, "defer")
				require.NoError(t, err)
				require.True(t, have)
			})

			t.Run("WithPrincipal", func(t *testing.T) {
				ctx, cancelFunc := context.WithTimeout(t.Context(), timeout)
				defer cancelFunc()

				have, err := c.WithPrincipal(principal).IsAllowed(ctx, resource, "defer")
				require.NoError(t, err)
				require.True(t, have)
			})
		})

		t.Run("PlanResources", func(t *testing.T) {
			principal := cerbos.NewPrincipal("maggie").
				WithRoles("manager").
				WithAttr("geography", "US").
				WithAttr("department", "marketing").
				WithAttr("team", "design").
				WithAttr("managed_geographies", "US").
				WithAttr("reader", false)

			resource := cerbos.NewResource("leave_request", "").
				WithPolicyVersion("20210210").
				WithAttr("geography", "US")

			cc := c.With(cerbos.IncludeMeta(true))

			check := func(t *testing.T, have *cerbos.PlanResourcesResponse, err error) {
				t.Helper()
				is := require.New(t)

				is.NoError(err)
				is.Equal(enginev1.PlanResourcesFilter_KIND_CONDITIONAL, have.Filter.Kind, "Expected conditional filter")
				expression := have.Filter.Condition.GetExpression()
				is.NotNil(expression)
				is.Equal("eq", expression.Operator)
				is.Equal("request.resource.attr.status", expression.Operands[0].GetVariable())
				is.Equal("PENDING_APPROVAL", expression.Operands[1].GetValue().GetStringValue())
				t.Log(have.Meta.FilterDebug)
			}

			t.Run("Direct", func(t *testing.T) {
				ctx, cancelFunc := context.WithTimeout(t.Context(), timeout)
				defer cancelFunc()

				have, err := cc.PlanResources(ctx, principal, resource, "approve")
				check(t, have, err)
			})

			t.Run("WithPrincipal", func(t *testing.T) {
				ctx, cancelFunc := context.WithTimeout(t.Context(), timeout)
				defer cancelFunc()

				have, err := cc.WithPrincipal(principal).PlanResources(ctx, resource, "approve")
				check(t, have, err)
			})
		})
	}
}

func generateToken(t *testing.T, expiry time.Time) string {
	t.Helper()

	token := jwt.New()
	require.NoError(t, token.Set(jwt.IssuerKey, "cerbos-test-suite"))
	require.NoError(t, token.Set(jwt.AudienceKey, "cerbos-jwt-tests"))
	require.NoError(t, token.Set(jwt.ExpirationKey, expiry))
	require.NoError(t, token.Set("customString", "foobar"))
	require.NoError(t, token.Set("customInt", 42)) //nolint:mnd
	require.NoError(t, token.Set("customArray", []string{"A", "B", "C"}))
	require.NoError(t, token.Set("customMap", map[string]any{"A": "AA", "B": "BB", "C": "CC"}))

	keyData, err := os.ReadFile(filepath.Join(test.PathToDir(t, "auxdata"), "signing_key.jwk"))
	require.NoError(t, err)

	keySet, err := jwk.ParseKey(keyData)
	require.NoError(t, err)

	tokenBytes, err := jwt.Sign(token, jwt.WithKey(jwa.ES384, keySet))
	require.NoError(t, err)

	return string(tokenBytes)
}
