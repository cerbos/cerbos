// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"log"

	"github.com/cerbos/cerbos/client"
)

func ExampleNew() {
	// A client that connects to Cerbos over a Unix domain socket using a CA certificate to validate the server TLS certificates.
	c, err := client.New("unix:/var/sock/cerbos", client.WithTLSCACert("/path/to/ca.crt"))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	allowed, err := c.IsAllowed(
		context.TODO(),
		client.NewPrincipal("sally").WithRoles("user"),
		client.NewResource("album:object", "A001"),
		"view",
	)
	if err != nil {
		log.Fatalf("Failed to check permission: %v", err)
	}

	log.Printf("Is Sally allowed to view album A001: %t", allowed)
}

func ExampleNewAdminClient() {
	// Create an admin client using the credentials stored in environment variables or netrc.
	ac, err := client.NewAdminClient("10.1.2.3:3593", client.WithTLSCACert("/path/to/ca.crt"))
	if err != nil {
		log.Fatalf("Failed to create admin client: %v", err)
	}

	policy := client.NewResourcePolicy("album:comments", "default").
		WithDerivedRolesImports("album_derived_roles").
		AddResourceRules(
			client.NewAllowResourceRule("view").
				WithDerivedRoles("owners").
				WithCondition(
					client.MatchAllOf(
						client.MatchExpr(`request.resource.attr.status == "unmoderated"`),
						client.MatchExpr(`request.resource.attr.user_status == "anonymous"`),
					),
				),
		)

	if err := ac.AddOrUpdatePolicy(context.TODO(), client.NewPolicySet().AddResourcePolicies(policy)); err != nil {
		log.Fatalf("Failed to add policy: %v", err)
	}
}

func ExampleClient_CheckResources() {
	c, err := client.New("dns:///cerbos.ns.svc.cluster.local:3593", client.WithTLSCACert("/path/to/ca.crt"))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	cc := c.WithPrincipal(client.NewPrincipal("john").
		WithRoles("employee").
		WithPolicyVersion("20210210").
		WithAttributes(map[string]any{
			"department": "marketing",
			"geography":  "GB",
			"team":       "design",
		}))

	resources := client.NewResourceBatch().
		Add(client.
			NewResource("leave_request", "XX125").
			WithPolicyVersion("20210210").
			WithAttributes(map[string]any{
				"department": "marketing",
				"geography":  "GB",
				"id":         "XX125",
				"owner":      "john",
				"team":       "design",
			}), "view:public", "defer").
		Add(client.
			NewResource("leave_request", "XX225").
			WithPolicyVersion("20210210").
			WithAttributes(map[string]any{
				"department": "engineering",
				"geography":  "GB",
				"id":         "XX225",
				"owner":      "mary",
				"team":       "frontend",
			}), "approve")

	ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
	defer cancelFunc()

	result, err := cc.CheckResources(ctx, resources)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}

	resXX125 := result.GetResource("XX125", client.MatchResourcePolicyVersion("20210210"))
	if resXX125.IsAllowed("view:public") {
		log.Println("Action view:public is allowed on resource XX125")
	}
}
