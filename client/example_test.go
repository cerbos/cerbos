// Copyright 2021 Zenauth Ltd.
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
