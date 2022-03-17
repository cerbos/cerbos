// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package testutil_test

import (
	"context"
	"fmt"
	"log"

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/client/testutil"
)

//nolint:gocritic,errcheck
func ExampleStartCerbosServer() {
	s, err := testutil.StartCerbosServer()
	if err != nil {
		log.Fatalf("Failed to start Cerbos server: %v", err)
	}

	defer s.Stop()

	c, err := client.New(s.GRPCAddr(), client.WithPlaintext())
	if err != nil {
		log.Fatalf("Failed to create Cerbos client: %v", err)
	}

	resp, err := c.CheckResourceSet(
		context.TODO(),
		client.NewPrincipal("john").
			WithRoles("employee", "manager").
			WithAttr("department", "marketing").
			WithAttr("geography", "GB"),
		client.NewResourceSet("leave_request").
			AddResourceInstance("XX125", map[string]interface{}{
				"department": "marketing",
				"geography":  "GB",
				"owner":      "harry",
				"status":     "DRAFT",
			}),
		"view", "approve")
	if err != nil {
		log.Fatalf("API request failed: %v", err)
	}

	fmt.Println(resp.IsAllowed("XX125", "view"))
	// Output: false
}
