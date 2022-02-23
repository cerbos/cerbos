// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"errors"
	"fmt"

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/flagset"
)

var errInvalidCredentials = errors.New("invalid credentials: username and password must be non-empty strings")

type Context struct {
	Client      client.Client
	AdminClient client.AdminClient
}

func GetAdminClient(globals *flagset.Globals) (client.AdminClient, error) {
	if globals.Username == "" || globals.Password == "" {
		return nil, errInvalidCredentials
	}

	opts := globals.ToClientOpts()

	ac, err := client.NewAdminClientWithCredentials(globals.Server, globals.Username, globals.Password, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create the admin client: %w", err)
	}

	return ac, nil
}

func GetClient(globals *flagset.Globals) (client.Client, error) {
	opts := globals.ToClientOpts()

	c, err := client.New(globals.Server, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create the client: %w", err)
	}

	return c, nil
}
