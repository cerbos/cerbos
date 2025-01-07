// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"errors"
	"fmt"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/flagset"
)

var errInvalidCredentials = errors.New("invalid credentials: username and password must be non-empty strings")

type Context struct {
	Client      *cerbos.GRPCClient
	AdminClient *cerbos.GRPCAdminClient
}

func GetAdminClient(globals *flagset.Globals) (*cerbos.GRPCAdminClient, error) {
	if globals.Username == "" || globals.Password == "" {
		return nil, errInvalidCredentials
	}

	opts := globals.ToClientOpts()

	ac, err := cerbos.NewAdminClientWithCredentials("passthrough:///"+globals.Server, globals.Username, globals.Password, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create the admin client: %w", err)
	}

	return ac, nil
}

func GetClient(globals *flagset.Globals) (*cerbos.GRPCClient, error) {
	opts := globals.ToClientOpts()

	c, err := cerbos.New("passthrough:///"+globals.Server, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create the client: %w", err)
	}

	return c, nil
}
