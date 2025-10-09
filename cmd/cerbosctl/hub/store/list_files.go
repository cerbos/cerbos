// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/alecthomas/kong"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
	storev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/store/v1"
)

const listFilesHelp = `
# List all files

cerbosctl hub store list-files

# List files matching "resource"

cerbosctl hub store list-files --filter=contains:resource
`

type ListFilesCmd struct { //betteralign:ignore
	Output `embed:""`
	Filter string `name:"filter" optional:"" help:"Optional file name filter in the form <operator>:<value>. Supported operators are 'eq', 'in' and 'contains'. For 'in' multiple values can be provided as a comma separated list."`
}

func (*ListFilesCmd) Help() string {
	return listFilesHelp
}

func (lfc *ListFilesCmd) Run(k *kong.Kong, cmd *Cmd) error {
	client, err := cmd.storeClient()
	if err != nil {
		return lfc.toCommandError(k.Stderr, err)
	}

	req := hub.NewListFilesRequest(cmd.StoreID)
	if lfc.Filter != "" {
		kind, value, ok := strings.Cut(lfc.Filter, ":")
		if !ok {
			return lfc.toCommandError(k.Stderr, fmt.Errorf("invalid filter expression: %q", lfc.Filter))
		}

		switch strings.ToLower(kind) {
		case "eq":
			req.WithFileFilter(hub.FilterPathEqual(value))
		case "contains":
			req.WithFileFilter(hub.FilterPathContains(value))
		case "in":
			values := strings.Split(value, ",")
			req.WithFileFilter(hub.FilterPathIn(values...))
		default:
			return lfc.toCommandError(k.Stderr, fmt.Errorf("unknown filter kind: %q", kind))
		}
	}

	resp, err := client.ListFiles(context.Background(), req)
	if err != nil {
		return lfc.toCommandError(k.Stderr, err)
	}

	if len(resp.GetFiles()) == 0 {
		return nil
	}

	lfc.format(k.Stdout, listFilesOutput{ListFilesResponse: resp.ListFilesResponse})
	return nil
}

type listFilesOutput struct {
	*storev1.ListFilesResponse
}

func (lfo listFilesOutput) String() string {
	sb := new(strings.Builder)
	for _, f := range lfo.GetFiles() {
		sb.WriteString(f)
		sb.WriteString("\n")
	}

	return sb.String()
}

func (lfo listFilesOutput) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(lfo.ListFilesResponse)
}
