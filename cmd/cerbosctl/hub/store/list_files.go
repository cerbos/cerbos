// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/cerbos/cerbos-sdk-go/cerbos/hub"
	storev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/store/v1"
)

type ListFilesCmd struct {
	Output `embed:""`
	Filter string `name:"filter" optional:"" help:"Optional file name filter in the form <operator>:<value>. Supported operators are 'eq', 'in' and 'like'. For 'in' multiple values can be provided as a comma separated list."`
}

func (lfc *ListFilesCmd) Run(k *kong.Kong, cmd *Cmd) error {
	client, err := cmd.storeClient()
	if err != nil {
		return err
	}

	req := hub.NewListFilesRequest(cmd.StoreID)
	if lfc.Filter != "" {
		kind, value, ok := strings.Cut(lfc.Filter, ":")
		if !ok {
			return fmt.Errorf("invalid filter expression: %q", lfc.Filter)
		}

		switch strings.ToLower(kind) {
		case "eq":
			req.WithFileFilter(hub.FilterPathEqual(value))
		case "like":
			req.WithFileFilter(hub.FilterPathLike(value))
		case "in":
			values := strings.Split(value, ",")
			req.WithFileFilter(hub.FilterPathIn(values...))
		default:
			return fmt.Errorf("unknown filter kind: %q", kind)
		}
	}

	resp, err := client.ListFiles(context.Background(), req)
	if err != nil {
		return err
	}

	output := formatOutput(lfc.Output.Format, resp.ListFilesResponse, func(v *storev1.ListFilesResponse) string {
		buf := new(bytes.Buffer)
		fmt.Fprintf(buf, "Version: %d\n", v.GetStoreVersion())
		for _, f := range v.GetFiles() {
			fmt.Fprintln(buf, f)
		}

		return buf.String()
	})
	fmt.Fprintln(k.Stdout, output)

	return nil
}
