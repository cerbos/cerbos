// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

import (
	"fmt"
)

type Format struct {
	Output    OutputFormat `short:"o" default:"" help:"Output format for the policies; json, yaml, prettyjson formats are supported"`
	NoHeaders bool         `help:"Do not output headers"`
}

func (f Format) Validate(listing bool) error {
	if !listing && f.NoHeaders {
		return fmt.Errorf("--no-headers flag is only available when listing")
	}

	if listing && f.Output != OutputFormatNone {
		return fmt.Errorf("--output flag is only available when retrieving a specific policy")
	}

	return nil
}

type OutputFormat string

const (
	OutputFormatNone       OutputFormat = ""
	OutputFormatJSON       OutputFormat = "json"
	OutputFormatYAML       OutputFormat = "yaml"
	OutputFormatPrettyJSON OutputFormat = "prettyjson"
)
