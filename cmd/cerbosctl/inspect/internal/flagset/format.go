// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

type Format struct {
	Output    OutputFormat `short:"o" default:"" help:"Output format for inspection results; json, yaml, prettyjson formats are supported"`
	NoHeaders bool         `help:"Do not output headers"`
}

type OutputFormat string

const (
	OutputFormatNone       OutputFormat = ""
	OutputFormatJSON       OutputFormat = "json"
	OutputFormatYAML       OutputFormat = "yaml"
	OutputFormatPrettyJSON OutputFormat = "prettyjson"
)
