// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

type OutputFormat string

const (
	OutputFormatTree   OutputFormat = "tree"
	OutputFormatPretty OutputFormat = "pretty"
	OutputFormatJSON   OutputFormat = "json"
)
