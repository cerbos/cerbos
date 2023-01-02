// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

type OutputFormat string

const (
	OutputFormatTree OutputFormat = "tree"
	OutputFormatList OutputFormat = "list"
	OutputFormatJSON OutputFormat = "json"
)
