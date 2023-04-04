// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

type OutputFormat string

const (
	OutputFormatTree OutputFormat = "tree"
	OutputFormatList OutputFormat = "list"
	OutputFormatJSON OutputFormat = "json"
)

type VerificationOutputFormat string

const (
	VerificationOutputFormatTree  VerificationOutputFormat = "tree"
	VerificationOutputFormatList  VerificationOutputFormat = "list"
	VerificationOutputFormatJSON  VerificationOutputFormat = "json"
	VerificationOutputFormatJUnit VerificationOutputFormat = "junit"
)
