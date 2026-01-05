// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

import "fmt"

type OutputFormat string

const (
	OutputFormatTree OutputFormat = "tree"
	OutputFormatList OutputFormat = "list"
	OutputFormatJSON OutputFormat = "json"
)

type VerificationOutputFormat string

func (v *VerificationOutputFormat) Validate() error {
	if *v != "tree" && *v != "list" && *v != "json" && *v != "junit" {
		return fmt.Errorf("valid options are tree, list, json or junit")
	}

	return nil
}

const (
	VerificationOutputFormatTree  VerificationOutputFormat = "tree"
	VerificationOutputFormatList  VerificationOutputFormat = "list"
	VerificationOutputFormatJSON  VerificationOutputFormat = "json"
	VerificationOutputFormatJUnit VerificationOutputFormat = "junit"
)
