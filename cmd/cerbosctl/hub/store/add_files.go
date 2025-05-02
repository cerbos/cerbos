// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import "github.com/alecthomas/kong"

type AddFilesCmd struct {
	Files []string `arg:"" help:"List of files to add to the store" required:""`
}

func (afc *AddFilesCmd) Run(k *kong.Kong, cmd *Cmd) error {
	// TODO: Implement
}
