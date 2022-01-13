// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

import "github.com/spf13/pflag"

type Format struct {
	Output    string
	NoHeaders bool
}

func (f *Format) FlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("format", pflag.ExitOnError)
	fs.BoolVar(&f.NoHeaders, "no-headers", false, "Do not output headers")
	fs.StringVarP(&f.Output, "output", "o", "yaml", "Output format for the policies; json, yaml, prettyjson formats are supported")
	return fs
}
