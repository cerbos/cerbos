// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

import "github.com/spf13/pflag"

type Filters struct {
	Name    []string
	Version []string
}

func (f *Filters) FlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("filters", pflag.ExitOnError)
	fs.StringSliceVar(&f.Name, "name", []string{}, "Filter policies by name")
	fs.StringSliceVar(&f.Version, "version", []string{}, "Filter policies by version")
	return fs
}
