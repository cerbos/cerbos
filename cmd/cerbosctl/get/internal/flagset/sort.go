// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

import "github.com/spf13/pflag"

type SortByValue string

const (
	SortByPolicyID SortByValue = "policyId"
	SortByName     SortByValue = "name"
	SortByVersion  SortByValue = "version"
)

func (sbv SortByValue) String() string {
	return string(sbv)
}

const SortByFlag = "sort-by"

type Sort struct {
	SortBy string
}

func (s *Sort) FlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("sort", pflag.ExitOnError)
	fs.StringVar(&s.SortBy, SortByFlag, SortByPolicyID.String(), "Sort policies by column")
	return fs
}
