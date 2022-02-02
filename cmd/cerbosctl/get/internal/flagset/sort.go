// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

import (
	"fmt"

	"github.com/spf13/pflag"
)

const SortByFlag = "sort-by"

type Sort struct {
	SortBy SortByFlagType
}

func (s *Sort) FlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("sort", pflag.ExitOnError)
	fs.Var(&s.SortBy, SortByFlag, "Sort policies by column")
	return fs
}

type SortByValue string

const (
	SortByPolicyID SortByValue = "policyId"
	SortByName     SortByValue = "name"
	SortByVersion  SortByValue = "version"
)

type SortByFlagType SortByValue

func (sbft SortByFlagType) Kind() SortByValue {
	return SortByValue(sbft)
}

func (sbft SortByFlagType) String() string {
	return string(SortByPolicyID)
}

func (sbft *SortByFlagType) Set(v string) error {
	switch SortByValue(v) {
	case SortByPolicyID, SortByName, SortByVersion:
		*sbft = SortByFlagType(v)
		return nil
	default:
		return fmt.Errorf("invalid --sort-by value %q, possible values are %s, %s and %s", v, SortByPolicyID, SortByName, SortByVersion)
	}
}

func (sbft SortByFlagType) Type() string {
	return "SortByFlag"
}
