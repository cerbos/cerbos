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

func (sbv SortByValue) String() string {
	return string(sbv)
}

type SortByFlagType SortByValue

func (kf SortByFlagType) Kind() SortByValue {
	return SortByValue(kf)
}

func (kf SortByFlagType) String() string {
	return SortByPolicyID.String()
}

func (kf *SortByFlagType) Set(v string) error {
	switch v {
	case SortByPolicyID.String(), SortByName.String(), SortByVersion.String():
		*kf = SortByFlagType(v)
		return nil
	default:
		return fmt.Errorf("invalid --sort-by value %q, possible values are %s, %s and %s", v, SortByPolicyID, SortByName, SortByVersion)
	}
}

func (kf SortByFlagType) Type() string {
	return "SortByFlag"
}
