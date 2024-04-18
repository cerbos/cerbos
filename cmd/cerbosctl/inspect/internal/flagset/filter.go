// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

type Filters struct {
	NameRegexp      string `help:"Filter policies by name, using regular expression"`
	VersionRegexp   string `help:"Filter policies by version, using regular expression"`
	ScopeRegexp     string `help:"Filter policies by scope, using regular expression"`
	IncludeDisabled bool   `help:"Include disabled policies"`
}
