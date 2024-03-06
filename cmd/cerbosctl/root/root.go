// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package root

import (
	"github.com/cerbos/cerbos/cmd/cerbosctl/audit"
	"github.com/cerbos/cerbos/cmd/cerbosctl/decisions"
	"github.com/cerbos/cerbos/cmd/cerbosctl/del"
	"github.com/cerbos/cerbos/cmd/cerbosctl/disable"
	"github.com/cerbos/cerbos/cmd/cerbosctl/enable"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/put"
	"github.com/cerbos/cerbos/cmd/cerbosctl/store"
	"github.com/cerbos/cerbos/cmd/cerbosctl/version"
)

type Cli struct {
	Get get.Cmd `cmd:"" help:"List or view policies and schemas"`
	flagset.Globals
	Store     store.Cmd     `cmd:"" help:"Store operations"`
	Delete    del.Cmd       `cmd:"" help:"Delete schemas"`
	Disable   disable.Cmd   `cmd:"" help:"Disable policies"`
	Enable    enable.Cmd    `cmd:"" help:"Enable policies"`
	Put       put.Cmd       `cmd:"" help:"Put policies or schemas"`
	Decisions decisions.Cmd `cmd:"" help:"Interactive decision log viewer"`
	Audit     audit.Cmd     `cmd:"" help:"View audit logs"`
	Version   version.Cmd   `cmd:"" help:"Show cerbosctl and PDP version"`
}
