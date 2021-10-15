// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"fmt"
	"runtime/debug"
	"strings"
)

var (
	AppName   = "cerbos"
	BuildDate = "unknown"
	Commit    = "unknown"
	Version   = "unknown"
)

func AppVersion() string {
	var sb strings.Builder
	_, _ = sb.WriteString(Version)
	_, _ = sb.WriteString(fmt.Sprintf("\nBuilt on %s from %s\n", BuildDate, Commit))

	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Sum != "" {
		_, _ = sb.WriteString(fmt.Sprintf("Module version: %s, Module checksum: %s\n", info.Main.Version, info.Main.Sum))
	}

	return sb.String()
}
