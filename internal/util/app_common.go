// Copyright 2021-2026 Zenauth Ltd.
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

	appID = []byte(AppName)
)

const nodeIDLen = 16

func AppVersion() string {
	var sb strings.Builder
	_, _ = sb.WriteString(Version)
	_, _ = fmt.Fprintf(&sb, "\nBuild timestamp: %s\n", BuildDate)
	_, _ = fmt.Fprintf(&sb, "Build commit: %s\n", Commit)

	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Sum != "" {
			_, _ = fmt.Fprintf(&sb, "Module version: %s, Module checksum: %s\n", info.Main.Version, info.Main.Sum)
		}

		_, _ = fmt.Fprintf(&sb, "Go version: %s\n", info.GoVersion)
		for _, bs := range info.Settings {
			if strings.HasPrefix(bs.Key, "vcs") {
				_, _ = fmt.Fprintf(&sb, "%s: %s\n", bs.Key, bs.Value)
			}
		}
	}

	return sb.String()
}

func AppShortVersion() string {
	var sb strings.Builder
	_, _ = sb.WriteString(Version)

	if info, ok := debug.ReadBuildInfo(); ok {
		for _, bs := range info.Settings {
			if bs.Key == "vcs.revision" {
				_, _ = sb.WriteString("-")
				_, _ = sb.WriteString(bs.Value)
			}
		}
	}

	return sb.String()
}
