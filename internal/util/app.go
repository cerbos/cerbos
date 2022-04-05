// Copyright 2021-2022 Zenauth Ltd.
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
	_, _ = sb.WriteString(fmt.Sprintf("\nBuild timestamp: %s\n", BuildDate))
	_, _ = sb.WriteString(fmt.Sprintf("Build commit: %s\n", Commit))

	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Sum != "" {
			_, _ = sb.WriteString(fmt.Sprintf("Module version: %s, Module checksum: %s\n", info.Main.Version, info.Main.Sum))
		}

		_, _ = sb.WriteString(fmt.Sprintf("Go version: %s\n", info.GoVersion))
		for _, bs := range info.Settings {
			if strings.HasPrefix(bs.Key, "vcs") {
				_, _ = sb.WriteString(fmt.Sprintf("%s: %s\n", bs.Key, bs.Value))
			}
		}
	}

	return sb.String()
}
