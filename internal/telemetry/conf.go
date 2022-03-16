// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package telemetry

const confKey = "telemetry"

// Conf for telemetry reporting.
type Conf struct {
	// Disabled switches off telemetry reporting.
	Disabled bool `yaml:"disabled" conf:",example=false"`
	// StateDir sets the directory for persisting state. Defaults to user config directory of the OS.
	StateDir string `yaml:"stateDir" conf:",example=${HOME}/.config/cerbos"`
}

func (c *Conf) Key() string {
	return confKey
}
