// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package telemetry

const confKey = "telemetry"

// Conf for telemetry reporting.
type Conf struct {
	StateDir string `yaml:"stateDir" conf:",example=${HOME}/.config/cerbos"`
	Disabled bool   `yaml:"disabled" conf:",example=false"`
}

func (c *Conf) Key() string {
	return confKey
}
