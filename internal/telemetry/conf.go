// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package telemetry

const confKey = "telemetry"

// Conf for telemetry reporting.
type Conf struct {
	// StateDir is used to persist state to avoid repeatedly sending the data over and over again.
	StateDir string `yaml:"stateDir" conf:",example=${HOME}/.config/cerbos"`
	// Disabled sets whether telemetry collection is disabled or not.
	Disabled bool `yaml:"disabled" conf:",example=false"`
}

func (c *Conf) Key() string {
	return confKey
}
