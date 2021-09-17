// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"

	"gopkg.in/yaml.v2"
)

const (
	ConfKey = "audit"
)

type Conf struct {
	confHolder
}

type confHolder struct {
	Enabled             bool   `yaml:"enabled"`
	Backend             string `yaml:"backend"`
	AccessLogsEnabled   bool   `yaml:"accessLogsEnabled"`
	DecisionLogsEnabled bool   `yaml:"decisionLogsEnabled"`
}

func (c *Conf) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// This is a workaround to circumvent strict config parsing.
	// Consider the following:
	//
	// audit:
	//   enabled: true
	//   backend: local
	//   local:
	//     storageDirectory: /var/cerbos
	//
	// Because the config for the "local" backend is nested under the "audit" key, we will
	// need to have "local" defined as a field in the Conf struct when strict parsing is on.
	// However, backends are self-contained plugins and it is not practical to add a new field
	// definition to the audit config struct for each plugin we introduce.
	// This hack is slightly inefficient because it marshals and unmarshals YAML twice. It is an
	// acceptable sacrifice to make because config is only read once on startup.

	var confMap map[string]interface{}
	if err := unmarshal(&confMap); err != nil {
		return fmt.Errorf("failed to unmarshal audit config: %w", err)
	}

	yamlBytes, err := yaml.Marshal(confMap)
	if err != nil {
		return fmt.Errorf("failed to marshal audit config [%v]: %w", confMap, err)
	}

	c.confHolder = confHolder{}
	return yaml.Unmarshal(yamlBytes, &c.confHolder)
}

func (c *Conf) Key() string {
	return ConfKey
}

func (c *Conf) SetDefaults() {
	c.AccessLogsEnabled = true
	c.DecisionLogsEnabled = true
}
