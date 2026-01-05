// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package storage

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/cerbos/cerbos/internal/config"
)

const ConfKey = "storage"

// Conf is required configuration for storage.
// +desc=This section is required. The field driver must be set to indicate which driver to use.
type Conf struct {
	confHolder
}

// confHolder exists to avoid a recursive loop in the UnmarshalYAML method below.
type confHolder struct {
	// Driver defines which storage driver to use.
	Driver string `yaml:"driver" conf:"required,example=\"disk\""`
}

func (c *Conf) Key() string {
	return ConfKey
}

func (c *Conf) UnmarshalYAML(unmarshal func(any) error) error {
	// We want to avoid defining all the storage driver configuration structs as fields of the Conf
	// struct to maintain the "plugin" nature of those drivers (and avoid circular package references).
	// However, the strict YAML parser throws an error if it sees undefined fields. This is a slightly
	// inefficient workaround to get over that issue.

	var confMap map[string]any
	if err := unmarshal(&confMap); err != nil {
		return fmt.Errorf("failed to unmarshal storage config: %w", err)
	}

	yamlBytes, err := yaml.Marshal(confMap)
	if err != nil {
		return fmt.Errorf("failed to marshal storage config [%v]: %w", confMap, err)
	}

	c.confHolder = confHolder{}
	return yaml.Unmarshal(yamlBytes, &c.confHolder)
}

func GetConf() (*Conf, error) {
	conf := &Conf{}
	err := config.GetSection(conf)

	return conf, err
}
