// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/cerbos/cerbos/internal/config"
)

const (
	ConfKey = "audit"
)

// Conf is optional configuration for Audit.
type Conf struct {
	confHolder
}

type confHolder struct {
	// Backend states which backend to use for Audits.
	Backend string `yaml:"backend" conf:",example=local"`
	// IncludeMetadataKeys defines which gRPC request metadata keys should be included in the audit logs.
	IncludeMetadataKeys []string `yaml:"includeMetadataKeys" conf:",example=['content-type']"`
	// ExcludeMetadataKeys defines which gRPC request metadata keys should be excluded from the audit logs. Takes precedence over includeMetadataKeys.
	ExcludeMetadataKeys []string `yaml:"excludeMetadataKeys" conf:",example=['authorization']"`
	// Enabled defines whether audit logging is enabled.
	Enabled bool `yaml:"enabled" conf:",example=false"`
	// AccessLogsEnabled defines whether access logging is enabled.
	AccessLogsEnabled bool `yaml:"accessLogsEnabled" conf:",example=false"`
	// DecisionLogsEnabled defines whether logging of policy decisions is enabled.
	DecisionLogsEnabled bool `yaml:"decisionLogsEnabled" conf:",example=false"`
	// DecisionLogFilters define the filters to apply while producing decision logs.
	DecisionLogFilters DecisionLogFilters `yaml:"decisionLogFilters"`
}

type DecisionLogFilters struct {
	// CheckResources defines the filters that apply to CheckResources calls.
	CheckResources CheckResourcesFilter `yaml:"checkResources"`
	// PlanResources defines the filters that apply to PlanResources calls.
	PlanResources PlanResourcesFilter `yaml:"planResources"`
}

type CheckResourcesFilter struct {
	// IgnoreAllowAll ignores responses that don't contain an EFFECT_DENY.
	IgnoreAllowAll bool `yaml:"ignoreAllowAll" conf:",example=false"`
}

type PlanResourcesFilter struct {
	// IgnoreAll prevents any plan responses from being logged. Takes precedence over other filters.
	IgnoreAll bool `yaml:"ignoreAll" conf:",example=false"`
	// IgnoreAlwaysAllow ignores ALWAYS_ALLOWED plans.
	IgnoreAlwaysAllow bool `yaml:"ignoreAlwaysAllow" conf:",example=false"`
}

func (c *Conf) UnmarshalYAML(unmarshal func(any) error) error {
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

	var confMap map[string]any
	if err := unmarshal(&confMap); err != nil {
		return fmt.Errorf("failed to unmarshal audit config: %w", err)
	}

	yamlBytes, err := yaml.Marshal(confMap)
	if err != nil {
		return fmt.Errorf("failed to marshal audit config [%v]: %w", confMap, err)
	}

	c.confHolder = confHolder{AccessLogsEnabled: true, DecisionLogsEnabled: true}
	return yaml.Unmarshal(yamlBytes, &c.confHolder)
}

func (c *Conf) Key() string {
	return ConfKey
}

func (c *Conf) SetDefaults() {
	c.AccessLogsEnabled = true
	c.DecisionLogsEnabled = true
}

func GetConf() (*Conf, error) {
	conf := &Conf{}
	err := config.GetSection(conf)

	return conf, err
}
