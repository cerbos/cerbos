// Copyright 2021 Zenauth Ltd.

package audit

const (
	ConfKey = "audit"
)

type Conf struct {
	Enabled             bool   `yaml:"enabled"`
	Backend             string `yaml:"backend"`
	AccessLogsEnabled   bool   `yaml:"accessLogsEnabled"`
	DecisionLogsEnabled bool   `yaml:"decisionLogsEnabled"`
}

func (c *Conf) Key() string {
	return ConfKey
}

func (c *Conf) SetDefaults() {
	c.AccessLogsEnabled = true
	c.DecisionLogsEnabled = true
}
