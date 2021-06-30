// Copyright 2021 Zenauth Ltd.

package engine

import (
	"errors"
	"runtime"
	"strings"

	"github.com/cerbos/cerbos/internal/namer"
)

const confKey = "engine"

var errEmptyDefaultVersion = errors.New("engine.defaultVersion must not be an empty string")

type Conf struct {
	DefaultPolicyVersion string `yaml:"defaultPolicyVersion"`
	NumWorkers           uint   `yaml:"numWorkers"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.DefaultPolicyVersion = namer.DefaultVersion
	c.NumWorkers = uint(runtime.NumCPU() + 4) //nolint:gomnd
}

func (c *Conf) Validate() error {
	if strings.TrimSpace(c.DefaultPolicyVersion) == "" {
		return errEmptyDefaultVersion
	}

	return nil
}
