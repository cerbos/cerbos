package engine

import (
	"errors"
	"strings"

	"github.com/cerbos/cerbos/internal/namer"
)

const confKey = "engine"

var errEmptyDefaultVersion = errors.New("engine.defaultVersion must not be an empty string")

type Conf struct {
	DefaultPolicyVersion      string `yaml:"defaultPolicyVersion"`
	IncludeMetadataInResponse bool   `yaml:"includeMetadataInResponse"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.DefaultPolicyVersion = namer.DefaultVersion
	c.IncludeMetadataInResponse = true
}

func (c *Conf) Validate() error {
	if strings.TrimSpace(c.DefaultPolicyVersion) == "" {
		return errEmptyDefaultVersion
	}

	return nil
}
