package kafka

import (
	"errors"
	"strings"

	"github.com/cerbos/cerbos/internal/audit"
)

const confKey = audit.ConfKey + ".kafka"

// Conf is optional configuration for file Audit.
type Conf struct {
	// Path to the log file to use as output. The special values stdout and stderr can be used to write to stdout or stderr respectively.
	// Path string `yaml:"path" conf:",example=/path/to/file.log"`

	Brokers []string `yaml:"brokers" conf:",example=localhost:9092,localhost:9093"`

	Topic string `yaml:"topic" conf:",example=cerbos.audit.log"`

	Async bool `yaml:"sync" conf:",example=true"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {}

func (c *Conf) Validate() error {
	if len(c.Brokers) == 0 {
		return errors.New("empty brokers")
	}
	if strings.TrimSpace(c.Topic) == "" {
		return errors.New("invalid topic")
	}
	return nil
}
