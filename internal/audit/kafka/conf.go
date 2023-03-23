// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cerbos/cerbos/internal/audit"
)

const confKey = audit.ConfKey + ".kafka"

const (
	EncodingJSON     = "json"
	EncodingProtobuf = "protobuf"
)

// Conf is optional configuration for kafka Audit.
type Conf struct {
	// Seed brokers Kafka client will connect to
	Brokers []string `yaml:"brokers" conf:",example=localhost:9092,localhost:9093"`
	// Name of the topic audit entries are written to
	Topic string `yaml:"topic" conf:",example=cerbos.audit.log"`
	// Data format written to Kafka, accepts either json (default) or protobuf
	Encoding string `yaml:"format" conf:",example=protobuf"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.Encoding = EncodingJSON
}

func (c *Conf) Validate() error {
	if len(c.Brokers) == 0 {
		return errors.New("empty brokers")
	}

	if strings.TrimSpace(c.Topic) == "" {
		return errors.New("invalid topic")
	}

	switch c.Encoding {
	case EncodingJSON, EncodingProtobuf:
	default:
		return fmt.Errorf("invalid encoding format: %s", c.Encoding)
	}

	return nil
}
