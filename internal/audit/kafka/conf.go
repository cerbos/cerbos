// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cerbos/cerbos/internal/audit"
)

const confKey = audit.ConfKey + ".kafka"

// Conf is optional configuration for kafka Audit.
type Conf struct {
	// Name of the topic audit entries are written to
	Topic string `yaml:"topic" conf:",example=cerbos.audit.log"`
	// Data format written to Kafka, accepts either json (default) or protobuf
	Encoding string `yaml:"format" conf:",example=protobuf"`
	// Timeout for flushing messages to Kafka
	FlushTimeout string `yaml:"flushTimeout" conf:",example=30s"`
	// Identifier sent with all requests to Kafka
	ClientID string `yaml:"clientID" conf:",example=cerbos"`
	// Seed brokers Kafka client will connect to
	Brokers []string `yaml:"brokers" conf:",example=['localhost:9092', 'localhost:9093']"`
	// Increase reliability by stopping asynchronous publishing at the cost of reduced performance
	ProduceSync bool `yaml:"produceSync" conf:",example=true"`
	// MaxBufferedLogs sets the max amount of logs the client will buffer before blocking
	MaxBufferedLogs int `yaml:"maxBufferedLogs" conf:",example=1000"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.Encoding = EncodingJSON
	c.FlushTimeout = "30s"
	c.ClientID = "cerbos"
	c.MaxBufferedLogs = 250
}

func (c *Conf) Validate() error {
	if strings.TrimSpace(c.Topic) == "" {
		return errors.New("invalid topic")
	}

	switch c.Encoding {
	case EncodingJSON, EncodingProtobuf:
	default:
		return fmt.Errorf("invalid encoding format: %s", c.Encoding)
	}

	if _, err := time.ParseDuration(c.FlushTimeout); err != nil {
		return fmt.Errorf("invalid flush timeout: %w", err)
	}

	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("invalid client ID")
	}

	if len(c.Brokers) == 0 {
		return errors.New("empty brokers")
	}

	return nil
}
