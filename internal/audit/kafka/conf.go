// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cerbos/cerbos/internal/audit"
	"github.com/twmb/franz-go/pkg/kgo"
)

const confKey = audit.ConfKey + ".kafka"

const (
	defaultAcknowledgement = AckAll
	defaultEncoding        = EncodingJSON
	defaultFlushTimeout    = 30 * time.Second
	defaultClientID        = "cerbos"
	defaultMaxBufferedLogs = 250
)

// Conf is optional configuration for kafka Audit.
type Conf struct {
	// Required acknowledgement for messages, accepts none, leader or the default all. Idempotency disabled when not all
	Ack string `yaml:"ack" conf:",example=all"`
	// Name of the topic audit entries are written to
	Topic string `yaml:"topic" conf:",example=cerbos.audit.log"`
	// Data format written to Kafka, accepts either json (default) or protobuf
	Encoding Encoding `yaml:"encoding" conf:",example=protobuf"`
	// Identifier sent with all requests to Kafka
	ClientID string `yaml:"clientID" conf:",example=cerbos"`
	// Seed brokers Kafka client will connect to
	Brokers []string `yaml:"brokers" conf:",example=['localhost:9092']"`
	// Timeout for flushing messages to Kafka
	FlushTimeout time.Duration `yaml:"flushTimeout" conf:",example=30s"`
	// MaxBufferedLogs sets the max amount of logs the client will buffer before blocking
	MaxBufferedLogs int `yaml:"maxBufferedLogs" conf:",example=1000"`
	// Increase reliability by stopping asynchronous publishing at the cost of reduced performance
	ProduceSync bool `yaml:"produceSync" conf:",example=true"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.Ack = defaultAcknowledgement
	c.Encoding = defaultEncoding
	c.FlushTimeout = defaultFlushTimeout
	c.ClientID = defaultClientID
	c.MaxBufferedLogs = defaultMaxBufferedLogs
}

func (c *Conf) Validate() error {
	switch c.Ack {
	case AckNone, AckAll, AckLeader:
	default:
		return fmt.Errorf("invalid ack value: %s", c.Ack)
	}

	if _, err := formatAck(c.Ack); err != nil {
		return err
	}

	if strings.TrimSpace(c.Topic) == "" {
		return errors.New("invalid topic")
	}

	switch c.Encoding {
	case EncodingJSON, EncodingProtobuf:
	default:
		return fmt.Errorf("invalid encoding format: %s", c.Encoding)
	}

	if c.FlushTimeout <= 0 {
		return errors.New("invalid flush timeout")
	}

	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("invalid client ID")
	}

	if len(c.Brokers) == 0 {
		return errors.New("empty brokers")
	}

	return nil
}

func formatAck(ack string) (kgo.Acks, error) {
	switch ack {
	case AckNone:
		return kgo.NoAck(), nil
	case AckAll:
		return kgo.AllISRAcks(), nil
	case AckLeader:
		return kgo.LeaderAck(), nil
	default:
		return kgo.NoAck(), fmt.Errorf("invalid ack value: %s", ack)
	}
}
