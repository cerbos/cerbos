// Copyright 2021-2024 Zenauth Ltd.
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
	defaultAcknowledgement    = AckAll
	defaultEncoding           = EncodingJSON
	defaultCloseTimeout       = 30 * time.Second
	defaultClientID           = "cerbos"
	defaultMaxBufferedRecords = 250
)

type Authentication struct {
	TLS *TLS `yaml:"tls"`
}

type TLS struct {
	// CAPath is the path to the CA certificate.
	CAPath string `yaml:"caPath" conf:"required,example=/path/to/ca.crt"`
	// CertPath is the path to the client certificate.
	CertPath string `yaml:"certPath" conf:",example=/path/to/tls.cert"`
	// KeyPath is the path to the client key.
	KeyPath string `yaml:"keyPath" conf:",example=/path/to/tls.key"`
	// ReloadInterval is the interval at which the TLS certificates are reloaded. The default is 0 (no reload).
	ReloadInterval time.Duration `yaml:"reloadInterval" conf:",example=5m"`
	// InsecureSkipVerify controls whether the server's certificate chain and host name are verified. Default is false.
	InsecureSkipVerify bool `yaml:"insecureSkipVerify" conf:",example=true"`
}

// Conf is optional configuration for kafka Audit.
type Conf struct {
	// Ack mode for producing messages. Valid values are "none", "leader" or "all" (default). Idempotency is disabled when mode is not "all".
	Ack string `yaml:"ack" conf:",example=all"`
	// Authentication
	Authentication Authentication `yaml:"authentication"`
	// Topic to write audit entries to.
	Topic string `yaml:"topic" conf:"required,example=cerbos.audit.log"`
	// Encoding format. Valid values are "json" (default) or "protobuf".
	Encoding Encoding `yaml:"encoding" conf:",example=json"`
	// ClientID reported in Kafka connections.
	ClientID string `yaml:"clientID" conf:",example=cerbos"`
	// Brokers list to seed the Kafka client.
	Brokers []string `yaml:"brokers" conf:"required,example=['localhost:9092']"`
	// Compression sets the compression algorithm to use in order of priority. Valid values are "none", "gzip", "snappy","lz4", "zstd". Default is ["snappy", "none"].
	Compression []string `yaml:"compression" conf:",example=['snappy', 'none']"`
	// CloseTimeout sets how long when closing the client to wait for any remaining messages to be flushed.
	CloseTimeout time.Duration `yaml:"closeTimeout" conf:",example=30s"`
	// MaxBufferedRecords sets the maximum number of records the client should buffer in memory in async mode.
	MaxBufferedRecords int `yaml:"maxBufferedRecords" conf:",example=1000"`
	// ProduceSync forces the client to produce messages to Kafka synchronously. This can have a significant impact on performance.
	ProduceSync bool `yaml:"produceSync" conf:",example=false"`
}

func (c *Conf) Key() string {
	return confKey
}

func (c *Conf) SetDefaults() {
	c.Ack = defaultAcknowledgement
	c.Encoding = defaultEncoding
	c.CloseTimeout = defaultCloseTimeout
	c.ClientID = defaultClientID
	c.MaxBufferedRecords = defaultMaxBufferedRecords
	c.Compression = []string{CompressionSnappy, CompressionNone}
}

func (c *Conf) Validate() error {
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

	if c.CloseTimeout <= 0 {
		return errors.New("invalid close timeout")
	}

	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("invalid client ID")
	}

	if len(c.Brokers) == 0 {
		return errors.New("empty brokers")
	}

	_, err := formatCompression(c.Compression)
	if err != nil {
		return err
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

func formatCompression(compression []string) ([]kgo.CompressionCodec, error) {
	codecs := make([]kgo.CompressionCodec, 0, len(compression))

	for _, c := range compression {
		switch c {
		case CompressionNone:
			codecs = append(codecs, kgo.NoCompression())
		case CompressionGzip:
			codecs = append(codecs, kgo.GzipCompression())
		case CompressionSnappy:
			codecs = append(codecs, kgo.SnappyCompression())
		case CompressionLZ4:
			codecs = append(codecs, kgo.Lz4Compression())
		case CompressionZstd:
			codecs = append(codecs, kgo.ZstdCompression())
		default:
			return nil, fmt.Errorf("invalid compression algorithm: %s", compression)
		}
	}

	return codecs, nil
}
