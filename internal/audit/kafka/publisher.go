// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/plugin/kzap"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/metrics"

	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/config"
)

const Backend = "kafka"

const (
	AckNone   = "none"
	AckAll    = "all"
	AckLeader = "leader"

	HeaderKeyEncoding = "cerbos.audit.encoding"
	HeaderKeyKind     = "cerbos.audit.kind"

	CompressionNone   = "none"
	CompressionGzip   = "gzip"
	CompressionSnappy = "snappy"
	CompressionLZ4    = "lz4"
	CompressionZstd   = "zstd"
)

type Encoding string

const (
	EncodingJSON     Encoding = "json"
	EncodingProtobuf Encoding = "protobuf"
)

type Kind []byte

var (
	// reallocate once ahead of time to avoid allocations in the hot path.
	KindAccess   Kind = []byte(audit.KindAccess)
	KindDecision Kind = []byte(audit.KindDecision)
)

func init() {
	audit.RegisterBackend(Backend, func(ctx context.Context, confW *config.Wrapper, decisionFilter audit.DecisionLogEntryFilter) (audit.Log, error) {
		conf := new(Conf)
		if err := confW.GetSection(conf); err != nil {
			return nil, fmt.Errorf("failed to read kafka audit log configuration: %w", err)
		}

		return NewPublisher(ctx, conf, decisionFilter)
	})
}

type Client interface {
	Close()
	Flush(context.Context) error
	TryProduce(context.Context, *kgo.Record, func(*kgo.Record, error))
	ProduceSync(context.Context, ...*kgo.Record) kgo.ProduceResults
}

type Publisher struct {
	Client         Client
	decisionFilter audit.DecisionLogEntryFilter
	marshaller     recordMarshaller
	sync           bool
	closeTimeout   time.Duration
}

func NewPublisher(ctx context.Context, conf *Conf, decisionFilter audit.DecisionLogEntryFilter) (*Publisher, error) {
	clientOpts := []kgo.Opt{
		kgo.ClientID(conf.ClientID),
		kgo.SeedBrokers(conf.Brokers...),
		kgo.DefaultProduceTopic(conf.Topic),
		kgo.MaxBufferedRecords(conf.MaxBufferedRecords),
	}

	if _, ok := os.LookupEnv("CERBOS_DEBUG_KAFKA"); ok {
		clientOpts = append(clientOpts, kgo.WithLogger(
			kzap.New(zap.L().Named("kafka"), kzap.Level(kgo.LogLevelDebug)),
		))
	}

	ack, err := formatAck(conf.Ack)
	if err != nil {
		return nil, err
	}
	clientOpts = append(clientOpts, kgo.RequiredAcks(ack))
	if conf.Ack != AckAll {
		clientOpts = append(clientOpts, kgo.DisableIdempotentWrite())
	}

	compression, err := formatCompression(conf.Compression)
	if err != nil {
		return nil, err
	}

	clientOpts = append(clientOpts, kgo.ProducerBatchCompression(compression...))

	if conf.Authentication.TLS != nil {
		tlsConfig, err := NewTLSConfig(ctx,
			conf.Authentication.TLS.ReloadInterval,
			conf.Authentication.TLS.InsecureSkipVerify,
			conf.Authentication.TLS.CAPath,
			conf.Authentication.TLS.CertPath,
			conf.Authentication.TLS.KeyPath)
		if err != nil {
			return nil, err
		}

		clientOpts = append(clientOpts, kgo.DialTLSConfig(tlsConfig))
	}

	client, err := kgo.NewClient(clientOpts...)
	if err != nil {
		return nil, err
	}

	return &Publisher{
		Client:         client,
		decisionFilter: decisionFilter,
		marshaller:     newMarshaller(conf.Encoding),
		sync:           conf.ProduceSync,
		closeTimeout:   conf.CloseTimeout,
	}, nil
}

func (p *Publisher) Close() error {
	flushCtx, flushCancel := context.WithTimeout(context.Background(), p.closeTimeout)
	defer flushCancel()
	if err := p.Client.Flush(flushCtx); err != nil {
		return err
	}

	p.Client.Close()
	return nil
}

func (p *Publisher) Backend() string {
	return Backend
}

func (p *Publisher) Enabled() bool {
	return true
}

func (p *Publisher) WriteAccessLogEntry(ctx context.Context, record audit.AccessLogEntryMaker) error {
	rec, err := record()
	if err != nil {
		return err
	}

	msg, err := p.marshaller.Marshal(rec, KindAccess)
	if err != nil {
		return err
	}

	return p.write(ctx, msg)
}

func (p *Publisher) WriteDecisionLogEntry(ctx context.Context, record audit.DecisionLogEntryMaker) error {
	rec, err := record()
	if err != nil {
		return err
	}

	if p.decisionFilter != nil {
		rec = p.decisionFilter(rec)
		if rec == nil {
			return nil
		}
	}

	msg, err := p.marshaller.Marshal(rec, KindDecision)
	if err != nil {
		return err
	}

	return p.write(ctx, msg)
}

func (p *Publisher) write(ctx context.Context, msg *kgo.Record) error {
	if p.sync {
		return p.Client.ProduceSync(ctx, msg).FirstErr()
	}

	// detach the context from the caller so the request can return
	// without cancelling any async kafka operations
	ctx = context.WithoutCancel(ctx)

	p.Client.TryProduce(ctx, msg, func(r *kgo.Record, err error) {
		if err == nil {
			return
		}

		// TODO: Currently have to duplicate logWrapper as it does not support async audit publishing.
		logging.FromContext(ctx).Warn("failed to write audit log entry", zap.Error(err))

		// Due to async nature of this callback, we need to pull the `kind` out of the header
		var kind string
		for _, h := range r.Headers {
			if h.Key == HeaderKeyKind {
				kind = string(h.Value)
				break
			}
		}

		metrics.Inc(ctx, metrics.AuditErrorCount(), metrics.KindKey(kind))
	})
	return nil
}

func newMarshaller(enc Encoding) recordMarshaller {
	return recordMarshaller{
		encoding:    enc,
		encodingKey: []byte(enc),
	}
}

type recordMarshaller struct {
	encoding    Encoding
	encodingKey []byte
}

type auditEntry interface {
	proto.Message
	GetCallId() string
	MarshalVT() ([]byte, error)
}

func (m recordMarshaller) Marshal(entry auditEntry, kind Kind) (*kgo.Record, error) {
	partitionKey, err := audit.ID(entry.GetCallId()).Repr()
	if err != nil {
		return nil, fmt.Errorf("invalid call ID: %w", err)
	}

	var payload []byte
	switch m.encoding {
	default:
		return nil, fmt.Errorf("invalid encoding format: %s", m.encoding)
	case EncodingJSON:
		payload, err = protojson.Marshal(entry)
	case EncodingProtobuf:
		payload, err = entry.MarshalVT()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to marshal entry: %w", err)
	}

	return &kgo.Record{
		Key:   partitionKey.Bytes(),
		Value: payload,
		Headers: []kgo.RecordHeader{
			{
				Key:   HeaderKeyEncoding,
				Value: m.encodingKey,
			},
			{
				Key:   HeaderKeyKind,
				Value: kind,
			},
		},
	}, nil
}
