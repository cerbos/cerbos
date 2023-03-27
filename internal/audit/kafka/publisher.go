// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/plugin/kzap"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/config"
)

const Backend = "kafka"

const (
	AckNone   = "none"
	AckAll    = "all"
	AckLeader = "leader"

	EncodingJSON     = "json"
	EncodingProtobuf = "protobuf"

	HeaderKeyEncoding = "cerbos.audit.encoding"
	HeaderKeyKind     = "cerbos.audit.kind"

	KindAccess   = "access"
	KindDecision = "decision"
)

func init() {
	audit.RegisterBackend(Backend, func(ctx context.Context, confW *config.Wrapper, decisionFilter audit.DecisionLogEntryFilter) (audit.Log, error) {
		conf := new(Conf)
		if err := confW.GetSection(conf); err != nil {
			return nil, fmt.Errorf("failed to read kafka audit log configuration: %w", err)
		}

		return NewPublisher(conf, decisionFilter)
	})
}

type Client interface {
	Close()
	Flush(context.Context) error
	Produce(context.Context, *kgo.Record, func(*kgo.Record, error))
	ProduceSync(context.Context, ...*kgo.Record) kgo.ProduceResults
}

type Publisher struct {
	Client         Client
	decisionFilter audit.DecisionLogEntryFilter
	marshaller     recordMarshaller
	sync           bool
	flushTimeout   time.Duration
}

func NewPublisher(conf *Conf, decisionFilter audit.DecisionLogEntryFilter) (*Publisher, error) {
	clientOpts := []kgo.Opt{
		kgo.ClientID(conf.ClientID),
		kgo.SeedBrokers(conf.Brokers...),
		kgo.DefaultProduceTopic(conf.Topic),
		kgo.MaxBufferedRecords(conf.MaxBufferedLogs),
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

	client, err := kgo.NewClient(clientOpts...)
	if err != nil {
		return nil, err
	}

	return &Publisher{
		Client:         client,
		decisionFilter: decisionFilter,
		marshaller:     recordMarshaller{Encoding: conf.Encoding},
		sync:           conf.ProduceSync,
		flushTimeout:   conf.FlushTimeout,
	}, nil
}

func (p *Publisher) Close() {
	flushCtx, flushCancel := context.WithTimeout(context.Background(), p.flushTimeout)
	defer flushCancel()
	// TODO: Change log.Close to return an error & then log
	_ = p.Client.Flush(flushCtx)

	p.Client.Close()
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

	msg, err := p.marshaller.MarshalAccessLogEntry(rec)
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

	msg, err := p.marshaller.MarshalDecisionLogEntry(rec)
	if err != nil {
		return err
	}

	return p.write(ctx, msg)
}

func (p *Publisher) write(ctx context.Context, msg *kgo.Record) error {
	if p.sync {
		return p.Client.ProduceSync(ctx, msg).FirstErr()
	}

	p.Client.Produce(ctx, msg, func(r *kgo.Record, err error) {
		if err != nil {
			// TODO: Handle via interceptor
			ctxzap.Extract(ctx).Warn("failed to write audit log entry", zap.Error(err))
		}
	})
	return nil
}

type recordMarshaller struct {
	Encoding string
}

func (m recordMarshaller) MarshalAccessLogEntry(rec *auditv1.AccessLogEntry) (*kgo.Record, error) {
	callID, err := audit.ID(rec.CallId).Repr()
	if err != nil {
		return nil, fmt.Errorf("invalid call ID: %w", err)
	}

	var payload []byte
	switch m.Encoding {
	default:
		return nil, fmt.Errorf("invalid encoding format: %s", m.Encoding)
	case EncodingJSON:
		payload, err = protojson.Marshal(rec)
	case EncodingProtobuf:
		payload, err = rec.MarshalVT()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to marshal entry: %w", err)
	}

	return &kgo.Record{
		Key:   callID.Bytes(),
		Value: payload,
		Headers: []kgo.RecordHeader{
			{
				Key:   HeaderKeyEncoding,
				Value: []byte(m.Encoding),
			},
			{
				Key:   HeaderKeyKind,
				Value: []byte(KindAccess),
			},
		},
	}, nil
}

func (m recordMarshaller) MarshalDecisionLogEntry(rec *auditv1.DecisionLogEntry) (*kgo.Record, error) {
	callID, err := audit.ID(rec.CallId).Repr()
	if err != nil {
		return nil, fmt.Errorf("invalid call ID: %w", err)
	}

	var payload []byte
	switch m.Encoding {
	default:
		return nil, fmt.Errorf("invalid encoding format: %s", m.Encoding)
	case EncodingJSON:
		payload, err = protojson.Marshal(rec)
	case EncodingProtobuf:
		payload, err = rec.MarshalVT()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to marshal entry: %w", err)
	}

	return &kgo.Record{
		Key:   callID.Bytes(),
		Value: payload,
		Headers: []kgo.RecordHeader{
			{
				Key:   HeaderKeyEncoding,
				Value: []byte(m.Encoding),
			},
			{
				Key:   HeaderKeyKind,
				Value: []byte(KindDecision),
			},
		},
	}, nil
}
