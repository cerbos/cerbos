// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/twmb/franz-go/pkg/kgo"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/config"
)

const Backend = "kafka"

func init() {
	audit.RegisterBackend(Backend, func(ctx context.Context, confW *config.Wrapper, decisionFilter audit.DecisionLogEntryFilter) (audit.Log, error) {
		conf := new(Conf)
		if err := confW.GetSection(conf); err != nil {
			return nil, fmt.Errorf("failed to read kafka audit log configuration: %w", err)
		}

		return NewPublisher(conf, decisionFilter)
	})
}

type Publisher struct {
	decisionFilter audit.DecisionLogEntryFilter
	client         *kgo.Client
	async          bool
}

func NewPublisher(conf *Conf, decisionFilter audit.DecisionLogEntryFilter) (*Publisher, error) {
	client, err := kgo.NewClient(
		kgo.SeedBrokers(conf.Brokers...),
		kgo.DefaultProduceTopic(conf.Topic),

		// kgo.BrokerMaxWriteBytes(100),
	)
	if err != nil {
		return nil, err
	}

	return &Publisher{
		decisionFilter: decisionFilter,
		client:         client,
		async:          conf.Async,
	}, nil
}

func (p *Publisher) Close() {
	p.client.Close()
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

	value, err := rec.MarshalVT()
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	callID, err := audit.ID(rec.CallId).Repr()
	if err != nil {
		return fmt.Errorf("invalid call ID: %w", err)
	}

	// Write to Kafka
	msg := &kgo.Record{
		Key:   callID.Bytes(),
		Value: value,
	}

	if !p.async {
		// Wait for acknowledgement message has been written
		return p.client.ProduceSync(ctx, msg).FirstErr()
	}

	// Async gives us improved performance, at the cost of potentially loosing messages
	p.client.Produce(ctx, msg, func(r *kgo.Record, err error) {
		if err != nil {
			// TODO: Metrics
			// TODO: Convert `WriteAccessLogEntry` to take err channel??
			ctxzap.Extract(ctx).Warn("Failed to write access log entry", zap.Error(err))
		}
	})
	return nil
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

	value, err := rec.MarshalVT()
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	callID, err := audit.ID(rec.CallId).Repr()
	if err != nil {
		return fmt.Errorf("invalid call ID: %w", err)
	}

	// Write to Kafka
	msg := &kgo.Record{
		Key:   callID.Bytes(),
		Value: value,
	}

	if !p.async {
		// Wait for acknowledgement message has been written
		return p.client.ProduceSync(ctx, msg).FirstErr()
	}

	// Async gives us improved performance, at the cost of potentially loosing messages
	p.client.Produce(ctx, msg, func(r *kgo.Record, err error) {
		if err != nil {
			// TODO: Metrics
			// TODO: Convert `WriteAccessLogEntry` to take err channel??
			ctxzap.Extract(ctx).Warn("Failed to write decision log entry", zap.Error(err))
		}
	})
	return nil
}
