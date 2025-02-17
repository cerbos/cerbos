// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package kafka_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/encoding/protojson"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/kafka"
)

var id = audit.ID("01ARZ3NDEKTSV4RRFFQ69G5FAV")

func TestWriteAccessLogEntry(t *testing.T) {
	t.Run("json encoded message", func(t *testing.T) {
		publisher, kafkaClient := newPublisher(t, kafka.Conf{
			Encoding: kafka.EncodingJSON,
		})

		err := publisher.WriteAccessLogEntry(t.Context(), func() (*auditv1.AccessLogEntry, error) {
			return &auditv1.AccessLogEntry{
				CallId: string(id),
			}, nil
		})
		require.NoError(t, err)

		expectPartitionKey(t, kafkaClient)
		expectKind(t, kafkaClient, kafka.KindAccess)
		expectJSON(t, kafkaClient)
	})

	t.Run("protobuf encoded message", func(t *testing.T) {
		publisher, kafkaClient := newPublisher(t, kafka.Conf{
			Encoding: kafka.EncodingProtobuf,
		})

		err := publisher.WriteAccessLogEntry(t.Context(), func() (*auditv1.AccessLogEntry, error) {
			return &auditv1.AccessLogEntry{
				CallId: string(id),
			}, nil
		})
		require.NoError(t, err)

		expectPartitionKey(t, kafkaClient)
		expectKind(t, kafkaClient, kafka.KindAccess)
		expectProtobuf(t, kafkaClient)
	})

	t.Run("sync message", func(t *testing.T) {
		publisher, kafkaClient := newPublisher(t, kafka.Conf{
			Encoding:    kafka.EncodingJSON,
			ProduceSync: true,
		})

		err := publisher.WriteAccessLogEntry(t.Context(), func() (*auditv1.AccessLogEntry, error) {
			return &auditv1.AccessLogEntry{
				CallId: string(id),
			}, nil
		})
		require.NoError(t, err)

		expectPartitionKey(t, kafkaClient)
		expectKind(t, kafkaClient, kafka.KindAccess)
		expectJSON(t, kafkaClient)
	})
}

func TestWriteDecisionLogEntry(t *testing.T) {
	t.Run("json encoded message", func(t *testing.T) {
		publisher, kafkaClient := newPublisher(t, kafka.Conf{
			Encoding: kafka.EncodingJSON,
		})

		err := publisher.WriteDecisionLogEntry(t.Context(), func() (*auditv1.DecisionLogEntry, error) {
			return &auditv1.DecisionLogEntry{
				CallId: string(id),
			}, nil
		})
		require.NoError(t, err)

		expectPartitionKey(t, kafkaClient)
		expectKind(t, kafkaClient, kafka.KindDecision)
		expectJSON(t, kafkaClient)
	})

	t.Run("protobuf encoded message", func(t *testing.T) {
		publisher, kafkaClient := newPublisher(t, kafka.Conf{
			Encoding: kafka.EncodingProtobuf,
		})

		err := publisher.WriteDecisionLogEntry(t.Context(), func() (*auditv1.DecisionLogEntry, error) {
			return &auditv1.DecisionLogEntry{
				CallId: string(id),
			}, nil
		})
		require.NoError(t, err)

		expectPartitionKey(t, kafkaClient)
		expectKind(t, kafkaClient, kafka.KindDecision)
		expectProtobuf(t, kafkaClient)
	})
}

func expectPartitionKey(t *testing.T, kafkaClient *mockClient) {
	t.Helper()

	expectedID, err := id.Repr()
	require.NoError(t, err)
	assert.Equal(t, expectedID.Bytes(), kafkaClient.Records[0].Key)
}

func expectKind(t *testing.T, kafkaClient *mockClient, kind []byte) {
	t.Helper()

	assert.Equal(t, kind, getHeader(kafkaClient.Records[0].Headers, kafka.HeaderKeyKind))
}

func expectJSON(t *testing.T, kafkaClient *mockClient) {
	t.Helper()

	// expected encoding
	assert.Equal(t, []byte(kafka.EncodingJSON), getHeader(kafkaClient.Records[0].Headers, kafka.HeaderKeyEncoding))

	// decode json
	var entry auditv1.AccessLogEntry
	err := protojson.Unmarshal(kafkaClient.Records[0].Value, &entry)
	require.NoError(t, err)
	assert.Equal(t, entry.CallId, string(id))
}

func expectProtobuf(t *testing.T, kafkaClient *mockClient) {
	t.Helper()

	// expected encoding
	assert.Equal(t, []byte(kafka.EncodingProtobuf), getHeader(kafkaClient.Records[0].Headers, kafka.HeaderKeyEncoding))

	// decode protobuf
	var entry auditv1.AccessLogEntry
	err := entry.UnmarshalVT(kafkaClient.Records[0].Value)
	require.NoError(t, err)
	assert.Equal(t, entry.CallId, string(id))
}

func newPublisher(t *testing.T, cfg kafka.Conf) (*kafka.Publisher, *mockClient) {
	t.Helper()

	config := &kafka.Conf{}
	config.SetDefaults()
	config.Brokers = []string{"localhost:9092"}
	config.Encoding = cfg.Encoding
	config.ProduceSync = cfg.ProduceSync

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	publisher, err := kafka.NewPublisher(ctx, config, nil)
	require.NoError(t, err)

	kafkaClient := &mockClient{}
	publisher.Client = kafkaClient

	return publisher, kafkaClient
}

func getHeader(headers []kgo.RecordHeader, key string) []byte {
	for _, h := range headers {
		if h.Key == key {
			return h.Value
		}
	}
	return nil
}

type mockClient struct {
	Records []*kgo.Record
}

func (m *mockClient) Reset() {
	m.Records = nil
}

func (m *mockClient) Close() {}

func (m *mockClient) Flush(_ context.Context) error {
	return nil
}

func (m *mockClient) TryProduce(_ context.Context, record *kgo.Record, _ func(*kgo.Record, error)) {
	m.Records = append(m.Records, record)
}

func (m *mockClient) ProduceSync(_ context.Context, records ...*kgo.Record) kgo.ProduceResults {
	m.Records = append(m.Records, records...)
	return kgo.ProduceResults{}
}
