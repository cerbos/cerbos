// Copyright 2021-2023 Zenauth Ltd.
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
		publisher, kafkaClient := newPublisher(t, kafka.EncodingJSON)

		err := publisher.WriteAccessLogEntry(context.Background(), func() (*auditv1.AccessLogEntry, error) {
			return &auditv1.AccessLogEntry{
				CallId: string(id),
			}, nil
		})
		require.NoError(t, err)

		expectPartitionKey(t, kafkaClient)
		expectJSON(t, kafkaClient)
	})

	t.Run("protobuf encoded message", func(t *testing.T) {
		publisher, kafkaClient := newPublisher(t, kafka.EncodingProtobuf)

		err := publisher.WriteAccessLogEntry(context.Background(), func() (*auditv1.AccessLogEntry, error) {
			return &auditv1.AccessLogEntry{
				CallId: string(id),
			}, nil
		})
		require.NoError(t, err)

		expectPartitionKey(t, kafkaClient)
		expectProtobuf(t, kafkaClient)
	})
}

func TestWriteDecisionLogEntry(t *testing.T) {
	t.Run("json encoded message", func(t *testing.T) {
		publisher, kafkaClient := newPublisher(t, kafka.EncodingJSON)

		err := publisher.WriteDecisionLogEntry(context.Background(), func() (*auditv1.DecisionLogEntry, error) {
			return &auditv1.DecisionLogEntry{
				CallId: string(id),
			}, nil
		})
		require.NoError(t, err)

		expectPartitionKey(t, kafkaClient)
		expectJSON(t, kafkaClient)
	})

	t.Run("protobuf encoded message", func(t *testing.T) {
		publisher, kafkaClient := newPublisher(t, kafka.EncodingProtobuf)

		err := publisher.WriteAccessLogEntry(context.Background(), func() (*auditv1.AccessLogEntry, error) {
			return &auditv1.AccessLogEntry{
				CallId: string(id),
			}, nil
		})
		require.NoError(t, err)

		expectPartitionKey(t, kafkaClient)
		expectProtobuf(t, kafkaClient)
	})
}

func expectPartitionKey(t *testing.T, kafkaClient *mockClient) {
	expectedID, err := id.Repr()
	require.NoError(t, err)
	assert.Equal(t, expectedID.Bytes(), kafkaClient.Records[0].Key)
}

func expectJSON(t *testing.T, kafkaClient *mockClient) {
	// expected encoding
	assert.Len(t, kafkaClient.Records[0].Headers, 1)
	assert.Equal(t, []byte(kafka.EncodingJSON), kafkaClient.Records[0].Headers[0].Value)

	// decode json
	var entry auditv1.AccessLogEntry
	err := protojson.Unmarshal(kafkaClient.Records[0].Value, &entry)
	require.NoError(t, err)
	assert.Equal(t, entry.CallId, string(id))
}

func expectProtobuf(t *testing.T, kafkaClient *mockClient) {
	// expected encoding
	assert.Len(t, kafkaClient.Records[0].Headers, 1)
	assert.Equal(t, []byte(kafka.EncodingProtobuf), kafkaClient.Records[0].Headers[0].Value)

	// decode protobuf
	var entry auditv1.AccessLogEntry
	err := entry.UnmarshalVT(kafkaClient.Records[0].Value)
	require.NoError(t, err)
	assert.Equal(t, entry.CallId, string(id))
}

func newPublisher(t *testing.T, encoding string) (*kafka.Publisher, *mockClient) {
	publisher, err := kafka.NewPublisher(&kafka.Conf{
		Brokers:  []string{"localhost:9092"},
		Encoding: encoding,
	}, nil)
	require.NoError(t, err)

	kafkaClient := &mockClient{}
	publisher.Client = kafkaClient

	return publisher, kafkaClient
}

type mockClient struct {
	Records []*kgo.Record
}

func (m *mockClient) Reset() {
	m.Records = nil
}

func (m *mockClient) Close() {}

func (m *mockClient) Produce(_ context.Context, record *kgo.Record, _ func(*kgo.Record, error)) {
	m.Records = append(m.Records, record)
}
