// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build integration
// +build integration

package kafka_test

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/audit"
	_ "github.com/cerbos/cerbos/internal/audit/kafka"
	"github.com/cerbos/cerbos/internal/config"
)

const (
	redpandaImage   = "redpandadata/redpanda"
	redpandaVersion = "v23.1.5"

	defaultIntegrationTopic = "cerbos"
)

func TestSyncProduce(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// setup kafka
	uri := newKafkaBroker(t, defaultIntegrationTopic)
	log, err := newLog(map[string]any{
		"audit": map[string]any{
			"enabled": true,
			"backend": "kafka",
			"kafka": map[string]any{
				"brokers":     []string{uri},
				"topic":       defaultIntegrationTopic,
				"produceSync": true,
			},
		},
	})
	require.NoError(t, err)

	// write audit log entries
	err = log.WriteAccessLogEntry(ctx, func() (*auditv1.AccessLogEntry, error) {
		return &auditv1.AccessLogEntry{
			CallId: "01ARZ3NDEKTSV4RRFFQ69G5FA1",
		}, nil
	})
	require.NoError(t, err)

	err = log.WriteDecisionLogEntry(ctx, func() (*auditv1.DecisionLogEntry, error) {
		return &auditv1.DecisionLogEntry{
			CallId: "01ARZ3NDEKTSV4RRFFQ69G5FA2",
		}, nil
	})
	require.NoError(t, err)

	// validate we see this entries in kafka
	records, err := fetchKafkaTopic(uri, defaultIntegrationTopic)
	require.NoError(t, err)
	require.Len(t, records, 2, "unexpected number of published audit log entries")
}

func TestAsyncProduce(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// setup kafka
	uri := newKafkaBroker(t, defaultIntegrationTopic)
	log, err := newLog(map[string]any{
		"audit": map[string]any{
			"enabled": true,
			"backend": "kafka",
			"kafka": map[string]any{
				"brokers":     []string{uri},
				"topic":       defaultIntegrationTopic,
				"produceSync": false,
			},
		},
	})
	require.NoError(t, err)

	// write audit log entries
	err = log.WriteAccessLogEntry(ctx, func() (*auditv1.AccessLogEntry, error) {
		return &auditv1.AccessLogEntry{
			CallId: "01ARZ3NDEKTSV4RRFFQ69G5FA1",
		}, nil
	})
	require.NoError(t, err)

	err = log.WriteDecisionLogEntry(ctx, func() (*auditv1.DecisionLogEntry, error) {
		return &auditv1.DecisionLogEntry{
			CallId: "01ARZ3NDEKTSV4RRFFQ69G5FA2",
		}, nil
	})
	require.NoError(t, err)

	// validate we see this entries in kafka, eventually
	require.Eventually(t, func() bool {
		records, err := fetchKafkaTopic(uri, defaultIntegrationTopic)
		require.NoError(t, err)
		return len(records) == 2
	}, 10*time.Second, 100*time.Millisecond, "expected to see audit log entries in kafka")
}

func newKafkaBroker(t *testing.T, topic string) string {
	t.Helper()

	hostPort, err := freePort()
	require.NoError(t, err, "Unable to get free port")

	pool, err := dockertest.NewPool("")
	require.NoError(t, err, "Failed to connect to Docker")

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: redpandaImage,
		Tag:        redpandaVersion,
		Cmd: []string{
			"redpanda",
			"start",
			"--mode", "dev-container",
			"--advertise-kafka-addr", fmt.Sprintf("localhost:%d", hostPort),
		},
		ExposedPorts: []string{
			"9092/tcp",
		},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"9092/tcp": {{HostIP: "localhost", HostPort: strconv.Itoa(hostPort)}},
		},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
	})
	require.NoError(t, err, "Failed to start container")

	t.Cleanup(func() {
		_ = pool.Purge(resource)
	})

	brokerDSN := fmt.Sprintf("localhost:%d", hostPort)
	client, err := kgo.NewClient(kgo.SeedBrokers(brokerDSN))
	require.NoError(t, err)

	require.NoError(t, pool.Retry(func() error {
		return client.Ping(context.Background())
	}), "Failed to connect to Kafka")

	// create topic
	_, err = kadm.NewClient(client).CreateTopic(context.Background(), 1, 1, nil, topic)
	require.NoError(t, err, "Failed to create Kafka topic")

	return brokerDSN
}

func fetchKafkaTopic(uri, topic string) ([]*kgo.Record, error) {
	client, err := kgo.NewClient(kgo.SeedBrokers(uri))
	if err != nil {
		return nil, err
	}

	client.AddConsumeTopics(topic)

	fetches := client.PollFetches(context.Background())
	return fetches.Records(), fetches.Err()
}

func newLog(m map[string]any) (audit.Log, error) {
	cfg, err := config.WrapperFromMap(m)
	if err != nil {
		return nil, err
	}
	return audit.NewLogFromConf(context.Background(), cfg)
}

func freePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port, nil
}
