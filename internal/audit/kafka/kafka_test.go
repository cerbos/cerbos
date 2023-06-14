// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build integration
// +build integration

package kafka_test

import (
	"context"
	"fmt"
	"path/filepath"
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
	"github.com/cerbos/cerbos/internal/util"
)

const (
	redpandaImage   = "redpandadata/redpanda"
	redpandaVersion = "v23.1.5"

	defaultIntegrationTopic = "cerbos"
)

func TestProduceWithTLS(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// setup kafka
	uri := newKafkaBrokerWithTLS(t, defaultIntegrationTopic, "testdata/valid/ca.crt", "testdata/valid/client/tls.crt", "testdata/valid/client/tls.key")
	log, err := newLog(map[string]any{
		"audit": map[string]any{
			"enabled": true,
			"backend": "kafka",
			"kafka": map[string]any{
				"authentication": map[string]any{
					"tls": map[string]any{
						"caPath":   "testdata/valid/ca.crt",
						"certPath": "testdata/valid/client/tls.crt",
						"keyPath":  "testdata/valid/client/tls.key",
					},
				},
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
	records, err := fetchKafkaTopic(uri, defaultIntegrationTopic, true)
	require.NoError(t, err)
	require.Len(t, records, 2, "unexpected number of published audit log entries")
}

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
	records, err := fetchKafkaTopic(uri, defaultIntegrationTopic, false)
	require.NoError(t, err)
	require.Len(t, records, 2, "unexpected number of published audit log entries")
}

func TestCompression(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// setup kafka
	uri := newKafkaBroker(t, defaultIntegrationTopic)

	for _, compression := range []string{"none", "gzip", "snappy", "lz4", "zstd"} {
		log, err := newLog(map[string]any{
			"audit": map[string]any{
				"enabled": true,
				"backend": "kafka",
				"kafka": map[string]any{
					"brokers":     []string{uri},
					"topic":       defaultIntegrationTopic,
					"produceSync": true,
					"compression": []string{compression},
				},
			},
		})
		require.NoError(t, err)

		// write audit log entries
		callId, err := audit.NewID()
		require.NoError(t, err)

		err = log.WriteAccessLogEntry(ctx, func() (*auditv1.AccessLogEntry, error) {
			return &auditv1.AccessLogEntry{
				CallId: string(callId),
			}, nil
		})
		require.NoError(t, err)
	}

	// validate we see these entries in kafka
	records, err := fetchKafkaTopic(uri, defaultIntegrationTopic)
	require.NoError(t, err)
	require.Len(t, records, 5, "unexpected number of published audit log entries")
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
		records, err := fetchKafkaTopic(uri, defaultIntegrationTopic, false)
		require.NoError(t, err)
		return len(records) == 2
	}, 10*time.Second, 100*time.Millisecond, "expected to see audit log entries in kafka")
}

func newKafkaBrokerWithTLS(t *testing.T, topic, caPath, certPath, keyPath string) string {
	t.Helper()

	testDataAbsPath, err := filepath.Abs("testdata/valid")
	require.NoError(t, err)

	pool, err := dockertest.NewPool("")
	require.NoError(t, err, "Failed to connect to Docker")

	hostPort := 65136

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: redpandaImage,
		Tag:        redpandaVersion,
		Cmd: []string{
			"redpanda",
			"start",
			"--mode", "dev-container",
			// kafka admin client will retrieve the advertised address from the broker
			// so we need it to use the same port that is exposed on the container
			"--config", "/etc/redpanda/rpconfig.yaml",
			"--advertise-kafka-addr", fmt.Sprintf("localhost:%d", hostPort),
		},
		ExposedPorts: []string{
			"9092/tcp",
		},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"9092/tcp": {{HostIP: "localhost", HostPort: strconv.Itoa(hostPort)}},
		},
		Mounts: []string{
			fmt.Sprintf("%s:/etc/redpanda", testDataAbsPath),
		},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
	})
	require.NoError(t, err, "Failed to start container")

	t.Cleanup(func() {
		_ = pool.Purge(resource)
	})

	brokerDSN := fmt.Sprintf("localhost:%d", hostPort)
	tlsConfig, err := kafka.NewTLSConfig(caPath, certPath, keyPath)
	require.NoError(t, err)
	client, err := kgo.NewClient(kgo.SeedBrokers(brokerDSN), kgo.DialTLSConfig(tlsConfig))
	require.NoError(t, err)

	require.NoError(t, pool.Retry(func() error {
		return client.Ping(context.Background())
	}), "Failed to connect to Kafka")
	// create topic
	_, err = kadm.NewClient(client).CreateTopic(context.Background(), 1, 1, nil, topic)
	require.NoError(t, err, "Failed to create Kafka topic")

	return brokerDSN
}

func newKafkaBroker(t *testing.T, topic string) string {
	t.Helper()

	hostPort, err := util.GetFreePort()
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
			// kafka admin client will retrieve the advertised address from the broker
			// so we need it to use the same port that is exposed on the container
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

func fetchKafkaTopic(uri string, topic string, tlsEnabled bool) ([]*kgo.Record, error) {
	kgoOptions := []kgo.Opt{kgo.SeedBrokers(uri)}
	if tlsEnabled {
		tlsConfig, err := kafka.NewTLSConfig("testdata/valid/ca.crt", "testdata/valid/client/tls.crt", "testdata/valid/client/tls.key")
		if err != nil {
			return nil, err
		}

		kgoOptions = append(kgoOptions, kgo.DialTLSConfig(tlsConfig))
	}

	client, err := kgo.NewClient(kgoOptions...)
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
