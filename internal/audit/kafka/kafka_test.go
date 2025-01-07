// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build integration
// +build integration

package kafka_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
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
	"github.com/cerbos/cerbos/internal/audit/kafka"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	redpandaImage   = "redpandadata/redpanda"
	redpandaVersion = "v23.2.15"

	defaultIntegrationTopic = "cerbos"
	maxWait                 = 60 * time.Second
)

func TestProduceWithTLS(t *testing.T) {
	ctx := context.Background()

	// setup kafka
	uri := newKafkaBrokerWithTLS(t, defaultIntegrationTopic, "testdata/valid/certs/ca.crt", "testdata/valid/client/tls.crt", "testdata/valid/client/tls.key")
	log, err := newLog(map[string]any{
		"audit": map[string]any{
			"enabled": true,
			"backend": "kafka",
			"kafka": map[string]any{
				"authentication": map[string]any{
					"tls": map[string]any{
						"caPath":         "testdata/valid/certs/ca.crt",
						"certPath":       "testdata/valid/client/tls.crt",
						"keyPath":        "testdata/valid/client/tls.key",
						"reloadInterval": "10s",
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
	require.NoError(t, log.Close())

	// validate we see this entries in kafka
	records, err := fetchKafkaTopic(t, uri, defaultIntegrationTopic, true)
	require.NoError(t, err)
	require.Len(t, records, 2, "unexpected number of published audit log entries")
}

func TestSyncProduce(t *testing.T) {
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
	require.NoError(t, log.Close())

	// validate we see this entries in kafka
	records, err := fetchKafkaTopic(t, uri, defaultIntegrationTopic, false)
	require.NoError(t, err)
	require.Len(t, records, 2, "unexpected number of published audit log entries")
}

func TestCompression(t *testing.T) {
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
		require.NoError(t, log.Close())
	}

	// validate we see these entries in kafka
	records, err := fetchKafkaTopic(t, uri, defaultIntegrationTopic, false)
	require.NoError(t, err)
	require.Len(t, records, 5, "unexpected number of published audit log entries")
}

func TestAsyncProduce(t *testing.T) {
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
	require.NoError(t, log.Close())

	// validate we see this entries in kafka, eventually
	require.Eventually(t, func() bool {
		records, err := fetchKafkaTopic(t, uri, defaultIntegrationTopic, false)
		require.NoError(t, err)
		return len(records) == 2
	}, 10*time.Second, 100*time.Millisecond, "expected to see audit log entries in kafka")
}

func newKafkaBrokerWithTLS(t *testing.T, topic, caPath, certPath, keyPath string) string {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	duration := 10 * time.Second
	skipVerify := false
	tlsConfig, err := kafka.NewTLSConfig(ctx, duration, skipVerify, caPath, certPath, keyPath)
	require.NoError(t, err)

	return startKafkaBroker(t, topic, tlsConfig)
}

func newKafkaBroker(t *testing.T, topic string) string {
	t.Helper()

	return startKafkaBroker(t, topic, nil)
}

func startKafkaBroker(t *testing.T, topic string, tlsConfig *tls.Config) string {
	t.Helper()

	port, err := util.GetFreePort()
	require.NoError(t, err, "Failed to find free address")

	testDataAbsPath, err := filepath.Abs("testdata/valid")
	require.NoError(t, err)

	cfg := test.RenderTemplate(t, filepath.Join(testDataAbsPath, "redpanda", "redpanda.yaml.gotmpl"), struct {
		TLSEnabled bool
		Port       int
	}{
		TLSEnabled: tlsConfig != nil,
		Port:       port,
	})
	t.Logf("Config:\n%s\n", string(cfg))

	tempDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "redpanda.yaml"), cfg, 0o644))

	pool, err := dockertest.NewPool("")
	require.NoError(t, err, "Failed to connect to Docker")
	pool.MaxWait = maxWait

	runOpts := &dockertest.RunOptions{
		Repository: redpandaImage,
		Tag:        redpandaVersion,
		Entrypoint: []string{"/opt/redpanda/bin/redpanda"},
		Cmd: []string{
			"--redpanda-cfg",
			"/etc/redpanda/redpanda.yaml",
			"--unsafe-bypass-fsync=true",
			"--reserve-memory=0M",
			"--overprovisioned",
			"--lock-memory=false",
			"--default-log-level=error",
			"--logger-log-level=kafka=info:request_auth=debug:security=debug",
		},
		ExposedPorts: []string{
			"9092/tcp",
		},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"9092/tcp": {
				{HostIP: "::1", HostPort: strconv.Itoa(port)},
				{HostIP: "127.0.0.1", HostPort: strconv.Itoa(port)},
			},
		},
		Mounts: []string{
			fmt.Sprintf("%s:/certs", filepath.Join(testDataAbsPath, "certs")),
			fmt.Sprintf("%s:/etc/redpanda", tempDir),
		},
	}

	var clientOpts []kgo.Opt
	exposedPort := "9092/tcp"
	if tlsConfig != nil {
		clientOpts = append(clientOpts, kgo.DialTLSConfig(tlsConfig))
	}

	resource, err := pool.RunWithOptions(runOpts, func(config *docker.HostConfig) {
		config.AutoRemove = true
	})
	require.NoError(t, err, "Failed to start container")

	t.Cleanup(func() {
		_ = pool.Purge(resource)
	})

	brokerAddr := net.JoinHostPort("localhost", resource.GetPort(exposedPort))
	clientOpts = append(clientOpts, kgo.SeedBrokers(brokerAddr))

	if _, ok := os.LookupEnv("CERBOS_DEBUG_KAFKA"); ok {
		ctx, cancelFunc := context.WithCancel(context.Background())
		go func() {
			if err := pool.Client.Logs(docker.LogsOptions{
				Context:      ctx,
				Container:    resource.Container.ID,
				OutputStream: os.Stdout,
				ErrorStream:  os.Stderr,
				Stdout:       true,
				Stderr:       true,
				Follow:       true,
			}); err != nil {
				cancelFunc()
			}
		}()
		t.Cleanup(cancelFunc)
	}

	client, err := kgo.NewClient(clientOpts...)
	require.NoError(t, err)

	require.NoError(t, pool.Retry(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		if err := client.Ping(ctx); err != nil {
			t.Logf("Ping failed: %v", err)
			return err
		}

		return nil
	}), "Failed to connect to Kafka")

	// create topic
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	t.Cleanup(cancel)
	_, err = kadm.NewClient(client).CreateTopic(ctx, 1, 1, nil, topic)
	require.NoError(t, err, "Failed to create Kafka topic")

	return brokerAddr
}

func fetchKafkaTopic(t *testing.T, uri string, topic string, tlsEnabled bool) ([]*kgo.Record, error) {
	kgoOptions := []kgo.Opt{kgo.SeedBrokers(uri)}
	if tlsEnabled {
		duration := 10 * time.Second
		skipVerify := false
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		tlsConfig, err := kafka.NewTLSConfig(ctx, duration, skipVerify, "testdata/valid/certs/ca.crt", "testdata/valid/client/tls.crt", "testdata/valid/client/tls.key")
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
