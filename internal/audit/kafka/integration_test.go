package kafka_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/config"
)

const (
	redpandaImage   = "redpandadata/redpanda"
	redpandaVersion = "v23.1.5"

	defaultIntegrationTopic = "cerbos"
)

func TestSyncProduce(t *testing.T) {
	ctx := context.Background()

	// setup kafka
	uri := newKafkaBroker(t)
	err := newKafkaTopic(uri, defaultIntegrationTopic)
	require.NoError(t, err)
	// kafka audit backend with synchronous publishing
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
	ctx := context.Background()

	// setup kafka
	uri := newKafkaBroker(t)
	err := newKafkaTopic(uri, defaultIntegrationTopic)
	require.NoError(t, err)
	// kafka audit backend with synchronous publishing
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

	require.Eventually(t, func() bool {
		records, err := fetchKafkaTopic(uri, defaultIntegrationTopic)
		require.NoError(t, err)
		return len(records) == 2
	}, 10*time.Second, 100*time.Millisecond, "expected to see audit log entries in kafka")
}

func newKafkaBroker(t *testing.T) string {
	ctx := context.Background()

	// start container
	req := testcontainers.ContainerRequest{
		Image: fmt.Sprintf("%s:%s", redpandaImage, redpandaVersion),
		ExposedPorts: []string{
			"9092:9092/tcp",
		},
		Cmd:        []string{"redpanda", "start", "--mode", "dev-container"},
		WaitingFor: wait.ForLog("Successfully started Redpanda!"),
		AutoRemove: true,
	}

	cntr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	// shutdown container when test completes
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := cntr.Terminate(ctx); err != nil {
			t.Logf("failed to terminate kafka container: %s", err)
		}
	})

	// broker URI
	mappedPort, err := cntr.MappedPort(ctx, "9092")
	require.NoError(t, err)

	hostIP, err := cntr.Host(ctx)
	require.NoError(t, err)

	return fmt.Sprintf("%s:%s", hostIP, mappedPort.Port())
}

func newKafkaTopic(uri, topic string) error {
	client, err := kgo.NewClient(kgo.SeedBrokers(uri))
	if err != nil {
		return err
	}

	aclient := kadm.NewClient(client)

	_, err = aclient.CreateTopic(context.Background(), 1, 1, nil, topic)
	return err
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
