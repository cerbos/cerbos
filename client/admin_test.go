// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
)

func TestCollectLogs(t *testing.T) {
	type ticker struct {
		tick <-chan time.Time
		tock <-chan time.Time
	}

	newTicker := func() ticker {
		return ticker{
			tick: time.After(50 * time.Millisecond),
			tock: time.After(60 * time.Millisecond),
		}
	}

	t.Run("access logs", func(t *testing.T) {
		clock := newTicker()
		receiver := func() (*responsev1.ListAuditLogEntriesResponse, error) {
			select {
			case <-clock.tick:
				return &responsev1.ListAuditLogEntriesResponse{Entry: &responsev1.ListAuditLogEntriesResponse_AccessLogEntry{
					AccessLogEntry: &auditv1.AccessLogEntry{CallId: "test"},
				}}, nil
			case <-clock.tock:
				return nil, io.EOF
			}
		}

		accesses := make(chan *AccessLogEntry)
		err := collectLogs(receiver, accesses)
		require.NoError(t, err)

		access := <-accesses
		require.Equal(t, "test", access.Log.CallId)
		require.Empty(t, accesses)
	})

	t.Run("decision logs", func(t *testing.T) {
		clock := newTicker()
		receiver := func() (*responsev1.ListAuditLogEntriesResponse, error) {
			select {
			case <-clock.tick:
				return &responsev1.ListAuditLogEntriesResponse{Entry: &responsev1.ListAuditLogEntriesResponse_DecisionLogEntry{
					DecisionLogEntry: &auditv1.DecisionLogEntry{CallId: "test"},
				}}, nil
			case <-clock.tock:
				return nil, io.EOF
			}
		}

		decisions := make(chan *DecisionLogEntry)
		err := collectLogs(receiver, decisions)
		require.NoError(t, err)

		decision := <-decisions
		require.Equal(t, "test", decision.Log.CallId)
		require.Empty(t, decisions)
	})

	t.Run("invalid types", func(t *testing.T) {
		receiver := func() (*responsev1.ListAuditLogEntriesResponse, error) { return nil, io.EOF }

		err := collectLogs(receiver, "decisions")
		require.Error(t, err)

		err = collectLogs(receiver, make(chan string))
		require.Error(t, err)
	})

	t.Run("error from receiver", func(t *testing.T) {
		receiver := func() (*responsev1.ListAuditLogEntriesResponse, error) { return nil, errors.New("test-error") }
		decisions := make(chan *DecisionLogEntry)

		err := collectLogs(receiver, decisions)
		require.NoError(t, err)

		decision := <-decisions
		require.Nil(t, decision.Log)
		require.Error(t, decision.Err)
	})
}

func TestDecisionLogs(t *testing.T) {
	t.Run("should fail on invalid log options", func(t *testing.T) {
		c := GrpcAdminClient{client: svcv1.NewCerbosAdminServiceClient(&grpc.ClientConn{})}

		_, err := c.DecisionLogs(context.Background(), AuditLogOptions{
			Tail: 10000,
		})

		require.Error(t, err)
	})
}

func TestAccessLogs(t *testing.T) {
	t.Run("should fail on invalid log options", func(t *testing.T) {
		c := GrpcAdminClient{client: svcv1.NewCerbosAdminServiceClient(&grpc.ClientConn{})}

		_, err := c.AccessLogs(context.Background(), AuditLogOptions{
			Tail: 10000,
		})

		require.Error(t, err)
	})
}
