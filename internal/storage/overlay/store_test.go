// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package overlay

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/blob"
	"github.com/cerbos/cerbos/internal/storage/disk"
)

var (
	_ storage.Store       = (*MockStore)(nil)
	_ storage.BinaryStore = (*MockBinaryStore)(nil)
	_ storage.Reloadable  = (*MockReloadable)(nil)
)

func TestDriverInstantiation(t *testing.T) {
	ctx := t.Context()

	bucketName := "test"
	t.Setenv("AWS_ACCESS_KEY_ID", "minioadmin")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "minioadmin")

	conf := map[string]any{
		"storage": map[string]any{
			"driver": "overlay",
			"overlay": map[string]any{
				"baseDriver":             "blob",
				"fallbackDriver":         "disk",
				"fallbackErrorThreshold": 3,
			},
			"blob": map[string]any{
				"bucket":             blob.MinioBucketURL(bucketName, blob.StartMinio(ctx, t, bucketName)),
				"workDir":            t.TempDir(),
				"updatePollInterval": "10s",
			},
			"disk": map[string]any{
				"directory": t.TempDir(),
			},
		},
	}
	require.NoError(t, config.LoadMap(conf))

	// policy loader successfully created
	t.Run("policy loader creation successful", func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(t.Context())
		defer cancelFunc()

		store, err := storage.New(ctx)
		require.NoError(t, err, "error creating store")
		require.Equal(t, DriverName, store.Driver())

		overlayStore, ok := store.(Overlay)
		require.True(t, ok, "store does not implement Overlay interface")

		_, err = overlayStore.GetOverlayPolicyLoader(ctx)
		require.NoError(t, err, "error creating overlay policy loader")

		wrappedStore, ok := store.(*Store)
		require.True(t, ok)

		_, ok = wrappedStore.baseStore.(*blob.Store)
		require.True(t, ok, "baseStore should be of type *blob.Store")

		_, ok = wrappedStore.fallbackStore.(*disk.Store)
		require.True(t, ok, "baseStore should be of type *disk.Store")
	})
}

func TestFailover(t *testing.T) {
	fallbackErrorThreshold := 3
	confMap := map[string]any{
		"storage": map[string]any{
			"driver": "overlay",
			"overlay": map[string]any{
				"baseDriver":             "foo",
				"fallbackDriver":         "bar",
				"fallbackErrorThreshold": fallbackErrorThreshold,
			},
		},
	}
	require.NoError(t, config.LoadMap(confMap))

	conf := new(Conf)
	err := config.Get(confKey, conf)
	require.NoError(t, err)

	t.Run("failover not triggered when consecutive failures within threshold", func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(t.Context())
		defer cancelFunc()

		nFailures := fallbackErrorThreshold - 1
		nRequests := nFailures + 1
		basePolicyLoader := new(MockPolicyLoader)
		basePolicyLoader.On("GetFirstMatch", ctx, mock.AnythingOfType("[]namer.ModuleID")).Return((*runtimev1.RunnablePolicySet)(nil), errors.New("base store error")).Times(nFailures)
		basePolicyLoader.On("GetFirstMatch", ctx, mock.AnythingOfType("[]namer.ModuleID")).Return(&runtimev1.RunnablePolicySet{}, nil).Once()

		fallbackPolicyLoader := new(MockPolicyLoader)

		wrappedSourceStore := &Store{
			log:                  zap.S(),
			basePolicyLoader:     basePolicyLoader,
			fallbackPolicyLoader: fallbackPolicyLoader,
			circuitBreaker:       newCircuitBreaker(conf),
		}

		for i := range nRequests {
			_, err := wrappedSourceStore.GetFirstMatch(ctx, []namer.ModuleID{namer.GenModuleIDFromFQN("example")})
			if i < nFailures {
				require.Error(t, err, "expected base store to return an error")
			} else {
				require.NoError(t, err, "expected base store to succeed")
			}
		}

		basePolicyLoader.AssertExpectations(t)
	})

	t.Run("failover triggered when consecutive failures exceed threshold", func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(t.Context())
		defer cancelFunc()

		nFailures := fallbackErrorThreshold
		nRequests := nFailures + 1
		basePolicyLoader := new(MockPolicyLoader)
		basePolicyLoader.On("GetFirstMatch", ctx, mock.AnythingOfType("[]namer.ModuleID")).Return((*runtimev1.RunnablePolicySet)(nil), errors.New("base store error")).Times(nFailures)

		fallbackPolicyLoader := new(MockPolicyLoader)
		fallbackPolicyLoader.On("GetFirstMatch", ctx, mock.AnythingOfType("[]namer.ModuleID")).Return(&runtimev1.RunnablePolicySet{}, nil).Once()

		wrappedSourceStore := &Store{
			log:                  zap.S(),
			basePolicyLoader:     basePolicyLoader,
			fallbackPolicyLoader: fallbackPolicyLoader,
			circuitBreaker:       newCircuitBreaker(conf),
		}

		for i := range nRequests {
			_, err := wrappedSourceStore.GetFirstMatch(ctx, []namer.ModuleID{namer.GenModuleIDFromFQN("example")})
			if i < nFailures {
				require.Error(t, err, "expected base store to return an error")
			} else {
				require.NoError(t, err, "expected fallback store to succeed")
			}
		}

		basePolicyLoader.AssertExpectations(t)
		fallbackPolicyLoader.AssertExpectations(t)
	})

	t.Run("reload only called on baseStore if not implemented on fallbackStore", func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(t.Context())
		defer cancelFunc()

		baseStore := new(MockReloadable)
		baseStore.On("Reload", mock.AnythingOfType("*context.cancelCtx")).Return(nil).Once()

		// Fallback store does not implement required method
		fallbackStore := new(MockBinaryStore)

		wrappedSourceStore := &Store{
			log:            zap.S(),
			baseStore:      baseStore,
			fallbackStore:  fallbackStore,
			circuitBreaker: newCircuitBreaker(conf),
		}

		err := wrappedSourceStore.Reload(ctx)
		require.NoError(t, err, "error calling overlay reload method")

		baseStore.AssertExpectations(t)
		fallbackStore.AssertNotCalled(t, "Reload")
	})

	t.Run("reload only called on fallbackStore if not implemented on baseStore", func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(t.Context())
		defer cancelFunc()

		baseStore := new(MockBinaryStore)

		fallbackStore := new(MockReloadable)
		fallbackStore.On("Reload", mock.AnythingOfType("*context.cancelCtx")).Return(nil).Once()

		wrappedSourceStore := &Store{
			log:            zap.S(),
			baseStore:      baseStore,
			fallbackStore:  fallbackStore,
			circuitBreaker: newCircuitBreaker(conf),
		}

		err := wrappedSourceStore.Reload(ctx)
		require.NoError(t, err, "error calling overlay reload method")

		baseStore.AssertNotCalled(t, "Reload")
		fallbackStore.AssertExpectations(t)
	})

	t.Run("reload not called if not implemented on either store", func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(t.Context())
		defer cancelFunc()

		baseStore := new(MockBinaryStore)
		fallbackStore := new(MockBinaryStore)

		wrappedSourceStore := &Store{
			log:            zap.S(),
			baseStore:      baseStore,
			fallbackStore:  fallbackStore,
			circuitBreaker: newCircuitBreaker(conf),
		}

		err := wrappedSourceStore.Reload(ctx)
		require.NoError(t, err, "error calling overlay reload method")

		baseStore.AssertNotCalled(t, "Reload")
		fallbackStore.AssertNotCalled(t, "Reload")
	})
}

type MockPolicyLoader struct {
	mock.Mock
}

func (m *MockPolicyLoader) GetFirstMatch(ctx context.Context, candidates []namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	args := m.Called(ctx, candidates)
	return args.Get(0).(*runtimev1.RunnablePolicySet), args.Error(1)
}

func (m *MockPolicyLoader) GetAll(ctx context.Context) ([]*runtimev1.RunnablePolicySet, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*runtimev1.RunnablePolicySet), args.Error(1)
}

func (m *MockPolicyLoader) GetAllMatching(ctx context.Context, modIDs []namer.ModuleID) ([]*runtimev1.RunnablePolicySet, error) {
	args := m.Called(ctx, modIDs)
	return args.Get(0).([]*runtimev1.RunnablePolicySet), args.Error(1)
}

func (m *MockPolicyLoader) Source() *auditv1.PolicySource {
	return nil
}

type MockStore struct {
	mock.Mock
}

func (ms *MockStore) Driver() string {
	args := ms.Called()
	return args.String(0)
}

func (ms *MockStore) InspectPolicies(ctx context.Context, _ storage.ListPolicyIDsParams) (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	args := ms.Called(ctx)
	if res := args.Get(0); res == nil {
		return nil, args.Error(0)
	}
	return args.Get(0).(map[string]*responsev1.InspectPoliciesResponse_Result), args.Error(0)
}

func (ms *MockStore) ListPolicyIDs(ctx context.Context, _ storage.ListPolicyIDsParams) ([]string, error) {
	args := ms.Called(ctx)
	if res := args.Get(0); res == nil {
		return nil, args.Error(0)
	}
	return args.Get(0).([]string), args.Error(0)
}

func (ms *MockStore) ListSchemaIDs(ctx context.Context) ([]string, error) {
	args := ms.Called(ctx)
	if res := args.Get(0); res == nil {
		return nil, args.Error(0)
	}
	return args.Get(0).([]string), args.Error(0)
}

func (ms *MockStore) LoadSchema(ctx context.Context, _ string) (io.ReadCloser, error) {
	args := ms.Called(ctx)
	if res := args.Get(0); res == nil {
		return nil, args.Error(0)
	}
	return nil, nil
}

func (ms *MockStore) Source() *auditv1.PolicySource {
	return nil
}

type MockBinaryStore struct {
	mock.Mock
	MockStore
}

func (m *MockBinaryStore) GetFirstMatch(ctx context.Context, candidates []namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	args := m.Called(ctx, candidates)
	return args.Get(0).(*runtimev1.RunnablePolicySet), args.Error(1)
}

func (m *MockBinaryStore) GetAll(ctx context.Context) ([]*runtimev1.RunnablePolicySet, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*runtimev1.RunnablePolicySet), args.Error(1)
}

func (m *MockBinaryStore) GetAllMatching(ctx context.Context, modIDs []namer.ModuleID) ([]*runtimev1.RunnablePolicySet, error) {
	args := m.Called(ctx, modIDs)
	return args.Get(0).([]*runtimev1.RunnablePolicySet), args.Error(1)
}

func (m *MockBinaryStore) Subscribe(s storage.Subscriber) {
	m.Called(s)
}

func (m *MockBinaryStore) Unsubscribe(s storage.Subscriber) {
	m.Called(s)
}

type MockReloadable struct {
	mock.Mock
	MockStore
}

func (m *MockReloadable) Reload(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}
