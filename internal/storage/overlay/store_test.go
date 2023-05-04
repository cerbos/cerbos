// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package overlay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/blob"

	"github.com/cerbos/cerbos/internal/storage/disk"
)

var (
	_ storage.Store       = (*MockStore)(nil)
	_ storage.BinaryStore = (*MockBinaryStore)(nil)
	_ storage.SourceStore = (*MockSourceStore)(nil)
)

func TestDriverInstantiation(t *testing.T) {
	ctx := context.Background()

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
		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()

		store, err := storage.New(ctx)
		require.NoError(t, err, "error creating store")
		require.Equal(t, DriverName, store.Driver())

		schemaMgr, err := schema.New(ctx, store)
		require.NoError(t, err, "error creating schema manager")

		overlayStore, ok := store.(Overlay)
		require.True(t, ok, "store does not implement Overlay interface")

		_, err = overlayStore.GetOverlayPolicyLoader(ctx, schemaMgr)
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
				"fallbackErrorThreshold": fallbackErrorThreshold,
			},
		},
	}
	require.NoError(t, config.LoadMap(confMap))

	conf := new(Conf)
	err := config.Get(confKey, conf)
	require.NoError(t, err)

	t.Run("failover not triggered when consecutive failures within threshold", func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()

		nFailures := fallbackErrorThreshold - 1
		nRequests := nFailures + 1
		basePolicyLoader := new(MockPolicyLoader)
		basePolicyLoader.On("GetPolicySet", ctx, mock.AnythingOfType("namer.ModuleID")).Return((*runtimev1.RunnablePolicySet)(nil), errors.New("base store error")).Times(nFailures)
		basePolicyLoader.On("GetPolicySet", ctx, mock.AnythingOfType("namer.ModuleID")).Return(&runtimev1.RunnablePolicySet{}, nil).Once()

		fallbackPolicyLoader := new(MockPolicyLoader)

		wrappedSourceStore := &Store{
			log:                  zap.S(),
			basePolicyLoader:     basePolicyLoader,
			fallbackPolicyLoader: fallbackPolicyLoader,
			circuitBreaker:       newCircuitBreaker(conf),
		}

		for i := 0; i < nRequests; i++ {
			_, err := wrappedSourceStore.GetPolicySet(ctx, namer.GenModuleIDFromFQN("example"))
			if i < nFailures {
				require.Error(t, err, "expected base store to return an error")
			} else {
				require.NoError(t, err, "expected base store to succeed")
			}
		}

		basePolicyLoader.AssertExpectations(t)
	})

	t.Run("failover triggered when consecutive failures exceed threshold", func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()

		nFailures := fallbackErrorThreshold
		nRequests := nFailures + 1
		basePolicyLoader := new(MockPolicyLoader)
		basePolicyLoader.On("GetPolicySet", ctx, mock.AnythingOfType("namer.ModuleID")).Return((*runtimev1.RunnablePolicySet)(nil), errors.New("base store error")).Times(nFailures)

		fallbackPolicyLoader := new(MockPolicyLoader)
		fallbackPolicyLoader.On("GetPolicySet", ctx, mock.AnythingOfType("namer.ModuleID")).Return(&runtimev1.RunnablePolicySet{}, nil).Once()

		wrappedSourceStore := &Store{
			log:                  zap.S(),
			basePolicyLoader:     basePolicyLoader,
			fallbackPolicyLoader: fallbackPolicyLoader,
			circuitBreaker:       newCircuitBreaker(conf),
		}

		for i := 0; i < nRequests; i++ {
			_, err := wrappedSourceStore.GetPolicySet(ctx, namer.GenModuleIDFromFQN("example"))
			if i < nFailures {
				require.Error(t, err, "expected base store to return an error")
			} else {
				require.NoError(t, err, "expected fallback store to succeed")
			}
		}

		basePolicyLoader.AssertExpectations(t)
		fallbackPolicyLoader.AssertExpectations(t)
	})

	t.Run("failover not triggered when consecutive failures exceed threshold on unimplemented fallback interface method", func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()

		nRequests := fallbackErrorThreshold + 1
		baseStore := new(MockSourceStore)
		baseStore.On("GetCompilationUnits", ctx, mock.AnythingOfType("[]namer.ModuleID")).Return((map[namer.ModuleID]*policy.CompilationUnit)(nil), errors.New("base store error")).Times(nRequests)

		// Fallback store does not implement required method
		fallbackStore := new(MockBinaryStore)

		wrappedSourceStore := &Store{
			log:            zap.S(),
			baseStore:      baseStore,
			fallbackStore:  fallbackStore,
			circuitBreaker: newCircuitBreaker(conf),
		}

		for i := 0; i < nRequests; i++ {
			_, err := wrappedSourceStore.GetCompilationUnits(ctx, namer.GenModuleIDFromFQN("example"))
			require.Error(t, err, "expected overlay to return an error")
		}

		baseStore.AssertExpectations(t)
		fallbackStore.AssertNotCalled(t, "GetCompilationUnits")
	})

	t.Run("neither store method called when request made on unimplemented base interface method", func(t *testing.T) {
		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()

		nRequests := 2
		// Base store does not implement required method
		baseStore := new(MockBinaryStore)
		fallbackStore := new(MockSourceStore)

		wrappedSourceStore := &Store{
			log:            zap.S(),
			baseStore:      baseStore,
			fallbackStore:  fallbackStore,
			circuitBreaker: newCircuitBreaker(conf),
		}

		for i := 0; i < nRequests; i++ {
			_, err := wrappedSourceStore.GetCompilationUnits(ctx, namer.GenModuleIDFromFQN("example"))
			require.Error(t, err, "expected base store to return an error")
		}

		baseStore.AssertNotCalled(t, "GetCompilationUnits")
		fallbackStore.AssertNotCalled(t, "GetCompilationUnits")
	})
}

type MockPolicyLoader struct {
	mock.Mock
}

func (m *MockPolicyLoader) GetPolicySet(ctx context.Context, id namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*runtimev1.RunnablePolicySet), args.Error(1)
}

type MockStore struct {
	mock.Mock
}

func (ms *MockStore) Driver() string {
	args := ms.MethodCalled("Driver")
	return args.String(0)
}

func (ms *MockStore) ListPolicyIDs(ctx context.Context, _ bool) ([]string, error) {
	args := ms.MethodCalled("ListPolicyIDs", ctx)
	if res := args.Get(0); res == nil {
		return nil, args.Error(0)
	}
	return args.Get(0).([]string), args.Error(0)
}

func (ms *MockStore) ListSchemaIDs(ctx context.Context) ([]string, error) {
	args := ms.MethodCalled("ListSchemaIDs", ctx)
	if res := args.Get(0); res == nil {
		return nil, args.Error(0)
	}
	return args.Get(0).([]string), args.Error(0)
}

func (ms *MockStore) LoadSchema(ctx context.Context, _ string) (io.ReadCloser, error) {
	args := ms.MethodCalled("LoadSchema", ctx)
	if res := args.Get(0); res == nil {
		return nil, args.Error(0)
	}
	return nil, nil
}

type MockBinaryStore struct {
	mock.Mock
	MockStore
}

func (m *MockBinaryStore) GetPolicySet(ctx context.Context, id namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*runtimev1.RunnablePolicySet), args.Error(1)
}

type MockSourceStore struct {
	mock.Mock
	MockStore
	subscriber storage.Subscriber
}

func (ms *MockSourceStore) GetCompilationUnits(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error) {
	args := ms.MethodCalled("GetCompilationUnits", ctx, ids)
	res := args.Get(0)
	switch t := res.(type) {
	case nil:
		return nil, args.Error(1)
	case map[namer.ModuleID]*policy.CompilationUnit:
		return t, args.Error(1)
	case func() (map[namer.ModuleID]*policy.CompilationUnit, error):
		return t()
	default:
		panic(fmt.Errorf("unknown return value type: %T", res))
	}
}

func (ms *MockSourceStore) GetDependents(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error) {
	args := ms.MethodCalled("GetDependents", ctx, ids)
	if res := args.Get(0); res == nil {
		return nil, args.Error(0)
	}
	return args.Get(0).(map[namer.ModuleID][]namer.ModuleID), args.Error(1)
}

func (ms *MockSourceStore) LoadPolicy(ctx context.Context, _ ...string) ([]*policy.Wrapper, error) {
	args := ms.MethodCalled("LoadPolicy", ctx)
	if res := args.Get(0); res == nil {
		return nil, args.Error(0)
	}
	return nil, nil
}

func (ms *MockSourceStore) Subscribe(s storage.Subscriber) {
	ms.MethodCalled("Subscribe", s)
	ms.subscriber = s
}

func (ms *MockSourceStore) Unsubscribe(s storage.Subscriber) {
	ms.MethodCalled("Unsubscribe", s)
	ms.subscriber = nil
}
