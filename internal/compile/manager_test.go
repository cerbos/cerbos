// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/test"
)

func TestManager(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		mgr, mockStore, cancel := mkManager()
		defer cancel()

		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))
		dr := policy.Wrap(test.GenDerivedRoles(test.NoMod()))

		mockStore.
			On("GetCompilationUnits", mock.MatchedBy(anyCtx), []namer.ModuleID{rp.ID}).
			Return(map[namer.ModuleID]*policy.CompilationUnit{
				rp.ID: &policy.CompilationUnit{
					ModID:       rp.ID,
					Definitions: map[namer.ModuleID]*policyv1.Policy{rp.ID: rp.Policy, dr.ID: dr.Policy},
				},
			}, nil).
			Once()

		rps1, err := mgr.Get(context.Background(), rp.ID)
		require.NoError(t, err)
		require.NotNil(t, rps1)

		// should be read from the cache this time
		rps2, err := mgr.Get(context.Background(), rp.ID)
		require.NoError(t, err)
		require.NotNil(t, rps2)
		require.Equal(t, rps1, rps2)

		mockStore.AssertExpectations(t)
	})

	t.Run("no_matching_policy", func(t *testing.T) {
		mgr, mockStore, cancel := mkManager()
		defer cancel()

		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))

		mockStore.
			On("GetCompilationUnits", mock.MatchedBy(anyCtx), []namer.ModuleID{rp.ID}).
			Return(map[namer.ModuleID]*policy.CompilationUnit{}, nil).
			Once()

		rps1, err := mgr.Get(context.Background(), rp.ID)
		require.NoError(t, err)
		require.Nil(t, rps1)

		// should be read from the cache this time
		rps2, err := mgr.Get(context.Background(), rp.ID)
		require.NoError(t, err)
		require.Nil(t, rps2)

		mockStore.AssertExpectations(t)
	})

	t.Run("error_from_store", func(t *testing.T) {
		mgr, mockStore, cancel := mkManager()
		defer cancel()

		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))

		wantErr := errors.New("oh no")
		mockStore.
			On("GetCompilationUnits", mock.MatchedBy(anyCtx), []namer.ModuleID{rp.ID}).
			Return(nil, wantErr).
			Twice()

		_, err := mgr.Get(context.Background(), rp.ID)
		require.Error(t, err)
		require.ErrorIs(t, err, wantErr)

		// should not hit the cache this time because the previous call errored
		_, err = mgr.Get(context.Background(), rp.ID)
		require.Error(t, err)
		require.ErrorIs(t, err, wantErr)

		mockStore.AssertExpectations(t)
	})

	t.Run("recompile_on_update", func(t *testing.T) {
		mgr, mockStore, cancel := mkManager()
		defer cancel()

		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))
		dr := policy.Wrap(test.GenDerivedRoles(test.NoMod()))

		mockStore.
			On("GetCompilationUnits", mock.MatchedBy(anyCtx), []namer.ModuleID{rp.ID}).
			Return(map[namer.ModuleID]*policy.CompilationUnit{
				rp.ID: &policy.CompilationUnit{
					ModID:       rp.ID,
					Definitions: map[namer.ModuleID]*policyv1.Policy{rp.ID: rp.Policy, dr.ID: dr.Policy},
				},
			}, nil).
			Once()

		mockStore.
			On("GetCompilationUnits", mock.MatchedBy(anyCtx), []namer.ModuleID{dr.ID, rp.ID}).
			Return(map[namer.ModuleID]*policy.CompilationUnit{
				rp.ID: &policy.CompilationUnit{
					ModID:       rp.ID,
					Definitions: map[namer.ModuleID]*policyv1.Policy{rp.ID: rp.Policy, dr.ID: dr.Policy},
				},
				dr.ID: &policy.CompilationUnit{
					ModID:       dr.ID,
					Definitions: map[namer.ModuleID]*policyv1.Policy{dr.ID: dr.Policy},
				},
			}, nil).
			Once()

		mockStore.
			On("GetDependents", mock.MatchedBy(anyCtx), []namer.ModuleID{dr.ID}).
			Return(map[namer.ModuleID][]namer.ModuleID{dr.ID: []namer.ModuleID{rp.ID}}, nil).
			Once()

		rps1, err := mgr.Get(context.Background(), rp.ID)
		require.NoError(t, err)
		require.NotNil(t, rps1)

		// send event to trigger recompiliation
		mockStore.subscriber.OnStorageEvent(storage.Event{Kind: storage.EventAddOrUpdatePolicy, PolicyID: dr.ID})

		yield()

		// a new evaluator should have replaced the previous one
		rps2, err := mgr.Get(context.Background(), rp.ID)
		require.NoError(t, err)
		require.NotNil(t, rps2)
		require.True(t, rps1 != rps2)

		mockStore.AssertExpectations(t)
	})

	t.Run("recompile_on_delete", func(t *testing.T) {
		mgr, mockStore, cancel := mkManager()
		defer cancel()

		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))
		dr := policy.Wrap(test.GenDerivedRoles(test.NoMod()))

		gcuInvocationCount := 0
		gcuFn := func() (map[namer.ModuleID]*policy.CompilationUnit, error) {
			gcuInvocationCount++
			switch gcuInvocationCount {
			case 1:
				return map[namer.ModuleID]*policy.CompilationUnit{
					rp.ID: &policy.CompilationUnit{
						ModID:       rp.ID,
						Definitions: map[namer.ModuleID]*policyv1.Policy{rp.ID: rp.Policy, dr.ID: dr.Policy},
					},
				}, nil
			case 2, 3: // derived roles is now deleted
				return map[namer.ModuleID]*policy.CompilationUnit{
					rp.ID: &policy.CompilationUnit{
						ModID:       rp.ID,
						Definitions: map[namer.ModuleID]*policyv1.Policy{rp.ID: rp.Policy},
					},
				}, nil
			default:
				panic(fmt.Errorf("unexpected number of calls: %d", gcuInvocationCount))
			}
		}

		mockStore.
			On("GetCompilationUnits", mock.MatchedBy(anyCtx), []namer.ModuleID{rp.ID}).
			Return(gcuFn)

		mockStore.
			On("GetDependents", mock.MatchedBy(anyCtx), []namer.ModuleID{dr.ID}).
			Return(map[namer.ModuleID][]namer.ModuleID{dr.ID: []namer.ModuleID{rp.ID}}, nil).
			Once()

		rps1, err := mgr.Get(context.Background(), rp.ID)
		require.NoError(t, err)
		require.NotNil(t, rps1)

		// send event to trigger recompiliation
		mockStore.subscriber.OnStorageEvent(storage.Event{Kind: storage.EventDeletePolicy, PolicyID: dr.ID})

		yield()

		// evaluator should be removed because it is now invalid and cannot be compiled
		rps2, err := mgr.Get(context.Background(), rp.ID)
		require.Error(t, err)
		require.Nil(t, rps2)

		mockStore.AssertExpectations(t)
	})
}

func yield() {
	runtime.Gosched()
	time.Sleep(200 * time.Millisecond)
	runtime.Gosched()
}

func mkManager() (*compile.Manager, *MockStore, context.CancelFunc) {
	ctx, cancelFunc := context.WithCancel(context.Background())

	mockStore := &MockStore{}
	mockStore.On("Subscribe", mock.Anything)

	mgr := compile.NewManager(ctx, mockStore)

	return mgr, mockStore, cancelFunc
}

func anyCtx(ctx context.Context) bool {
	return true
}

type MockStore struct {
	mock.Mock
	subscriber storage.Subscriber
}

func (ms *MockStore) Driver() string {
	args := ms.MethodCalled("Driver")
	return args.String(0)
}

func (ms *MockStore) Subscribe(s storage.Subscriber) {
	ms.MethodCalled("Subscribe", s)
	ms.subscriber = s
}

func (ms *MockStore) Unsubscribe(s storage.Subscriber) {
	ms.MethodCalled("Unsubscribe", s)
	ms.subscriber = nil
}

func (ms *MockStore) GetCompilationUnits(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error) {
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

func (ms *MockStore) GetDependents(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error) {
	args := ms.MethodCalled("GetDependents", ctx, ids)
	if res := args.Get(0); res == nil {
		return nil, args.Error(0)
	}
	return args.Get(0).(map[namer.ModuleID][]namer.ModuleID), args.Error(1)
}

func (ms *MockStore) AddOrUpdate(ctx context.Context, policies ...policy.Wrapper) error {
	args := ms.MethodCalled("AddOrUpdate", ctx, policies)
	return args.Error(0)
}

func (ms *MockStore) Delete(ctx context.Context, ids ...namer.ModuleID) error {
	args := ms.MethodCalled("Delete", ctx, ids)
	return args.Error(0)
}

func (ms *MockStore) GetPolicies(ctx context.Context) ([]*policy.Wrapper, error) {
	args := ms.MethodCalled("GetPolicies", ctx)
	if res := args.Get(0); res == nil {
		return nil, args.Error(0)
	}
	return args.Get(0).([]*policy.Wrapper), args.Error(0)
}
