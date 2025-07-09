// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/test"
)

func TestManager(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		mgr, mockStore, cancel := mkManager(t)
		defer cancel()

		ec := policy.Wrap(test.GenExportConstants(test.NoMod()))
		ev := policy.Wrap(test.GenExportVariables(test.NoMod()))
		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))
		dr := policy.Wrap(test.GenDerivedRoles(test.NoMod()))

		mockStore.
			On("GetCompilationUnits", mock.MatchedBy(anyCtx), []namer.ModuleID{rp.ID}).
			Return(map[namer.ModuleID]*policy.CompilationUnit{
				rp.ID: {
					ModID: rp.ID,
					Definitions: map[namer.ModuleID]*policyv1.Policy{
						rp.ID: rp.Policy,
						dr.ID: dr.Policy,
						ec.ID: ec.Policy,
						ev.ID: ev.Policy,
					},
				},
			}, nil).
			Twice()

		rps1, err := mgr.GetPolicySet(t.Context(), rp.ID)
		require.NoError(t, err)
		require.NotNil(t, rps1)

		rps2, err := mgr.GetPolicySet(t.Context(), rp.ID)
		require.NoError(t, err)
		require.NotNil(t, rps2)

		mockStore.AssertExpectations(t)
	})

	t.Run("no_matching_policy", func(t *testing.T) {
		mgr, mockStore, cancel := mkManager(t)
		defer cancel()

		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))

		mockStore.
			On("GetCompilationUnits", mock.MatchedBy(anyCtx), []namer.ModuleID{rp.ID}).
			Return(map[namer.ModuleID]*policy.CompilationUnit{}, nil).
			Twice()

		rps1, err := mgr.GetPolicySet(t.Context(), rp.ID)
		require.NoError(t, err)
		require.Nil(t, rps1)

		rps2, err := mgr.GetPolicySet(t.Context(), rp.ID)
		require.NoError(t, err)
		require.Nil(t, rps2)

		mockStore.AssertExpectations(t)
	})

	t.Run("error_from_store", func(t *testing.T) {
		mgr, mockStore, cancel := mkManager(t)
		defer cancel()

		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))

		wantErr := errors.New("oh no")
		mockStore.
			On("GetCompilationUnits", mock.MatchedBy(anyCtx), []namer.ModuleID{rp.ID}).
			Return(nil, wantErr).
			Twice()

		_, err := mgr.GetPolicySet(t.Context(), rp.ID)
		require.Error(t, err)
		require.ErrorIs(t, err, wantErr)

		// should not hit the cache this time because the previous call errored
		_, err = mgr.GetPolicySet(t.Context(), rp.ID)
		require.Error(t, err)
		require.ErrorIs(t, err, wantErr)

		mockStore.AssertExpectations(t)
	})
}

func TestGetFirstMatch(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		mgr, mockStore, cancel := mkManager(t)
		defer cancel()

		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))
		rpFoo := policy.Wrap(test.GenScopedResourcePolicy("foo", test.NoMod()))
		rpFooBar := policy.Wrap(test.GenScopedResourcePolicy("foo.bar", test.NoMod()))
		ec := policy.Wrap(test.GenExportConstants(test.NoMod()))
		ev := policy.Wrap(test.GenExportVariables(test.NoMod()))
		dr := policy.Wrap(test.GenDerivedRoles(test.NoMod()))

		mockStore.
			On("GetFirstMatch", mock.MatchedBy(anyCtx), []namer.ModuleID{rpFooBar.ID, rpFoo.ID, rp.ID}).
			Return(&policy.CompilationUnit{
				ModID: rpFooBar.ID,
				Definitions: map[namer.ModuleID]*policyv1.Policy{
					rpFooBar.ID: rpFooBar.Policy,
					rpFoo.ID:    rpFoo.Policy,
					rp.ID:       rp.Policy,
					dr.ID:       dr.Policy,
					ec.ID:       ec.Policy,
					ev.ID:       ev.Policy,
				},
			}, nil).
			Twice()

		rps1, err := mgr.GetFirstMatch(t.Context(), []namer.ModuleID{rpFooBar.ID, rpFoo.ID, rp.ID})
		require.NoError(t, err)
		require.NotNil(t, rps1)

		rps2, err := mgr.GetFirstMatch(t.Context(), []namer.ModuleID{rpFooBar.ID, rpFoo.ID, rp.ID})
		require.NoError(t, err)
		require.NotNil(t, rps2)

		mockStore.AssertExpectations(t)
	})

	t.Run("first_scope_missing", func(t *testing.T) {
		mgr, mockStore, cancel := mkManager(t)
		defer cancel()

		rp := policy.Wrap(test.GenResourcePolicy(test.NoMod()))
		rpFoo := policy.Wrap(test.GenScopedResourcePolicy("foo", test.NoMod()))
		rpFooBar := policy.Wrap(test.GenScopedResourcePolicy("foo.bar", test.NoMod()))
		ec := policy.Wrap(test.GenExportConstants(test.NoMod()))
		ev := policy.Wrap(test.GenExportVariables(test.NoMod()))
		dr := policy.Wrap(test.GenDerivedRoles(test.NoMod()))

		// pretend that scope foo.bar doesn't exist
		mockStore.
			On("GetFirstMatch", mock.MatchedBy(anyCtx), []namer.ModuleID{rpFooBar.ID, rpFoo.ID, rp.ID}).
			Return(&policy.CompilationUnit{
				ModID: rpFoo.ID,
				Definitions: map[namer.ModuleID]*policyv1.Policy{
					rpFoo.ID: rpFoo.Policy,
					rp.ID:    rp.Policy,
					dr.ID:    dr.Policy,
					ec.ID:    ec.Policy,
					ev.ID:    ev.Policy,
				},
			}, nil).
			Twice()

		rps1, err := mgr.GetFirstMatch(t.Context(), []namer.ModuleID{rpFooBar.ID, rpFoo.ID, rp.ID})
		require.NoError(t, err)
		require.NotNil(t, rps1)

		// should skip the cache because the first candidate doesn't exist
		rps2, err := mgr.GetFirstMatch(t.Context(), []namer.ModuleID{rpFooBar.ID, rpFoo.ID, rp.ID})
		require.NoError(t, err)
		require.NotNil(t, rps2)
		require.Equal(t, rps1, rps2)

		mockStore.AssertExpectations(t)
	})
}

func mkManager(t *testing.T) (*compile.Manager, *MockStore, context.CancelFunc) {
	t.Helper()

	ctx, cancelFunc := context.WithCancel(t.Context())

	mockStore := &MockStore{}
	mockStore.On("Subscribe", mock.Anything)

	mgr, err := compile.NewManager(ctx, mockStore, schema.NewNopManager())
	require.NoError(t, err)

	return mgr, mockStore, cancelFunc
}

func anyCtx(context.Context) bool {
	return true
}

type MockStore struct {
	subscriber storage.Subscriber
	mock.Mock
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

func (ms *MockStore) GetFirstMatch(ctx context.Context, candidates []namer.ModuleID) (*policy.CompilationUnit, error) {
	args := ms.MethodCalled("GetFirstMatch", ctx, candidates)
	res := args.Get(0)
	switch t := res.(type) {
	case nil:
		return nil, args.Error(1)
	case *policy.CompilationUnit:
		return t, args.Error(1)
	case func() (*policy.CompilationUnit, error):
		return t()
	default:
		panic(fmt.Errorf("unknown return value type: %T", res))
	}
}

func (ms *MockStore) GetAll(ctx context.Context) ([]*policy.CompilationUnit, error) {
	args := ms.MethodCalled("GetAll", ctx)
	if res := args.Get(0); res == nil {
		return nil, args.Error(0)
	}
	return args.Get(0).([]*policy.CompilationUnit), args.Error(1)
}

func (ms *MockStore) GetAllMatching(ctx context.Context, modIDs []namer.ModuleID) ([]*policy.CompilationUnit, error) {
	args := ms.MethodCalled("GetAllMatching", ctx, modIDs)
	if res := args.Get(0); res == nil {
		return nil, args.Error(0)
	}
	return args.Get(0).([]*policy.CompilationUnit), args.Error(1)
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

func (ms *MockStore) InspectPolicies(ctx context.Context, _ storage.ListPolicyIDsParams) (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	args := ms.MethodCalled("InspectPolicies", ctx)
	if res := args.Get(0); res == nil {
		return nil, args.Error(0)
	}
	return args.Get(0).(map[string]*responsev1.InspectPoliciesResponse_Result), args.Error(0)
}

func (ms *MockStore) ListPolicyIDs(ctx context.Context, _ storage.ListPolicyIDsParams) ([]string, error) {
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

func (ms *MockStore) LoadPolicy(ctx context.Context, _ ...string) ([]*policy.Wrapper, error) {
	args := ms.MethodCalled("LoadPolicy", ctx)
	if res := args.Get(0); res == nil {
		return nil, args.Error(0)
	}
	return nil, nil
}

func (ms *MockStore) LoadSchema(ctx context.Context, _ string) (io.ReadCloser, error) {
	args := ms.MethodCalled("LoadSchema", ctx)
	if res := args.Get(0); res == nil {
		return nil, args.Error(0)
	}
	return nil, nil
}

func (ms *MockStore) GetSchema(ctx context.Context, _ string) ([]byte, error) {
	args := ms.MethodCalled("GetSchema", ctx)
	if res := args.Get(0); res == nil {
		return nil, args.Error(0)
	}
	return nil, nil
}

func (ms *MockStore) AddOrUpdateSchema(ctx context.Context, _ ...*schemav1.Schema) error {
	args := ms.MethodCalled("AddOrUpdateSchema", ctx)
	if res := args.Get(0); res == nil {
		return args.Error(0)
	}
	return nil
}

func (ms *MockStore) Disable(ctx context.Context, _ ...string) (uint32, error) {
	args := ms.MethodCalled("Disable", ctx)
	if res := args.Get(0); res == nil {
		return 0, args.Error(0)
	}
	return 0, nil
}

func (ms *MockStore) Enable(ctx context.Context, _ ...string) (uint32, error) {
	args := ms.MethodCalled("Enable", ctx)
	if res := args.Get(0); res == nil {
		return 0, args.Error(0)
	}
	return 0, nil
}

func (ms *MockStore) DeleteSchema(ctx context.Context, _ ...string) error {
	args := ms.MethodCalled("DeleteSchema", ctx)
	if res := args.Get(0); res == nil {
		return args.Error(0)
	}
	return nil
}
