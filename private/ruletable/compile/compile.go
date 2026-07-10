// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"fmt"
	"io/fs"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	internalcompile "github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/private/compile"
)

func Compile(ctx context.Context, fsys fs.FS, attrs ...compile.SourceAttribute) (*runtimev1.RuleTable, error) {
	var rows []*runtimev1.RuleTable_RuleRow
	rt, err := CompileStream(ctx, fsys, func(row *runtimev1.RuleTable_RuleRow) error {
		rows = append(rows, row)
		return nil
	}, attrs...)
	if err != nil {
		return nil, err
	}

	rt.Rules = rows
	return rt, nil
}

// CompileStream compiles the policies in fsys into rule table rows, passing each row to
// onRow as it is produced instead of accumulating them. The returned rule table has all other field (schemas,
// metadata, derived roles, scope maps) initialised.
func CompileStream(ctx context.Context, fsys fs.FS, onRow func(*runtimev1.RuleTable_RuleRow) error, attrs ...compile.SourceAttribute) (*runtimev1.RuleTable, error) {
	idx, err := compile.BuildIndex(ctx, fsys, attrs...)
	if err != nil {
		return nil, err
	}

	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})

	mgr, err := internalcompile.NewManager(ctx, store)
	if err != nil {
		return nil, fmt.Errorf("failed to create compile manager: %w", err)
	}

	rt := ruletable.NewProtoRuletable()

	if err := ruletable.LoadPoliciesIterFunc(rt, mgr.Iter(ctx), onRow); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	if err := ruletable.LoadSchemas(ctx, rt, idx); err != nil {
		return nil, fmt.Errorf("failed to load schemas: %w", err)
	}

	return rt, nil
}

// AppendRuleRowRecord replicates protobuf marshalling of a single
// runtimev1.RuleTable_RuleRow as it is done by the (*RuleTable).MarshalToVT
// method. It can be used to marshall rows separately from the rest of the
// RuleTable.
func AppendRuleRowRecord(buf []byte, row *runtimev1.RuleTable_RuleRow) ([]byte, error) {
	return ruletable.AppendRuleRowRecord(buf, row)
}
