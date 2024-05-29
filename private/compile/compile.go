// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	internalcompile "github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/parser"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/rolepolicy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
)

type Index = index.Index

type Artefact struct {
	Error      error
	PolicySet  *runtimev1.RunnablePolicySet
	SourceFile string
}

type PanicError struct {
	Cause   any
	Context []byte
}

func (pe PanicError) Error() string {
	return fmt.Sprintf("panic: %v", pe.Cause)
}

type Errors struct {
	*runtimev1.Errors
}

func (e *Errors) Error() string {
	switch e.Kind.(type) {
	case *runtimev1.Errors_IndexBuildErrors:
		return "index build failed"
	case *runtimev1.Errors_CompileErrors:
		return "compilation failed"
	default:
		return fmt.Sprintf("unhandled error kind %T", e.Kind)
	}
}

type SourceAttribute struct {
	Value *structpb.Value
	Key   string
}

func Files(ctx context.Context, fsys fs.FS, attrs ...SourceAttribute) (Index, <-chan Artefact, error) {
	srcAttrs := make([]policy.SourceAttribute, len(attrs))
	for i, a := range attrs {
		srcAttrs[i] = policy.SourceAttribute{Key: a.Key, Value: a.Value}
	}

	idx, err := index.Build(ctx, fsys, index.WithSourceAttributes(srcAttrs...))
	if err != nil {
		idxErrs := new(index.BuildError)
		if errors.As(err, &idxErrs) {
			return nil, nil, &Errors{
				Errors: &runtimev1.Errors{
					Kind: &runtimev1.Errors_IndexBuildErrors{IndexBuildErrors: idxErrs.IndexBuildErrors},
				},
			}
		}

		panicErr := new(parser.PanicError)
		if errors.As(err, panicErr) {
			return nil, nil, PanicError{Cause: panicErr.Cause, Context: panicErr.Context}
		}

		return nil, nil, fmt.Errorf("failed to build index: %w", err)
	}

	rolePolicyMgr := rolepolicy.NewManager(idx.GetRolePolicyActionIndexes())

	outChan := make(chan Artefact, 1)

	go func() {
		defer close(outChan)

		store := disk.NewFromIndexWithConf(idx, &disk.Conf{})
		schemaMgr := schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))
		logger := logging.FromContext(ctx).Named("compile")

		inChan := idx.GetAllCompilationUnits(ctx)
		for unit := range inChan {
			srcFile := unit.MainSourceFile()
			log := logger.With(zap.String("source", srcFile))
			log.Debug("Compiling unit")

			artefact := Artefact{SourceFile: srcFile}
			artefact.PolicySet, artefact.Error = internalcompile.Compile(unit, schemaMgr, rolePolicyMgr)

			if artefact.Error != nil {
				log.Error("Compilation failed", zap.Error(artefact.Error))
				compErrs := new(internalcompile.ErrorSet)
				if errors.As(artefact.Error, &compErrs) {
					artefact.Error = &Errors{
						Errors: &runtimev1.Errors{
							Kind: &runtimev1.Errors_CompileErrors{CompileErrors: compErrs.Errors()},
						},
					}
				}
			} else {
				log.Debug("Compilation succeeded")
			}

			log.Debug("Sending artefact")
			select {
			case outChan <- artefact:
				log.Debug("Artefact sent")
			case <-ctx.Done():
				log.Debug("Artefact send cancelled", zap.Error(ctx.Err()))
				return
			}
		}
	}()

	return idx, outChan, nil
}
