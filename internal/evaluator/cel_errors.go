// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"sync"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/observability/logging"
)

const (
	celErrorMsg  = "Error evaluating CEL expression"
	celErrorHint = `CEL evaluation errors detected; set engine.celErrorLogLevel to "none" to silence these messages. From Cerbos v0.55, a DENY rule whose condition raises a runtime error will be considered as satisfying the DENY condition`
)

var celErrorHintOnce sync.Once

type celError struct {
	expression string
	message    string
}

type logFunc func(ctx context.Context, expression string, err error)

type CELErrors struct {
	errors map[celError]struct{}
	log    logFunc
}

func NewCELErrors(level CELErrorLogLevel) *CELErrors {
	return &CELErrors{log: getLogFunc(level)}
}

func getLogFunc(level CELErrorLogLevel) logFunc {
	switch level {
	case CELErrorLogLevelNone:
		return func(context.Context, string, error) {}
	case CELErrorLogLevelDebug:
		return func(ctx context.Context, expression string, err error) {
			logger := logging.FromContext(ctx)
			celErrorHintOnce.Do(func() { logger.Debug(celErrorHint) })
			logger.Debug(celErrorMsg, logging.String("expression", expression), logging.Error(err))
		}
	case CELErrorLogLevelInfo:
		return func(ctx context.Context, expression string, err error) {
			logger := logging.FromContext(ctx)
			celErrorHintOnce.Do(func() { logger.Info(celErrorHint) })
			logger.Info(celErrorMsg, logging.String("expression", expression), logging.Error(err))
		}
	case CELErrorLogLevelError:
		return func(ctx context.Context, expression string, err error) {
			logger := logging.FromContext(ctx)
			celErrorHintOnce.Do(func() { logger.Error(celErrorHint) })
			logger.Error(celErrorMsg, logging.String("expression", expression), logging.Error(err))
		}
	default:
		return func(ctx context.Context, expression string, err error) {
			logger := logging.FromContext(ctx)
			celErrorHintOnce.Do(func() { logger.Warn(celErrorHint) })
			logger.Warn(celErrorMsg, logging.String("expression", expression), logging.Error(err))
		}
	}
}

func (c *CELErrors) Add(ctx context.Context, expression string, err error) {
	e := celError{expression: expression, message: err.Error()}
	if _, ok := c.errors[e]; ok {
		return
	}

	if c.errors == nil {
		c.errors = make(map[celError]struct{})
	}
	c.errors[e] = struct{}{}

	c.log(ctx, expression, err)
}

func (c *CELErrors) All() []*enginev1.EvaluationError {
	if c == nil || len(c.errors) == 0 {
		return nil
	}

	res := make([]*enginev1.EvaluationError, 0, len(c.errors))
	for e := range c.errors {
		res = append(res, &enginev1.EvaluationError{
			Error: &enginev1.EvaluationError_CelError{
				CelError: &enginev1.EvaluationError_CELError{Expression: e.expression, Message: e.message},
			},
		})
	}

	slices.SortFunc(res, func(a, b *enginev1.EvaluationError) int {
		x, y := a.GetCelError(), b.GetCelError()
		return cmp.Or(strings.Compare(x.GetExpression(), y.GetExpression()), strings.Compare(x.GetMessage(), y.GetMessage()))
	})

	return res
}
