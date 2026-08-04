// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/observability/logging"
)

// StrictEvaluationError is raised when strict evaluation mode is enabled and a CEL runtime error occurs during evaluation.
// It never escapes the engine: the check and plan evaluators convert it into a DENY for the affected action.
type StrictEvaluationError struct {
	Err        error
	Expression string
}

func (e StrictEvaluationError) Error() string {
	return fmt.Sprintf("error evaluating expression %q: %v", e.Expression, e.Err)
}

func (e StrictEvaluationError) Unwrap() error {
	return e.Err
}

func (e StrictEvaluationError) Is(target error) bool {
	return errors.As(target, &StrictEvaluationError{})
}

const (
	celErrorMsg = "Error evaluating CEL expression"
)

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
			logger.Debug(celErrorMsg, logging.String("expression", expression), logging.Error(err))
		}
	case CELErrorLogLevelInfo:
		return func(ctx context.Context, expression string, err error) {
			logger := logging.FromContext(ctx)
			logger.Info(celErrorMsg, logging.String("expression", expression), logging.Error(err))
		}
	case CELErrorLogLevelError:
		return func(ctx context.Context, expression string, err error) {
			logger := logging.FromContext(ctx)
			logger.Error(celErrorMsg, logging.String("expression", expression), logging.Error(err))
		}
	default:
		return func(ctx context.Context, expression string, err error) {
			logger := logging.FromContext(ctx)
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
