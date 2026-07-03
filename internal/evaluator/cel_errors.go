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
	celErrorHint = `CEL evaluation errors detected; set engine.celErrorLogLevel to "none" to silence these messages. From Cerbos v0.55, a DENY rule whose condition raises a runtime error will be applied instead of skipped`
)

var celErrorHintOnce sync.Once

type celError struct {
	expression string
	message    string
}

type CELErrors struct {
	errors map[celError]struct{}
	level  CELErrorLogLevel
}

func NewCELErrors(level CELErrorLogLevel) *CELErrors {
	return &CELErrors{level: level}
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

	if c.level == CELErrorLogLevelNone {
		return
	}

	celErrorHintOnce.Do(func() {
		c.logHint(ctx)
	})
	c.logError(ctx, expression, err)
}

func (c *CELErrors) All() []*enginev1.CELError {
	if c == nil || len(c.errors) == 0 {
		return nil
	}

	res := make([]*enginev1.CELError, 0, len(c.errors))
	for e := range c.errors {
		res = append(res, &enginev1.CELError{Expression: e.expression, Message: e.message})
	}

	slices.SortFunc(res, func(a, b *enginev1.CELError) int {
		return cmp.Or(strings.Compare(a.Expression, b.Expression), strings.Compare(a.Message, b.Message))
	})

	return res
}

func (c *CELErrors) logHint(ctx context.Context) {
	logger := logging.FromContext(ctx)
	switch c.level {
	case CELErrorLogLevelDebug:
		logger.Debug(celErrorHint)
	case CELErrorLogLevelInfo:
		logger.Info(celErrorHint)
	case CELErrorLogLevelError:
		logger.Error(celErrorHint)
	default:
		logger.Warn(celErrorHint)
	}
}

func (c *CELErrors) logError(ctx context.Context, expression string, err error) {
	logger := logging.FromContext(ctx)
	expr, cause := logging.String("expression", expression), logging.Error(err)
	switch c.level {
	case CELErrorLogLevelDebug:
		logger.Debug(celErrorMsg, expr, cause)
	case CELErrorLogLevelInfo:
		logger.Info(celErrorMsg, expr, cause)
	case CELErrorLogLevelError:
		logger.Error(celErrorMsg, expr, cause)
	default:
		logger.Warn(celErrorMsg, expr, cause)
	}
}
