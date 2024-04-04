// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
	"go.uber.org/multierr"
)

const (
	// TODO(saml) profile alternative prefixes? Separate, static entries for each log type perhaps
	// both log types.
	unionedPathPrefix = "$.entries[*][*]"
	peerPrefix        = unionedPathPrefix + ".peer"
	metadataPrefix    = unionedPathPrefix + ".metadata"

	checkResourcesDeprecatedPrefix = "$.entries[*].decisionLogEntry"
	checkResourcesPrefix           = "$.entries[*].decisionLogEntry.checkResources"
	planResourcesPrefix            = "$.entries[*].decisionLogEntry.planResources"
)

// TODO(saml) How to store/represent error?
type ErrParse struct {
	underlying error
}

func (e ErrParse) Error() string {
	return e.underlying.Error()
}

type lexer struct {
	tokens []string
}

type AuditLogFilter struct {
	exprs []*lexer
}

func NewAuditLogFilter(conf MaskConf) (*AuditLogFilter, error) {
	expr, err := parseJSONPathExprs(conf)
	if err != nil {
		return nil, err
	}

	return &AuditLogFilter{
		exprs: expr,
	}, nil
}

func parseJSONPathExprs(conf MaskConf) (exprs []*lexer, outErr error) {
	// len(conf.CheckResources)*2 caters for two required rules
	// (deprecated base level inputs/outputs, and nested inside `check_resources`)
	nExpressions := len(conf.Peer) + len(conf.Metadata) + len(conf.CheckResources)*2 + len(conf.PlanResources)
	if nExpressions == 0 {
		return exprs, nil
	}

	exprs = make([]*lexer, nExpressions)

	i := 0
	parse := func(rule string) error {
		e, err := tokenize(rule)
		if err != nil {
			return err
		}

		exprs[i] = e
		i++
		return nil
	}

	for _, r := range conf.Peer {
		if err := parse(fmt.Sprintf("%s.%s", peerPrefix, r)); err != nil {
			outErr = multierr.Append(outErr, err)
		}
	}

	for _, r := range conf.Metadata {
		if err := parse(fmt.Sprintf("%s.%s", metadataPrefix, r)); err != nil {
			outErr = multierr.Append(outErr, err)
		}
	}

	for _, r := range conf.CheckResources {
		if err := parse(fmt.Sprintf("%s.%s", checkResourcesPrefix, r)); err != nil {
			outErr = multierr.Append(outErr, err)
		}

		if err := parse(fmt.Sprintf("%s.%s", checkResourcesDeprecatedPrefix, r)); err != nil {
			outErr = multierr.Append(outErr, err)
		}
	}

	for _, r := range conf.PlanResources {
		if err := parse(fmt.Sprintf("%s.%s", planResourcesPrefix, r)); err != nil {
			outErr = multierr.Append(outErr, err)
		}
	}

	// runtime.Breakpoint()
	return exprs, outErr
}

func tokenize(path string) (*lexer, error) {
	var (
		b      strings.Builder
		curs   int
		tokens []string
	)

	stack := newStack[rune]()

	nextRune := func() (rune, bool) {
		str := path[curs:]
		if len(str) == 0 {
			return -1, false
		}

		r, s := utf8.DecodeRuneInString(str)
		curs += s

		return r, true
	}

	flushToken := func() {
		if b.Len() > 0 {
			tokens = append(tokens, b.String())
			b.Reset()
		}
	}

	for {
		r, cont := nextRune()
		if !cont {
			flushToken()
			break
		}

		switch r {
		case '.':
			flushToken()
		case '[':
			if last, exists := stack.peek(); exists && last == '[' {
				return nil, ErrParse{
					errors.New("cannot nest `[` symbols"),
				}
			}

			stack.push(r)
			flushToken()
			b.WriteRune(r)
		case ']':
			if last, exists := stack.pop(); !exists || last != '[' {
				return nil, ErrParse{
					errors.New("no matching `[`"),
				}
			}

			b.WriteRune(r)
			flushToken()
		case '\'', '"':
			// we don't support nested quotations, so assert that any pairs use consistent quotations
			if last, exists := stack.peek(); exists && (last == '\'' || last == '"') && last != r {
				return nil, ErrParse{
					fmt.Errorf("non-matching quotation pair: %c and %c", last, r),
				}
			}
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}

	// TODO(saml) validation
	if b.Len() > 0 {
		return nil, ErrParse{
			errors.New("invalid path"),
		}
	}
	if stack.len() > 0 {
		return nil, ErrParse{
			errors.New("invalid path: no closing symbol"),
		}
	}

	return &lexer{tokens}, nil
}

func (f *AuditLogFilter) Filter(ingestBatch *logsv1.IngestBatch) (*logsv1.IngestBatch, error) {
	if len(f.exprs) == 0 {
		return ingestBatch, nil
	}

	return ingestBatch, nil
}
