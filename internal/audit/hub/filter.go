// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
	"go.uber.org/multierr"
)

const (
	// TODO(saml) profile alternative prefixes? Separate, static entries for each log type perhaps
	// both log types.
	// unionedPathPrefix = "$.entries[*][*]"
	unionedPathPrefix = "entries[*][*]"
	peerPrefix        = unionedPathPrefix + ".peer"
	metadataPrefix    = unionedPathPrefix + ".metadata"

	// checkResourcesDeprecatedPrefix = "$.entries[*].decisionLogEntry"
	// checkResourcesPrefix           = "$.entries[*].decisionLogEntry.checkResources"
	// planResourcesPrefix            = "$.entries[*].decisionLogEntry.planResources"
	checkResourcesDeprecatedPrefix = "entries[*].decisionLogEntry"
	checkResourcesPrefix           = "entries[*].decisionLogEntry.checkResources"
	planResourcesPrefix            = "entries[*].decisionLogEntry.planResources"
)

// TODO(saml) How to store/represent error?
type ErrParse struct {
	underlying error
}

func (e ErrParse) Error() string {
	return e.underlying.Error()
}

type tokenType int8

const (
	tokenUnknown tokenType = iota
	tokenAccessor
	tokenIndex
	tokenWildcard
)

type token struct {
	t tokenType
	v any
}

type lexer struct {
	tokens []*token
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

type state int8

const (
	stateUnknown state = iota
	statePlainAccessor
	stateParenOpen
	stateWildcard
	stateNumberOpen
	stateSingleQuoteOpen
	stateDoubleQuoteOpen
	stateStringClosed
	stateClosed
)

type tokenBuilder struct {
	t    tokenType
	s    state
	size int
	b    strings.Builder
}

func (tb *tokenBuilder) WriteRune(r rune) error {
	defer func() {
		tb.size += utf8.RuneLen(r)
	}()

	switch tb.size {
	case 0:
		switch {
		case unicode.IsLetter(r):
			tb.s = statePlainAccessor
			tb.t = tokenAccessor
		case r == '[':
			tb.s = stateParenOpen
			return nil
		default:
			return fmt.Errorf("invalid initial rune: %c", r)
		}
	case 1:
		switch tb.s {
		case statePlainAccessor:
		case stateParenOpen:
			switch {
			case unicode.IsDigit(r):
				tb.s = stateNumberOpen
				tb.t = tokenIndex
			case r == '*':
				tb.s = stateWildcard
				tb.t = tokenWildcard
				return nil
			case r == '\'':
				tb.s = stateSingleQuoteOpen
				tb.t = tokenAccessor
				return nil
			case r == '"':
				tb.s = stateDoubleQuoteOpen
				tb.t = tokenAccessor
				return nil
			default:
				return fmt.Errorf("invalid character following '[': %c", r)
			}
		default:
			return fmt.Errorf("unexpected state: %v", tb.s)
		}
	default:
		switch tb.s {
		case statePlainAccessor:
		case stateNumberOpen:
			switch {
			case unicode.IsDigit(r):
			case r == ']':
				tb.s = stateClosed
				return nil
			default:
				return fmt.Errorf("unexpected character in number: %c", r)
			}
		case stateWildcard:
			if r != ']' {
				return fmt.Errorf("expected ']' after '*', found: %c", r)
			}
			tb.s = stateClosed
			return nil
		case stateSingleQuoteOpen:
			switch r {
			case '"':
				return errors.New("unexpected character in single quote: '['")
			case '\'':
				tb.s = stateStringClosed
			default:
				// TODO(saml) extra validation?
			}
		case stateDoubleQuoteOpen:
			switch r {
			case '\'':
				return errors.New("unexpected character in double quote: '\"'")
			case '"':
				tb.s = stateStringClosed
			default:
				// TODO(saml) extra validation?
			}
		case stateStringClosed:
			if r != ']' {
				return fmt.Errorf("expected ']' after string, found: %c", r)
			}
			tb.s = stateClosed
			return nil
		}
	}

	// TODO(saml) handle empty strings?
	// Only allow `Flush` on statePlainAccessor or stateClosed?

	_, err := tb.b.WriteRune(r)
	if err != nil {
		return err
	}

	return nil
}

func (tb *tokenBuilder) Flush() (t *token, err error) {
	if tb.s != stateClosed && tb.s != statePlainAccessor {
		return t, fmt.Errorf("flush called in an invalid state: %v", tb.s)
	}

	defer func() {
		tb.b.Reset()
		tb.t = tokenUnknown
		tb.size = 0
	}()

	if tb.size > 0 {
		var value any
		switch tb.t {
		case tokenAccessor:
			value = tb.b.String()
		case tokenIndex:
			value, err = strconv.Atoi(tb.b.String())
			if err != nil {
				return t, err
			}
		}

		return &token{
			t: tb.t,
			v: value,
		}, nil
	}

	return t, nil
}

func tokenize(path string) (*lexer, error) {
	var (
		curs   int
		tokens []*token
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

	b := &tokenBuilder{}
	flushToken := func() error {
		t, err := b.Flush()
		if err != nil {
			return err
		}

		if t != nil {
			tokens = append(tokens, t)
		}

		return nil
	}

	for {
		r, cont := nextRune()
		if !cont {
			if err := flushToken(); err != nil {
				return nil, err
			}
			break
		}

		switch r {
		case '.':
			if err := flushToken(); err != nil {
				return nil, err
			}
		case '[':
			if last, exists := stack.peek(); exists && last == '[' {
				return nil, ErrParse{
					errors.New("cannot nest `[` symbols"),
				}
			}

			stack.push(r)
			if err := flushToken(); err != nil {
				return nil, err
			}
			if err := b.WriteRune(r); err != nil {
				return nil, ErrParse{errors.New("failed to write rune")}
			}
		case ']':
			if last, exists := stack.pop(); !exists || last != '[' {
				return nil, ErrParse{
					errors.New("no matching `[`"),
				}
			}

			b.WriteRune(r)
			if err := flushToken(); err != nil {
				return nil, err
			}
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

	return &lexer{tokens}, nil
}

func (f *AuditLogFilter) Filter(ingestBatch *logsv1.IngestBatch) (*logsv1.IngestBatch, error) {
	if len(f.exprs) == 0 {
		return ingestBatch, nil
	}

	return ingestBatch, nil
}
