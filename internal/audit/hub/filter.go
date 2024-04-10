// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
	"github.com/iancoleman/strcase"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/reflect/protopath"
	"google.golang.org/protobuf/reflect/protorange"
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
	t        tokenType
	v        string
	children map[string]*token
}

func (t *token) key() string {
	return t.v
}

type AuditLogFilter struct {
	ast *token
}

func NewAuditLogFilter(conf MaskConf) (*AuditLogFilter, error) {
	root, err := parseJSONPathExprs(conf)
	if err != nil {
		return nil, err
	}

	return &AuditLogFilter{
		ast: root,
	}, nil
}

func parseJSONPathExprs(conf MaskConf) (ast *token, outErr error) {
	root := &token{}

	parse := func(rule string) error {
		if err := tokenize(root, rule); err != nil {
			return err
		}

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
	return root, outErr
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
	buf  string
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
				return nil
			default:
				// TODO(saml) extra validation?
			}
		case stateDoubleQuoteOpen:
			switch r {
			case '\'':
				return errors.New("unexpected character in double quote: '\"'")
			case '"':
				tb.s = stateStringClosed
				return nil
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

	tb.buf += string(r)

	return nil
}

func (tb *tokenBuilder) Flush() (t *token, err error) {
	if tb.s != stateClosed && tb.s != statePlainAccessor {
		return t, fmt.Errorf("flush called in an invalid state: %v", tb.s)
	}

	defer func() {
		tb.buf = ""
		tb.t = tokenUnknown
		tb.size = 0
	}()

	if tb.size > 0 {
		var value string
		switch tb.t {
		case tokenAccessor:
			value = tb.buf
		case tokenIndex:
			value = "[" + tb.buf + "]"
		case tokenWildcard:
			value = "[*]"
		}

		return &token{
			t: tb.t,
			v: value,
		}, nil
	}

	return t, nil
}

func tokenize(root *token, path string) error {
	var (
		curs     int
		curToken = root
	)

	// TODO(saml) is the stack necessary anymore?
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
			if curToken.children == nil {
				curToken.children = make(map[string]*token)
			}

			if cached, ok := curToken.children[t.key()]; ok {
				curToken = cached
			} else {
				curToken.children[t.key()] = t
				curToken = t
			}
		}

		return nil
	}
	for {
		r, cont := nextRune()
		if !cont {
			if err := flushToken(); err != nil {
				return err
			}
			break
		}

		switch r {
		case '.':
			if err := flushToken(); err != nil {
				return err
			}
		case '[':
			if last, exists := stack.peek(); exists && last == '[' {
				return ErrParse{
					errors.New("cannot nest `[` symbols"),
				}
			}

			stack.push(r)
			if err := flushToken(); err != nil {
				return err
			}
			if err := b.WriteRune(r); err != nil {
				return ErrParse{errors.New("failed to write rune")}
			}
		case ']':
			if last, exists := stack.pop(); !exists || last != '[' {
				return ErrParse{
					errors.New("no matching `[`"),
				}
			}

			b.WriteRune(r)
			if err := flushToken(); err != nil {
				return err
			}
		case '\'', '"':
			// we don't support nested quotations, so assert that any pairs use consistent quotations
			if last, exists := stack.peek(); exists && (last == '\'' || last == '"') && last != r {
				return ErrParse{
					fmt.Errorf("non-matching quotation pair: %c and %c", last, r),
				}
			}
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}

	return nil
}

type filterCase int

const (
	filterCaseProcessing filterCase = iota // still matching but not at leaf node
	filterCaseNoMatch                      // stop searching
	filterCaseMatch
)

// TODO(saml) is this bad practice?
var camelCache = make(map[string]string)

func (f *AuditLogFilter) Filter(ingestBatch *logsv1.IngestBatch) error {
	if f.ast == nil || len(f.ast.children) == 0 {
		return nil
	}

	cachedToLowerCamel := func(s string) string {
		if cameled, ok := camelCache[s]; ok {
			return cameled
		}

		camel := strcase.ToLowerCamel(s) // TODO(saml) this is hugely inefficient
		camelCache[s] = camel
		return camel
	}

	checkExistence := func(p protopath.Path) filterCase {
		segments := make([]string, 0, len(p))
		for _, step := range p {
			// runtime.Breakpoint()
			s := step.String()
			if s[0] == '.' {
				s = s[1:]
			}
			switch step.Kind() {
			case protopath.FieldAccessStep:
				googlePrefix := "google.protobuf"
				if string(step.FieldDescriptor().FullName()[:len(googlePrefix)]) == googlePrefix {
					continue
				}
				s = cachedToLowerCamel(s)
			case protopath.MapIndexStep:
				// TODO(saml) more bulletproof way
				s = strings.TrimPrefix(s, "[\"")
				s = strings.TrimSuffix(s, "\"]")
				// TODO(saml) profile the below - reflections might be slower
				// s = step.MapIndex().String()
			}
			segments = append(segments, s)
		}

		// Traverse down all valid paths
		var visit func(*token, []string) filterCase
		visit = func(n *token, segments []string) filterCase {
			// Leaf node infers the rule is satisfied
			if n.children == nil {
				return filterCaseMatch
			}

			if len(segments) > 0 {
				s := segments[0]
				segments = segments[1:]

				if n, ok := n.children[s]; ok {
					if res := visit(n, segments); res == filterCaseMatch {
						return res
					}
				}

				if n, ok := n.children["[*]"]; ok {
					if res := visit(n, segments); res == filterCaseMatch {
						return res
					}
				}
			}

			return filterCaseProcessing
		}

		return visit(f.ast, segments)
	}

	protorange.Range(ingestBatch.ProtoReflect(), func(p protopath.Values) error {
		if len(p.Path) == 1 {
			return nil
		}

		switch checkExistence(p.Path[1:]) {
		case filterCaseProcessing:
			// runtime.Breakpoint()
			return nil
			// TODO need to return one level lower??
			// return protorange.Break
		case filterCaseMatch:
			last := p.Index(-1)
			beforeLast := p.Index(-2)
			switch last.Step.Kind() {
			case protopath.FieldAccessStep:
				m := beforeLast.Value.Message()
				fd := last.Step.FieldDescriptor()
				m.Clear(fd)
			case protopath.ListIndexStep:
				// TODO(saml) Do we need to support this?
				// ls := beforeLast.Value.List()
				// i := last.Step.ListIndex()
			case protopath.MapIndexStep:
				ms := beforeLast.Value.Map()
				k := last.Step.MapIndex()
				ms.Clear(k)
			}
		}

		return nil
	})

	return nil
}
