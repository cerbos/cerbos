// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"errors"
	"fmt"
	"strconv"
	"unicode"
	"unicode/utf8"

	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	// TODO(saml) profile alternative prefixes? Separate, static entries for each log type perhaps
	// both log types.
	unionedPathPrefix = "entries[*][*]"
	peerPrefix        = unionedPathPrefix + ".peer"
	metadataPrefix    = unionedPathPrefix + ".metadata"

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
	typ      tokenType
	val      any
	children map[string]*token
}

func (t *token) key() string {
	switch t.typ {
	case tokenAccessor:
		return t.val.(string)
	case tokenIndex:
		return "[" + strconv.Itoa(t.val.(int)) + "]"
	case tokenWildcard:
		return "[*]"
	}
	return ""
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
		if err := parse(peerPrefix + "." + r); err != nil {
			outErr = multierr.Append(outErr, err)
		}
	}

	for _, r := range conf.Metadata {
		if err := parse(metadataPrefix + "." + r); err != nil {
			outErr = multierr.Append(outErr, err)
		}
	}

	for _, r := range conf.CheckResources {
		if err := parse(checkResourcesPrefix + "." + r); err != nil {
			outErr = multierr.Append(outErr, err)
		}

		if err := parse(checkResourcesDeprecatedPrefix + "." + r); err != nil {
			outErr = multierr.Append(outErr, err)
		}
	}

	for _, r := range conf.PlanResources {
		if err := parse(planResourcesPrefix + "." + r); err != nil {
			outErr = multierr.Append(outErr, err)
		}
	}

	return root, outErr
}

type state int8

const (
	stateUnknown state = iota
	statePlainAccessor
	stateParenOpen
	stateWildcard
	stateNumberOpen
	stateStringOpen
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
				tb.s = stateStringOpen
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
		case stateStringOpen:
			switch r {
			case '\'':
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
		var value any
		switch tb.t {
		case tokenAccessor:
			value = tb.buf
		case tokenIndex:
			idx, err := strconv.Atoi(tb.buf)
			if err != nil {
				return nil, err
			}
			value = idx
		}

		return &token{
			typ: tb.t,
			val: value,
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

func (f *AuditLogFilter) Filter(ingestBatch *logsv1.IngestBatch) error {
	if f.ast == nil || len(f.ast.children) == 0 {
		return nil
	}

	visitPb(f.ast, ingestBatch.ProtoReflect())

	return nil
}

func visitPb(t *token, m protoreflect.Message) {
	if t.typ != tokenUnknown {
		if value, ok := m.Interface().(*structpb.Value); ok {
			visitStructpb(t, value)
			return
		}

		processFd := func(fd protoreflect.FieldDescriptor) bool {
			v := m.Get(fd)
			switch {
			case fd.IsMap():
				mv := v.Map()
				for _, c := range t.children {
					mapKey := protoreflect.ValueOfString(c.key()).MapKey()
					mvv := mv.Get(mapKey)
					if mvv.IsValid() {
						if c.children == nil {
							mv.Clear(mapKey)
							return false
						}
						switch {
						case fd.MapValue().Message() != nil:
							visitPb(c, mvv.Message())
						default:
						}
					}
				}
			case fd.IsList():
				lv := v.List()
				for _, c := range t.children {
					handleArrayIndex := func(idx int) {
						// For array indexes, reach ahead to the next token
						for _, c := range c.children {
							visitPb(c, lv.Get(idx).Message())
						}
					}

					switch c.typ {
					case tokenWildcard:
						for i := 0; i < lv.Len(); i++ {
							handleArrayIndex(i)
						}
					case tokenIndex:
						idx := c.val.(int)
						if idx < lv.Len() {
							handleArrayIndex(idx)
						}
					}
				}
			case fd.Message() != nil:
				for _, c := range t.children {
					visitPb(c, v.Message())
				}
			}

			return true
		}

		switch t.typ {
		case tokenWildcard:
			m.Range(func(fd protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
				shouldContinue := processFd(fd)
				return shouldContinue
			})
		case tokenAccessor:
			fd := m.Descriptor().Fields().ByJSONName(t.val.(string))
			if fd == nil {
				// return early, message field does not exist
				return
			} else if t.children == nil {
				// field exists and token is leaf node, therefore delete the field from the message
				if m.Has(fd) {
					m.Clear(fd)
				}
				return
			}
			processFd(fd)
		}
	}

	for _, c := range t.children {
		visitPb(c, m)
	}
}

func visitStructpb(t *token, v *structpb.Value) {
	for _, c := range t.children {
		switch k := v.GetKind().(type) {
		case *structpb.Value_StructValue:
			val := c.val.(string)
			if c.children == nil {
				delete(k.StructValue.Fields, val)
				continue
			}
			if fv, ok := k.StructValue.Fields[val]; ok {
				visitStructpb(c, fv)
			}
		case *structpb.Value_ListValue:
			switch c.typ {
			case tokenWildcard:
				if c.children == nil {
					k.ListValue.Values = []*structpb.Value{}
					continue
				}
				for i := 0; i < len(k.ListValue.Values); i++ {
					visitStructpb(c, k.ListValue.Values[i])
				}
			case tokenIndex:
				idx := c.val.(int)
				if c.children == nil {
					// zero the key in the array
					k.ListValue.Values[idx] = structpb.NewListValue(&structpb.ListValue{})
					continue
				}
				visitStructpb(c, k.ListValue.Values[idx])
			}
		}
	}
}
