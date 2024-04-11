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
	filterCaseUnknown filterCase = iota
	filterCaseNoMatch
	filterCaseMatch
)

func (f *AuditLogFilter) Filter(ingestBatch *logsv1.IngestBatch) error {
	if f.ast == nil || len(f.ast.children) == 0 {
		return nil
	}

	var visitStructpb func(*token, *structpb.Value)
	visitStructpb = func(t *token, v *structpb.Value) {
		switch k := v.GetKind().(type) {
		case *structpb.Value_NumberValue:
		case *structpb.Value_StringValue:
		case *structpb.Value_BoolValue:
		case *structpb.Value_StructValue:
			for _, c := range t.children {
				key := c.key()
				if c.children == nil {
					delete(k.StructValue.Fields, key)
					continue
				}
				if val, ok := k.StructValue.Fields[key]; ok {
					visitStructpb(c, val)
				}
			}
		case *structpb.Value_ListValue:
			for _, c := range t.children {
				key := c.key()
				switch c.t {
				case tokenWildcard:
					// TODO(saml) iterate over all keys
					if c.children == nil {
						k.ListValue.Values = []*structpb.Value{}
						continue
					}
					for i := 0; i < len(k.ListValue.Values); i++ {
						visitStructpb(c, k.ListValue.Values[i])
					}
				case tokenIndex:
					idx, err := strconv.Atoi(key[1 : len(key)-1])
					if err != nil {
						return
					}
					if c.children == nil {
						// delete the key from the array
						k.ListValue.Values[idx] = structpb.NewListValue(&structpb.ListValue{})
						// TODO(saml) could delete the item entirely with the below?
						// k.ListValue.Values = append(k.ListValue.Values[:idx], k.ListValue.Values[idx+1:]...)
						continue
					}
					visitStructpb(c, k.ListValue.Values[idx])
				}
			}
		}
	}

	var visit func(*token, protoreflect.Message)
	visit = func(t *token, m protoreflect.Message) {
		if t.t != tokenUnknown {
			key := t.key() // TODO(saml) inline

			if value, ok := m.Interface().(*structpb.Value); ok {
				visitStructpb(t, value)
				return
			}

			d := m.Descriptor()
			var fds []protoreflect.FieldDescriptor
			// TODO(saml) could I use m.Range() here instead of this manual fd generation?
			if key == "[*]" {
				l := d.Fields().Len()
				fds = make([]protoreflect.FieldDescriptor, l)
				for i := 0; i < l; i++ {
					fd := d.Fields().Get(i)
					fds[i] = fd
				}
			} else {
				fd := d.Fields().ByJSONName(key)
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
				fds = []protoreflect.FieldDescriptor{fd}
			}

			for _, fd := range fds {
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
								return
							}
							vfd := fd.MapValue()
							switch {
							// case vfd.IsMap():
							// case vfd.IsList():
							case vfd.Message() != nil:
								msg := mvv.Message()
								visit(c, msg)
							default:
							}
						}
					}
				case fd.IsList():
					lv := v.List()
					for _, c := range t.children {
						handleArrayIndex := func(idx int) {
							// For array indexes, reach ahead to the next token
							// TODO(saml) should there only ever be one child?
							lvv := lv.Get(idx)
							for _, c := range c.children {
								if fd.Message() != nil {
									msg := lvv.Message()
									visit(c, msg)
								}
							}
						}

						switch c.t {
						case tokenWildcard:
							for i := 0; i < lv.Len(); i++ {
								handleArrayIndex(i)
							}
						case tokenIndex:
							idx, err := strconv.Atoi(c.v[1 : len(c.v)-1])
							if err != nil {
								return
							}
							if lv.Len() <= idx {
								return
							}

							handleArrayIndex(idx)
						default:
							return
						}
					}
				case fd.Message() != nil:
					msg := v.Message()
					for _, c := range t.children {
						visit(c, msg)
					}
				}
			}
		}

		for _, c := range t.children {
			visit(c, m)
		}
	}

	m := ingestBatch.ProtoReflect()
	visit(f.ast, m)

	return nil
}
