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
	astRoot *token
}

func NewAuditLogFilter(conf MaskConf) (*AuditLogFilter, error) {
	root, err := parseJSONPathExprs(conf)
	if err != nil {
		return nil, err
	}

	return &AuditLogFilter{
		astRoot: root,
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
	t        tokenType
	s        state
	size     int
	buf      string
	curToken *token
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
			// TODO(saml) use consts for all relevant runes???
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

func (tb *tokenBuilder) Flush() error {
	if tb.s != stateClosed && tb.s != statePlainAccessor {
		return fmt.Errorf("flush called in an invalid state: %v", tb.s)
	}

	if tb.size > 0 {
		var value any
		switch tb.t {
		case tokenAccessor:
			value = tb.buf
		case tokenIndex:
			idx, err := strconv.Atoi(tb.buf)
			if err != nil {
				return err
			}
			value = idx
		}

		t := &token{
			typ: tb.t,
			val: value,
		}

		// update AST
		if tb.curToken.children == nil {
			tb.curToken.children = make(map[string]*token)
		}

		if cached, ok := tb.curToken.children[t.key()]; ok {
			tb.curToken = cached
		} else {
			tb.curToken.children[t.key()] = t
			tb.curToken = t
		}
	}

	tb.buf = ""
	tb.t = tokenUnknown
	tb.size = 0

	return nil
}

func tokenize(root *token, path string) error {
	curs := 0
	b := &tokenBuilder{
		curToken: root,
	}

	for curs < len(path) {
		r, size := utf8.DecodeRuneInString(path[curs:])
		curs += size

		// handle token boundaries
		switch r {
		case '.':
			if err := b.Flush(); err != nil {
				return err
			}
		case '[':
			if err := b.Flush(); err != nil {
				return err
			}
			if err := b.WriteRune(r); err != nil {
				return ErrParse{errors.New("failed to write rune")}
			}
		case ']':
			if err := b.WriteRune(r); err != nil {
				return ErrParse{errors.New("failed to write rune")}
			}
			if err := b.Flush(); err != nil {
				return err
			}
		default:
			b.WriteRune(r)
		}
	}

	if err := b.Flush(); err != nil {
		return err
	}

	return nil
}

func (f *AuditLogFilter) Filter(ingestBatch *logsv1.IngestBatch) error {
	if f.astRoot == nil {
		return nil
	}

	for _, c := range f.astRoot.children {
		visit(c, ingestBatch.ProtoReflect())
	}

	return nil
}

func visit(t *token, m protoreflect.Message) {
	if value, ok := m.Interface().(*structpb.Value); ok {
		visitStructpb(t, value)
		return
	}

	var fieldsToInspect []protoreflect.FieldDescriptor
	switch t.typ {
	case tokenAccessor:
		fd := m.Descriptor().Fields().ByJSONName(t.val.(string))
		if fd == nil {
			return
		} else if t.children == nil {
			if m.Has(fd) {
				m.Clear(fd)
			}
			return
		}
		fieldsToInspect = []protoreflect.FieldDescriptor{fd}
	case tokenWildcard:
		fds := m.Descriptor().Fields()
		fieldsToInspect = make([]protoreflect.FieldDescriptor, fds.Len())
		for i := 0; i < fds.Len(); i++ {
			fieldsToInspect[i] = fds.Get(i)
		}
	}

	for _, fd := range fieldsToInspect {
		v := m.Get(fd)
		for _, c := range t.children {
			switch {
			case fd.IsMap():
				mapVal := v.Map() // apparently retrieving typed values each iteration causes no slow-down
				mapKey := protoreflect.ValueOfString(c.val.(string)).MapKey()
				mv := mapVal.Get(mapKey)
				if mv.IsValid() {
					if c.children == nil {
						mapVal.Clear(mapKey)
						continue
					}
					if fd.MapValue().Message() != nil {
						visit(c, mv.Message())
					}
				}
			case fd.IsList():
				listVal := v.List()
				handleArrayIndex := func(idx int) {
					// For array indexes, reach ahead to the next token.
					for _, nc := range c.children {
						visit(nc, listVal.Get(idx).Message())
					}
				}

				switch c.typ {
				case tokenWildcard:
					for i := 0; i < listVal.Len(); i++ {
						handleArrayIndex(i)
					}
				case tokenIndex:
					idx := c.val.(int)
					if idx < listVal.Len() {
						handleArrayIndex(idx)
					}
				}
			case fd.Message() != nil:
				visit(c, v.Message())
			}
		}
	}
}

func visitStructpb(t *token, v *structpb.Value) {
	for _, c := range t.children {
		switch k := v.GetKind().(type) {
		case *structpb.Value_StructValue:
			if c.children == nil {
				delete(k.StructValue.Fields, c.val.(string))
				continue
			}
			if fv, ok := k.StructValue.Fields[c.val.(string)]; ok {
				visitStructpb(c, fv)
			}
		case *structpb.Value_ListValue:
			switch c.typ {
			case tokenWildcard:
				if c.children == nil {
					v = nil
					continue
				}
				for i := 0; i < len(k.ListValue.Values); i++ {
					visitStructpb(c, k.ListValue.Values[i])
				}
			case tokenIndex:
				idx := c.val.(int)
				if c.children == nil {
					if l := len(k.ListValue.Values); idx < l {
						if l == 1 {
							v = nil
						} else {
							copy(k.ListValue.Values[idx:], k.ListValue.Values[idx+1:])
							k.ListValue.Values = k.ListValue.Values[:len(k.ListValue.Values)-1]
						}
					}
					continue
				}
				visitStructpb(c, k.ListValue.Values[idx])
			}
		}
	}
}
