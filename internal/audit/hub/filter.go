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

	for {
		r, size := utf8.DecodeRuneInString(path[curs:])
		if size == 0 {
			if err := b.Flush(); err != nil {
				return err
			}
			break
		}
		curs += size

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

	return nil
}

func (f *AuditLogFilter) Filter(ingestBatch *logsv1.IngestBatch) error {
	if f.ast == nil || len(f.ast.children) == 0 {
		return nil
	}

	for _, c := range f.ast.children {
		visitPb(c, ingestBatch.ProtoReflect())
	}

	return nil
}

func visitPb(t *token, m protoreflect.Message) {
	if value, ok := m.Interface().(*structpb.Value); ok {
		visitStructpb(t, value)
		return
	}

	processFd := func(fd protoreflect.FieldDescriptor) {
		var (
			mapVal  protoreflect.Map
			listVal protoreflect.List
			msgVal  protoreflect.Message
		)
		v := m.Get(fd)
		for _, c := range t.children {
			switch {
			case fd.IsMap():
				if mapVal == nil {
					mapVal = v.Map()
				}
				mapKey := protoreflect.ValueOfString(c.val.(string)).MapKey()
				mvv := mapVal.Get(mapKey)
				if mvv.IsValid() {
					if c.children == nil {
						mapVal.Clear(mapKey)
						continue
					}
					switch {
					case fd.MapValue().Message() != nil:
						visitPb(c, mvv.Message())
					default:
					}
				}
			case fd.IsList():
				if listVal == nil {
					listVal = v.List()
				}
				handleArrayIndex := func(idx int) {
					// For array indexes, reach ahead to the next token
					for _, nc := range c.children {
						visitPb(nc, listVal.Get(idx).Message())
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
				if msgVal == nil {
					msgVal = v.Message()
				}
				visitPb(c, msgVal)
			}
		}
	}

	switch t.typ {
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
	case tokenWildcard:
		m.Range(func(fd protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
			processFd(fd)
			return true
		})
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
							k.ListValue.Values = append(k.ListValue.Values[:idx], k.ListValue.Values[idx+1:]...)
						}
					}
					continue
				}
				visitStructpb(c, k.ListValue.Values[idx])
			}
		}
	}
}