// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	peerPart             = "peer"
	metadataPart         = "metadata"
	checkResourcesPrefix = "decisionLogEntry.checkResources"
	planResourcesPrefix  = "decisionLogEntry.planResources"
)

var entryKindPrefixes = []string{"accessLogEntry", "decisionLogEntry"}

type tokenType int8

const (
	tokenUnknown tokenType = iota
	tokenAccessor
	tokenIndex
	tokenWildcard
)

type Token struct {
	val      any
	children map[string]*Token
	typ      tokenType
}

func (t *Token) key() string {
	switch t.typ {
	case tokenAccessor:
		return t.val.(string) //nolint:forcetypeassert
	case tokenIndex:
		return "[" + strconv.Itoa(t.val.(int)) + "]" //nolint:forcetypeassert
	case tokenWildcard:
		return "[*]"
	default:
		return ""
	}
}

type AuditLogFilter struct {
	astRoot *Token
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

func parseJSONPathExprs(conf MaskConf) (ast *Token, outErr error) {
	root := &Token{}

	parse := func(rule string) error {
		if err := Tokenize(root, rule); err != nil {
			return err
		}

		return nil
	}

	for _, r := range conf.Peer {
		for _, k := range entryKindPrefixes {
			if err := parse(strings.Join([]string{k, peerPart, r}, ".")); err != nil {
				outErr = multierr.Append(outErr, err)
			}
		}
	}

	for _, r := range conf.Metadata {
		for _, k := range entryKindPrefixes {
			if err := parse(strings.Join([]string{k, metadataPart, r}, ".")); err != nil {
				outErr = multierr.Append(outErr, err)
			}
		}
	}

	for _, r := range conf.CheckResources {
		if err := parse(checkResourcesPrefix + "." + r); err != nil {
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
	curToken *Token
	buf      string
	size     int
	t        tokenType
	s        state
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
			return fmt.Errorf("invalid first character: %c", r)
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
			if !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '_' {
				return fmt.Errorf("unexpected character for accessor: %c", r)
			}
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
			if r == '\'' {
				tb.s = stateStringClosed
				return nil
			}
		case stateStringClosed:
			if r != ']' {
				return fmt.Errorf("expected ']' after string, found: %c", r)
			}
			tb.s = stateClosed
			return nil
		default:
			return fmt.Errorf("unexpected state: %v", tb.s)
		}
	}

	tb.buf += string(r)

	return nil
}

func (tb *tokenBuilder) Flush() error {
	switch tb.s {
	case stateClosed, statePlainAccessor:
	case stateStringOpen:
		return errors.New("invalid string not closed")
	default:
		return fmt.Errorf("flush called in an invalid state: %v", tb.s)
	}

	if tb.size > 0 {
		var value any
		switch tb.t { //nolint:exhaustive
		case tokenAccessor:
			value = tb.buf
		case tokenIndex:
			idx, err := strconv.Atoi(tb.buf)
			if err != nil {
				return err
			}
			value = idx
		}

		t := &Token{
			typ: tb.t,
			val: value,
		}

		if tb.curToken.children == nil {
			tb.curToken.children = make(map[string]*Token)
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

func Tokenize(root *Token, path string) error {
	curs := 0
	b := &tokenBuilder{
		curToken: root,
	}

	var prev rune
	for curs < len(path) {
		r, size := utf8.DecodeRuneInString(path[curs:])
		curs += size

		// handle and validate token boundaries
		switch r {
		case '.':
			switch {
			case curs == size:
				return errors.New("invalid first character: '.'")
			case curs == len(path):
				return errors.New("invalid final character: '.'")
			case prev == '.':
				return errors.New("invalid empty token")
			}

			if err := b.Flush(); err != nil {
				return err
			}
		case '[':
			if err := b.Flush(); err != nil {
				return err
			}
			if err := b.WriteRune(r); err != nil {
				return err
			}
		case ']':
			if err := b.WriteRune(r); err != nil {
				return err
			}
			if err := b.Flush(); err != nil {
				return err
			}
		default:
			if err := b.WriteRune(r); err != nil {
				return err
			}
		}

		prev = r
	}

	if err := b.Flush(); err != nil {
		return err
	}

	return nil
}

func (f *AuditLogFilter) Filter(entry *logsv1.IngestBatch_Entry) error {
	if f.astRoot == nil {
		return nil
	}

	ib := entry.ProtoReflect()
	for _, c := range f.astRoot.children {
		visit(c, ib)
	}

	return nil
}

// We support a subset of JSONPath operations, as follows:
//
// - dot notation: `foo.bar.baz`
// - or bracket-notation: `['foo']['bar']['baz]`
// - or combinations thereof
//
// `bar` or `baz` above can be map keys, nested messages or structs.
//
// We support list indexing with Ints or wildcards:
// - foo.bar[0]
// - foo.bar[*]
//
// Wildcards can also operate on member names as a match-all. E.g `foo[*].baz`
// will match both `baz` values in the pseudo-object below:
//
//	{
//	  'foo': {
//	    'pow': {
//	        'baz',
//	    },
//	    'bosh': {
//	        'baz',
//	    },
//	  }
//	}
func visit(t *Token, m protoreflect.Message) {
	if m.Type().Descriptor().FullName() == "google.protobuf.Value" {
		visitStructpb(t, m.Interface().(*structpb.Value)) //nolint:forcetypeassert
		return
	}

	var fieldsToInspect []protoreflect.FieldDescriptor
	switch t.typ { //nolint:exhaustive
	case tokenAccessor:
		fd := m.Descriptor().Fields().ByJSONName(t.val.(string)) //nolint:forcetypeassert
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
		for i := range fds.Len() {
			fieldsToInspect[i] = fds.Get(i)
		}
	}

	for _, fd := range fieldsToInspect {
		v := m.Get(fd)
		for _, c := range t.children {
			switch {
			case fd.IsMap():
				mapVal := v.Map() // apparently retrieving typed values each iteration causes no slow-down
				k, ok := c.val.(string)
				if !ok {
					continue
				}
				mapKey := protoreflect.ValueOfString(k).MapKey()
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

				switch c.typ { //nolint:exhaustive
				case tokenWildcard:
					for i := range listVal.Len() {
						handleArrayIndex(i)
					}
				case tokenIndex:
					if idx := c.val.(int); idx < listVal.Len() { //nolint:forcetypeassert
						handleArrayIndex(idx)
					}
				}
			case fd.Message() != nil:
				visit(c, v.Message())
			}
		}
	}
}

func visitStructpb(t *Token, v *structpb.Value) {
	for _, c := range t.children {
		switch k := v.GetKind().(type) {
		case *structpb.Value_StructValue:
			name, ok := c.val.(string)
			if !ok {
				continue
			}
			if c.children == nil {
				delete(k.StructValue.Fields, name)
				continue
			}
			if fv, ok := k.StructValue.Fields[name]; ok {
				visitStructpb(c, fv)
			}
		case *structpb.Value_ListValue:
			switch c.typ { //nolint:exhaustive
			case tokenWildcard:
				if c.children == nil {
					v = nil
					continue
				}
				for i := range k.ListValue.Values {
					visitStructpb(c, k.ListValue.Values[i])
				}
			case tokenIndex:
				idx, ok := c.val.(int)
				if !ok {
					continue
				}
				if c.children == nil {
					if l := len(k.ListValue.Values); idx < l {
						if l == 1 {
							v = nil
						} else {
							k.ListValue.Values = slices.Delete(k.ListValue.Values, idx, idx+1)
						}
					}
					continue
				}
				visitStructpb(c, k.ListValue.Values[idx])
			}
		}
	}
}
