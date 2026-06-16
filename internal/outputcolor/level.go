// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package outputcolor

import (
	"fmt"
	"os"
	"reflect"

	"github.com/alecthomas/kong"
	"github.com/jwalton/go-supportscolor"
)

type Level uint8

const (
	None    = Level(supportscolor.None)
	Basic   = Level(supportscolor.Basic)
	Ansi256 = Level(supportscolor.Ansi256)
	Ansi16m = Level(supportscolor.Ansi16m)
)

func DefaultLevel() Level {
	return Level(supportscolor.SupportsColor(os.Stdout.Fd(), supportscolor.SniffFlagsOption(false)).Level)
}

var TypeMapper = kong.TypeMapper(reflect.TypeFor[*Level](), kong.MapperFunc(decode))

func (l *Level) Resolve(disable bool) Level {
	if disable {
		return None
	}

	if l != nil {
		return *l
	}

	return DefaultLevel()
}

func (l Level) Enabled() bool {
	return l > None
}

func decode(ctx *kong.DecodeContext, target reflect.Value) error {
	level, err := scan(ctx)
	if err != nil {
		return err
	}

	target.Set(reflect.ValueOf(level))
	return nil
}

func scan(ctx *kong.DecodeContext) (*Level, error) {
	token := ctx.Scan.Peek()

	switch token.Type {
	case kong.FlagValueToken:
		return parse(ctx.Scan.Pop().Value)

	case kong.ShortFlagTailToken, kong.UntypedToken:
		level, err := parse(token.Value)
		if err == nil {
			ctx.Scan.Pop()
			return level, nil
		}

	default:
	}

	return pointer(Basic), nil
}

func parse(v any) (*Level, error) {
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("invalid flag value (expected string, got %T)", v)
	}

	switch s {
	case "auto":
		return nil, nil

	case "false", "never":
		return pointer(None), nil

	case "true", "always":
		return pointer(Basic), nil

	case "256":
		return pointer(Ansi256), nil

	case "16m", "full", "truecolor":
		return pointer(Ansi16m), nil

	default:
		return nil, fmt.Errorf("invalid value for output color level: %q", s)
	}
}

func pointer(level Level) *Level {
	return &level
}
