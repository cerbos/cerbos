package wasm

import (
	"fmt"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"errors"
	"golang.org/x/exp/slices"
)

var (
	ErrUnsupportedType = errors.New("unsupported jsonschema type")
)

func ConvertSchema(s *jsonschema.Schema) ([]*Field, error) {
	fields := make([]*Field, 0, len(s.Properties))

	for n, schema := range s.Properties {
		required := slices.Index(s.Required, n) > 0
		var f *Field
		if t1, ok := mapTypes[schema.Types[0]]; ok {
			if t1 == "Vec" {
				if t2, ok := mapTypes[schema.Items2020.Types[0]]; ok {
					t1 = fmt.Sprintf("Vec<%s>", t2)
				} else {
					return nil, fmt.Errorf("array item type %q: %w", n, ErrUnsupportedType)
				}
			}
			f = &Field{
				Type: wrapOptional(t1, required),
				Name: n,
			}
		} else {
			return nil, fmt.Errorf("type %q: %w", n, ErrUnsupportedType)
		}

		fields = append(fields, f)
	}

	return fields, nil
}

type Field struct {
	Type string
	Name string
}

var mapTypes = map[string]string{
	"number":  "f64",
	"integer": "i64",
	"string":  "String",
	"boolean": "bool",
	"array":   "Vec",
}

func wrapOptional(t string, required bool) string {
	if required {
		return t
	} else {
		return fmt.Sprintf("Option<%s>", t)
	}
}

func fromBoolean(name string, required bool) *Field {
	return &Field{
		Type: wrapOptional("bool", required),
		Name: name,
	}
}

func fromString(name string, required bool) *Field {
	return &Field{
		Type: wrapOptional("String", required),
		Name: name,
	}
}

func fromArray(name string, itemType string, required bool) *Field {
	return &Field{
		Type: wrapOptional(fmt.Sprintf("Vec<%s>", itemType), required),
		Name: name,
	}
}

func fromNumber(name string, required bool) *Field {
	return &Field{
		Type: wrapOptional("f64", required),
		Name: name,
	}
}

func fromInteger(name string, required bool) *Field {
	return &Field{
		Type: wrapOptional("i64", required),
		Name: name,
	}
}
