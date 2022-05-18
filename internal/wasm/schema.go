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

func convert(s *jsonschema.Schema) ([]*Field, error) {
	fields := make([]*Field, 0, len(s.Properties))

	for n, schema := range s.Properties {
		required := slices.Index(s.Required, n) > 0
		var f *Field
		switch schema.Types[0] {
		case "number":
			f = fromNumber(n, required)
		case "integer":
			f = fromInteger(n, required)
		case "boolean":
			f = fromBoolean(n, required)
		case "string":
			f = fromString(n, required)
		case "array":
			f = fromArray(n, schema.Items2020.Types[0], required)
		default:
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
