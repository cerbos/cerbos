package util

import (
	"bytes"
	"fmt"
	"io"
	"unicode"

	"github.com/ghodss/yaml"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func ReadJSONOrYAML(src io.Reader, dest proto.Message) error {
	data, err := io.ReadAll(src)
	if err != nil {
		return fmt.Errorf("failed to read from source: %w", err)
	}

	jsonBytes, err := toJSON(data)
	if err != nil {
		return fmt.Errorf("failed to convert data to JSON: %w", err)
	}

	if err := protojson.Unmarshal(jsonBytes, dest); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return nil
}

func toJSON(data []byte) ([]byte, error) {
	trimmed := bytes.TrimLeftFunc(data, unicode.IsSpace)

	// If we find a starting brace, this already contains JSON.
	if bytes.HasPrefix(trimmed, []byte("{")) {
		return trimmed, nil
	}

	return yaml.YAMLToJSON(trimmed)
}

func WriteYAML(dest io.Writer, data proto.Message) error {
	jsonBytes, err := protojson.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	yamlBytes, err := yaml.JSONToYAML(jsonBytes)
	if err != nil {
		return fmt.Errorf("failed to convert data to YAML: %w", err)
	}

	if _, err := io.Copy(dest, bytes.NewReader(yamlBytes)); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	return nil
}
