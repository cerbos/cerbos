// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ghodss/yaml"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

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
