// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"unicode"

	"github.com/ghodss/yaml"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	bufSize     = 1024 * 4        // 4KiB
	maxFileSize = 1024 * 1024 * 4 // 4MiB
	newline     = '\n'
)

var (
	jsonStart           = []byte("{")
	yamlSep             = []byte("---")
	yamlComment         = []byte("#")
	ErrEmptyFile        = errors.New("empty file")
	ErrMultipleYAMLDocs = errors.New("more than one YAML document detected")
)

func ReadJSONOrYAML(src io.Reader, dest proto.Message) error {
	d := mkDecoder(io.LimitReader(src, maxFileSize))
	return d.decode(dest)
}

func IsJSON(src []byte) bool {
	trimmed := bytes.TrimLeftFunc(src, unicode.IsSpace)
	return bytes.HasPrefix(trimmed, jsonStart)
}

func mkDecoder(src io.Reader) decoder {
	buf := bufio.NewReaderSize(src, bufSize)
	prelude, _ := buf.Peek(bufSize)
	trimmed := bytes.TrimLeftFunc(prelude, unicode.IsSpace)

	if bytes.HasPrefix(trimmed, jsonStart) {
		return newJSONDecoder(buf)
	}

	return newYAMLDecoder(buf)
}

type decoder interface {
	decode(dest proto.Message) error
}

type decoderFunc func(dest proto.Message) error

func (df decoderFunc) decode(dest proto.Message) error {
	return df(dest)
}

func newJSONDecoder(src *bufio.Reader) decoderFunc {
	return func(dest proto.Message) error {
		jsonBytes, err := io.ReadAll(src)
		if err != nil {
			return err
		}

		if len(bytes.TrimSpace(jsonBytes)) == 0 {
			return ErrEmptyFile
		}

		if err := protojson.Unmarshal(jsonBytes, dest); err != nil {
			return fmt.Errorf("failed to unmarshal JSON: %w", err)
		}
		return nil
	}
}

func newYAMLDecoder(src *bufio.Reader) decoderFunc {
	return func(dest proto.Message) error {
		buf := new(bytes.Buffer)
		numDocs := 0

		s := bufio.NewScanner(src)
		seenContent := false
		for s.Scan() {
			line := s.Bytes()
			trimmedLine := bytes.TrimSpace(line)

			// ignore comments
			if bytes.HasPrefix(trimmedLine, yamlComment) {
				continue
			}

			// ignore empty lines at the beginning of the file
			if !seenContent && len(trimmedLine) == 0 {
				continue
			}
			seenContent = true

			if bytes.HasPrefix(line, yamlSep) {
				numDocs++
				if numDocs > 1 || (numDocs == 1 && buf.Len() > 0) {
					return ErrMultipleYAMLDocs
				}
			}

			if _, err := buf.Write(line); err != nil {
				return fmt.Errorf("failed to buffer YAML data: %w", err)
			}
			_ = buf.WriteByte(newline)
		}

		if err := s.Err(); err != nil {
			return fmt.Errorf("failed to read from source: %w", err)
		}

		yamlBytes := buf.Bytes()
		if len(bytes.TrimSpace(yamlBytes)) == 0 {
			return ErrEmptyFile
		}

		jsonBytes, err := yaml.YAMLToJSON(yamlBytes)
		if err != nil {
			return fmt.Errorf("failed to convert YAML to JSON: %w", err)
		}

		if err := protojson.Unmarshal(jsonBytes, dest); err != nil {
			return fmt.Errorf("failed to unmarshal JSON: %w", err)
		}
		return nil
	}
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
