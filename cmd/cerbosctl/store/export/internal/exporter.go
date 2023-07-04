// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ghodss/yaml"

	"github.com/cerbos/cerbos/internal/util"
)

type Exporter struct {
	gzipWriter *gzip.Writer
	tarWriter  *tar.Writer
	zipWriter  *zip.Writer
	file       *os.File
	path       string
}

func (e *Exporter) WriteJSON(name string, jsonData []byte) error {
	return e.write(name, jsonData)
}

func (e *Exporter) WriteYAML(name string, jsonData []byte) error {
	data, err := yaml.JSONToYAML(jsonData)
	if err != nil {
		return fmt.Errorf("failed to convert JSON to YAML: %w", err)
	}

	return e.write(name, data)
}

func (e *Exporter) write(name string, data []byte) error {
	var w io.Writer
	var err error
	switch {
	case util.IsTar(e.path) || util.IsGzip(e.path):
		if err := e.tarWriter.WriteHeader(&tar.Header{
			Name:     name,
			Size:     int64(len(data)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			return fmt.Errorf("failed to write tar header: %w", err)
		}

		w = e.tarWriter
	case util.IsZip(e.path):
		if w, err = e.zipWriter.Create(name); err != nil {
			return fmt.Errorf("failed to create file in the zip: %w", err)
		}
	default:
		p := filepath.Join(e.path, name)
		if err := os.MkdirAll(filepath.Dir(p), os.ModePerm); err != nil {
			return fmt.Errorf("failed to create missing directories in path %s: %w", e.path, err)
		}

		if w, err = os.Create(p); err != nil {
			return fmt.Errorf("failed to create file in the directory %s: %w", e.path, err)
		}
	}

	if _, err := io.CopyN(w, bytes.NewReader(data), int64(len(data))); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	return nil
}

func (e *Exporter) Close() error {
	if e.tarWriter != nil {
		if err := e.tarWriter.Close(); err != nil {
			return fmt.Errorf("failed to close tar writer: %w", err)
		}
	}

	if e.gzipWriter != nil {
		if err := e.gzipWriter.Close(); err != nil {
			return fmt.Errorf("failed to close gzip writer: %w", err)
		}
	}

	if e.zipWriter != nil {
		if err := e.zipWriter.Close(); err != nil {
			return fmt.Errorf("failed to close zip writer: %w", err)
		}
	}

	if e.file != nil {
		if err := e.file.Close(); err != nil {
			return fmt.Errorf("failed to close archive file: %w", err)
		}
	}

	return nil
}

func NewExporter(path string) (*Exporter, error) {
	e := &Exporter{
		path: path,
	}

	var err error
	if util.IsTar(path) || util.IsGzip(path) || util.IsZip(path) {
		if e.file, err = os.Create(path); err != nil {
			return nil, fmt.Errorf("failed to create archive file %s: %w", path, err)
		}
	}

	switch {
	case util.IsGzip(path):
		e.gzipWriter = gzip.NewWriter(e.file)
		e.tarWriter = tar.NewWriter(e.gzipWriter)
	case util.IsTar(path):
		e.tarWriter = tar.NewWriter(e.file)
	case util.IsZip(path):
		if e.file, err = os.Create(path); err != nil {
			return nil, fmt.Errorf("failed to create archive file %s: %w", path, err)
		}

		e.zipWriter = zip.NewWriter(e.file)
	default:
		if err := os.MkdirAll(filepath.Join(path, util.SchemasDirectory), os.ModePerm); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", path, err)
		}
	}

	return e, nil
}
