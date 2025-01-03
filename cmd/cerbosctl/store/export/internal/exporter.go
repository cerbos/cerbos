// Copyright 2021-2025 Zenauth Ltd.
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

func NewExporter(path string) (Exporter, error) {
	var file io.WriteCloser
	var err error
	if util.IsGzip(path) || util.IsTar(path) || util.IsZip(path) {
		if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
			return nil, fmt.Errorf("failed to create missing directories in path %s: %w", path, err)
		}

		if file, err = os.Create(path); err != nil {
			return nil, fmt.Errorf("failed to create archive file %s: %w", path, err)
		}
	}

	switch {
	case util.IsGzip(path):
		return newGzipExporter(file), nil
	case util.IsTar(path):
		return newTarExporter(file), nil
	case util.IsZip(path):
		return newZipExporter(file), nil
	}

	return newDirectoryExporter(path), nil
}

type Exporter interface {
	WriteJSON(name string, jsonData []byte) error
	WriteYAML(name string, jsonData []byte) error
	io.Closer
}

func newTarExporter(w io.WriteCloser) *tarExporter {
	return &tarExporter{
		archiveWriter: tar.NewWriter(w),
		writer:        w,
	}
}

type tarExporter struct {
	archiveWriter *tar.Writer
	writer        io.WriteCloser
}

func (e *tarExporter) WriteJSON(name string, jsonData []byte) error {
	return e.write(name, jsonData)
}

func (e *tarExporter) WriteYAML(name string, jsonData []byte) error {
	data, err := yaml.JSONToYAML(jsonData)
	if err != nil {
		return fmt.Errorf("failed to convert JSON to YAML: %w", err)
	}

	return e.write(name, data)
}

func (e *tarExporter) Close() error {
	if err := e.archiveWriter.Close(); err != nil {
		return fmt.Errorf("failed to close tar writer: %w", err)
	}

	if err := e.writer.Close(); err != nil {
		return fmt.Errorf("failed to close writer: %w", err)
	}

	return nil
}

func (e *tarExporter) write(name string, data []byte) error {
	if err := e.archiveWriter.WriteHeader(&tar.Header{
		Name:     name,
		Size:     int64(len(data)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		return fmt.Errorf("failed to write tar header: %w", err)
	}

	if _, err := io.Copy(e.archiveWriter, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	return nil
}

func newGzipExporter(w io.WriteCloser) *gzipExporter {
	gzipWriter := gzip.NewWriter(w)
	return &gzipExporter{
		archiveWriter: tar.NewWriter(gzipWriter),
		gzipWriter:    gzipWriter,
		writer:        w,
	}
}

type gzipExporter struct {
	archiveWriter *tar.Writer
	gzipWriter    *gzip.Writer
	writer        io.WriteCloser
}

func (e *gzipExporter) WriteJSON(name string, jsonData []byte) error {
	return e.write(name, jsonData)
}

func (e *gzipExporter) WriteYAML(name string, jsonData []byte) error {
	data, err := yaml.JSONToYAML(jsonData)
	if err != nil {
		return fmt.Errorf("failed to convert JSON to YAML: %w", err)
	}

	return e.write(name, data)
}

func (e *gzipExporter) Close() error {
	if err := e.archiveWriter.Close(); err != nil {
		return fmt.Errorf("failed to close tar writer: %w", err)
	}

	if err := e.gzipWriter.Close(); err != nil {
		return fmt.Errorf("failed to close gzip writer: %w", err)
	}

	if err := e.writer.Close(); err != nil {
		return fmt.Errorf("failed to close writer: %w", err)
	}

	return nil
}

func (e *gzipExporter) write(name string, data []byte) error {
	if err := e.archiveWriter.WriteHeader(&tar.Header{
		Name:     name,
		Size:     int64(len(data)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		return fmt.Errorf("failed to write tar header: %w", err)
	}

	if _, err := io.Copy(e.archiveWriter, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	return nil
}

func newZipExporter(w io.WriteCloser) *zipExporter {
	return &zipExporter{
		archiveWriter: zip.NewWriter(w),
		writer:        w,
	}
}

type zipExporter struct {
	archiveWriter *zip.Writer
	writer        io.WriteCloser
}

func (e *zipExporter) WriteJSON(name string, jsonData []byte) error {
	return e.write(name, jsonData)
}

func (e *zipExporter) WriteYAML(name string, jsonData []byte) error {
	data, err := yaml.JSONToYAML(jsonData)
	if err != nil {
		return fmt.Errorf("failed to convert JSON to YAML: %w", err)
	}

	return e.write(name, data)
}

func (e *zipExporter) Close() error {
	if err := e.archiveWriter.Close(); err != nil {
		return fmt.Errorf("failed to close zip writer: %w", err)
	}

	if err := e.writer.Close(); err != nil {
		return fmt.Errorf("failed to close writer: %w", err)
	}
	return nil
}

func (e *zipExporter) write(name string, data []byte) error {
	w, err := e.archiveWriter.Create(name)
	if err != nil {
		return fmt.Errorf("failed to create file in the zip: %w", err)
	}

	if _, err := io.Copy(w, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	return nil
}

func newDirectoryExporter(path string) *directoryExporter {
	return &directoryExporter{
		path: path,
	}
}

type directoryExporter struct {
	path string
}

func (e *directoryExporter) WriteJSON(name string, jsonData []byte) error {
	return e.write(name, jsonData)
}

func (e *directoryExporter) WriteYAML(name string, jsonData []byte) error {
	data, err := yaml.JSONToYAML(jsonData)
	if err != nil {
		return fmt.Errorf("failed to convert JSON to YAML: %w", err)
	}

	return e.write(name, data)
}

func (e *directoryExporter) Close() error {
	return nil
}

func (e *directoryExporter) write(name string, data []byte) error {
	p := filepath.Join(e.path, name)
	if err := os.MkdirAll(filepath.Dir(p), os.ModePerm); err != nil {
		return fmt.Errorf("failed to create missing directories in path %s: %w", e.path, err)
	}

	w, err := os.Create(p)
	if err != nil {
		return fmt.Errorf("failed to create file in the directory %s: %w", e.path, err)
	}

	if _, err := io.Copy(w, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	return nil
}
