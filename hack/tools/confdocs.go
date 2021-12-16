// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"github.com/cerbos/cerbos/hack/tools/confdocs/indexer"
	"github.com/cerbos/cerbos/hack/tools/confdocs/writer"
	"github.com/fatih/color"
	"go.uber.org/zap"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	interfacePackage  = "github.com/cerbos/cerbos/internal/config"
	interfaceName     = "Section"
	internalPkgPrefix = "github.com/cerbos/cerbos/internal/"
)

//go:embed docs.tmpl
var docsTempl string
var logger *zap.SugaredLogger

func init() {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatal(err)
	}

	logger = zapLogger.Sugar()
}

func main() {
	pkgsDir, err := getPackagesDir()
	if err != nil {
		log.Fatalf("failed to get packages directory: %v", err)
	}

	partialsDir, err := getPartialsDir()
	if err != nil {
		log.Fatalf("failed to get partials directory: %v", err)
	}

	index, err := indexer.New(indexer.Options{
		Log:         logger,
		PackagesDir: pkgsDir,
		IfaceName:   interfaceName,
		IfacePkg:    interfacePackage,
	}).Run()
	if err != nil {
		logger.Fatalf("Failed to run indexer: %v", err)
	}

	getFileName := func(pkgPath, structName string) string {
		prefix := strings.ToLower(structName)
		suffix := pkgPath[len(internalPkgPrefix):]

		return fmt.Sprintf("%s.%s.adoc", prefix, strings.ReplaceAll(suffix, "/", "."))
	}

	data, err := writer.New(writer.Options{
		Log:               logger,
		Index:             index,
		TemplateFile:      docsTempl,
		IgnoreTabsForPkgs: []string{"observability", "db"},
		GetFileNameFn:     getFileName,
	}).Run()
	if err != nil {
		logger.Fatalf("Failed to run engine: %v", err)
	}

	err = writeFiles(data, partialsDir)
	if err != nil {
		logger.Fatalf("Failed to write documentation files: %v", err)
	}
}

func writeFiles(data map[string]*bytes.Buffer, partialsDir string) error {
	for key, value := range data {
		destination := filepath.Join(partialsDir, key)
		color.Set(color.FgBlue)
		logger.Infof("Writing partial documentation file %s", destination)
		color.Unset()

		f, err := os.Create(destination)
		if err != nil {
			return fmt.Errorf("failed to create file to write: %w", err)
		}

		_, err = f.Write(value.Bytes())
		if err != nil {
			return fmt.Errorf("failed to write file with path %s: %w", destination, err)
		}
	}

	return nil
}

func getPackagesDir() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %v", err)
	}

	dir, err := filepath.Abs(cwd)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %v", err)
	}

	return dir, nil
}

func getPartialsDir() (string, error) {
	_, currFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("failed to get working directory")
	}

	return filepath.Join(filepath.Dir(currFile), "..", "..", "docs/modules/configuration/partials"), nil
}
