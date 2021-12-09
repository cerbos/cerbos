// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	_ "embed"
	"fmt"
	"github.com/cerbos/cerbos/hack/tools/confdocs"
	"go.uber.org/zap"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const (
	interfacePackage  = "github.com/cerbos/cerbos/internal/config"
	interfaceName     = "Section"
	internalPkgPrefix = "github.com/cerbos/cerbos/internal/"
)

//go:embed docs.tmpl
var docsTempl string

func main() {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatal(err)
	}

	logger := zapLogger.Sugar()

	cwd, err := os.Getwd()
	if err != nil {
		logger.Fatalf("Failed to get working directory: %v", err)
	}

	dir, err := filepath.Abs(cwd)
	if err != nil {
		logger.Fatalf("Failed to get absolute path: %v", err)
	}

	indexer := confdocs.NewIndexer(logger, dir, interfaceName, interfacePackage)
	index, err := indexer.Run()
	if err != nil {
		logger.Fatalf("Failed to run indexer: %v", err)
	}

	getFileName := func(pkgPath, structName string) string {
		prefix := strings.ToLower(structName)
		suffix := pkgPath[len(internalPkgPrefix):]

		return fmt.Sprintf("%s.%s.adoc", prefix, strings.ReplaceAll(suffix, "/", "."))
	}

	getRootName := func(pkgPath string) string {
		name := pkgPath[len(internalPkgPrefix):]
		split := strings.Split(name, "/")
		return split[len(split)-1]
	}

	engine := confdocs.NewEngine(logger, index, docsTempl, getFileName, getRootName)
	err = engine.Run()
	if err != nil {
		logger.Fatalf("Failed to run engine: %v", err)
	}
}
