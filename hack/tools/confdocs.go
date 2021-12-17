// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"github.com/cerbos/cerbos/hack/tools/confdocs/indexer"
	"github.com/cerbos/cerbos/hack/tools/confdocs/writer"
	"github.com/mattn/go-isatty"
	"go.elastic.co/ecszap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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
	defaultLogLevel   = "ERROR"
)

var logger *zap.Logger
var sugaredLogger *zap.SugaredLogger

func init() {
	if envLevel := os.Getenv("CONFDOCS_LOG_LEVEL"); envLevel != "" {
		doInitLogging(envLevel)
		return
	}
	doInitLogging(defaultLogLevel)
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
		Log:         sugaredLogger,
		PackagesDir: pkgsDir,
		IfaceName:   interfaceName,
		IfacePkg:    interfacePackage,
	}).Run()
	if err != nil {
		sugaredLogger.Fatalf("Failed to run indexer: %v", err)
	}

	getFileName := func(pkgPath, structName string) string {
		prefix := strings.ToLower(structName)
		suffix := pkgPath[len(internalPkgPrefix):]

		return fmt.Sprintf("%s.%s.adoc", prefix, strings.ReplaceAll(suffix, "/", "."))
	}

	data, err := writer.New(writer.Options{
		Log:               sugaredLogger,
		Index:             index,
		IgnoreTabsForPkgs: []string{"observability", "db"},
		GetFileNameFn:     getFileName,
	}).Run()
	if err != nil {
		sugaredLogger.Fatalf("Failed to run engine: %v", err)
	}

	err = writeFiles(data, partialsDir)
	if err != nil {
		sugaredLogger.Fatalf("Failed to write documentation files: %v", err)
	}
}

func writeFiles(data map[string]*bytes.Buffer, partialsDir string) error {
	for key, value := range data {
		destination := filepath.Join(partialsDir, key)
		sugaredLogger.Infof("Writing partial documentation file %s", destination)

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

	dir, err := filepath.Abs(filepath.Join(cwd))
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

func doInitLogging(level string) {
	errorPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl >= zapcore.ErrorLevel
	})

	minLogLevel := zapcore.InfoLevel

	switch strings.ToUpper(level) {
	case "DEBUG":
		minLogLevel = zapcore.DebugLevel
	case "INFO":
		minLogLevel = zapcore.InfoLevel
	case "WARN":
		minLogLevel = zapcore.WarnLevel
	case "ERROR":
		minLogLevel = zapcore.ErrorLevel
	}

	infoPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl < zapcore.ErrorLevel && lvl >= minLogLevel
	})

	consoleErrors := zapcore.Lock(os.Stderr)
	consoleInfo := zapcore.Lock(os.Stdout)

	encoderConf := ecszap.NewDefaultEncoderConfig().ToZapCoreEncoderConfig()
	var consoleEncoder zapcore.Encoder

	if !isatty.IsTerminal(os.Stdout.Fd()) {
		consoleEncoder = zapcore.NewJSONEncoder(encoderConf)
	} else {
		encoderConf.EncodeLevel = zapcore.CapitalColorLevelEncoder
		consoleEncoder = zapcore.NewConsoleEncoder(encoderConf)
	}

	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, consoleErrors, errorPriority),
		zapcore.NewCore(consoleEncoder, consoleInfo, infoPriority),
	)

	stackTraceEnabler := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl > zapcore.ErrorLevel
	})
	logger = zap.New(core, zap.AddStacktrace(stackTraceEnabler))

	zap.ReplaceGlobals(logger.Named("confdocs"))
	zap.RedirectStdLog(logger.Named("stdlog"))

	sugaredLogger = logger.Sugar()
}
