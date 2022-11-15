// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	"github.com/mattn/go-isatty"
	"go.elastic.co/ecszap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/cerbos/cerbos/internal/util"
)

const tmpLogLevelDuration = 10 * time.Minute

type ctxLog struct{}

var ctxLogKey = &ctxLog{}

// InitLogging initializes the global logger.
func InitLogging(ctx context.Context, level string) {
	if envLevel := os.Getenv("CERBOS_LOG_LEVEL"); envLevel != "" {
		doInitLogging(ctx, envLevel)
		return
	}

	doInitLogging(ctx, level)
}

func doInitLogging(ctx context.Context, level string) {
	var logger *zap.Logger

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

	encoderConf := ecszap.NewDefaultEncoderConfig().ToZapCoreEncoderConfig()
	var consoleEncoder zapcore.Encoder

	if !isatty.IsTerminal(os.Stdout.Fd()) {
		consoleEncoder = zapcore.NewJSONEncoder(encoderConf)
	} else {
		encoderConf.EncodeLevel = zapcore.CapitalColorLevelEncoder
		consoleEncoder = zapcore.NewConsoleEncoder(encoderConf)
	}

	consoleErrors := zapcore.Lock(os.Stderr)
	consoleInfo := zapcore.Lock(os.Stdout)
	atomicLevel := zap.NewAtomicLevelAt(minLogLevel)

	errorPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return atomicLevel.Enabled(lvl) && lvl >= zapcore.ErrorLevel
	})

	infoPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return atomicLevel.Enabled(lvl) && lvl < zapcore.ErrorLevel
	})

	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, consoleErrors, errorPriority),
		zapcore.NewCore(consoleEncoder, consoleInfo, infoPriority),
	)

	stackTraceEnabler := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl > zapcore.ErrorLevel
	})
	logger = zap.New(core, zap.AddStacktrace(stackTraceEnabler))

	zap.ReplaceGlobals(logger.Named(util.AppName))
	zap.RedirectStdLog(logger.Named("stdlog"))

	grpc_zap.ReplaceGrpcLoggerV2(logger.Named("grpc").WithOptions(
		zap.IncreaseLevel(zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
			return lvl > zapcore.ErrorLevel
		}))),
	)

	if minLogLevel > zap.DebugLevel {
		handleUSR1Signal(ctx, minLogLevel, &atomicLevel)
	}
}

// handleUSR1Signal temporarily sets the log level to debug when a SIGUSR1 signal is received.
func handleUSR1Signal(ctx context.Context, originalLevel zapcore.Level, atomicLevel *zap.AtomicLevel) {
	sigusr1 := make(chan os.Signal, 1)
	signal.Notify(sigusr1, syscall.SIGUSR1)

	go func() {
		inProgress := false
		doneChan := make(chan struct{}, 1)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigusr1:
				if !inProgress {
					inProgress = true
					go setLogLevelForDuration(ctx, doneChan, originalLevel, atomicLevel)
				}
			case <-doneChan:
				inProgress = false
			}
		}
	}()
}

// setLogLevelForDuration temporarily sets the global log level to the given level for a period of time.
func setLogLevelForDuration(ctx context.Context, doneChan chan<- struct{}, originalLevel zapcore.Level, atomicLevel *zap.AtomicLevel) {
	log := zap.S().Named("logging")

	log.Infof("Temporarily setting global log level to DEBUG for %s", tmpLogLevelDuration)
	atomicLevel.SetLevel(zap.DebugLevel)

	timer := time.NewTimer(tmpLogLevelDuration)
	defer timer.Stop()

	select {
	case <-ctx.Done():
	case <-timer.C:
	}

	log.Infof("Reverting global log level to %s", originalLevel)
	atomicLevel.SetLevel(originalLevel)
	doneChan <- struct{}{}
}

// FromContext returns the logger from the context if one exists. Otherwise it returns a new logger.
func FromContext(ctx context.Context) *zap.Logger {
	log, ok := ctx.Value(ctxLogKey).(*zap.Logger)
	if !ok || log == nil {
		return zap.L()
	}

	return log
}

// ToContext adds a logger to the context.
func ToContext(ctx context.Context, log *zap.Logger) context.Context {
	return context.WithValue(ctx, ctxLogKey, log)
}
