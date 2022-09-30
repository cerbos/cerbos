// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
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

	handleUSR1Signal(ctx, minLogLevel, &atomicLevel)
}

// setLevelForDuration sets the global log level to the given level for a given duration. Reverts to the original
// level after the duration.
func setLevelForDuration(level, originalLevel zapcore.Level, duration time.Duration, inProgress *atomic.Bool, atomicLevel *zap.AtomicLevel) {
	log := zap.S().Named("logging")

	log.Infof("Temporarily setting global log level to %s for %s", level, duration)
	atomicLevel.SetLevel(level)

	time.AfterFunc(duration, func() {
		log.Infof("Reverting global log level to %s", originalLevel)
		atomicLevel.SetLevel(originalLevel)
		inProgress.Store(false)
	})
}

// handleUSR1Signal sets the log level to zapcore.DebugLevel for some duration in case syscall.SIGUSR1 received.
func handleUSR1Signal(ctx context.Context, originalLevel zapcore.Level, atomicLevel *zap.AtomicLevel) {
	sigusr1 := make(chan os.Signal, 1)
	signal.Notify(sigusr1, syscall.SIGUSR1)

	go func() {
		inProgress := atomic.Bool{}
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigusr1:
				if !inProgress.Load() {
					inProgress.Store(true)
					setLevelForDuration(zapcore.DebugLevel, originalLevel, tmpLogLevelDuration, &inProgress, atomicLevel)
				}
			}
		}
	}()
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
