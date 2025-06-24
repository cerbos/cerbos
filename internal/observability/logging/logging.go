// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/mattn/go-isatty"
	"go.elastic.co/ecszap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zapgrpc"
	"google.golang.org/grpc/grpclog"

	"github.com/cerbos/cerbos/internal/util"
)

const defaultTmpLogLevelDuration = 10 * time.Minute

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
	default:
		if after, ok := strings.CutPrefix(level, "V"); ok {
			if vLevel, err := strconv.Atoi(after); err == nil {
				minLogLevel = zapcore.Level(-vLevel)
			}
		}
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
	grpclog.SetLoggerV2(zapgrpc.NewLogger(logger.Named("grpc").WithOptions(
		zap.IncreaseLevel(zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
			return lvl > zapcore.ErrorLevel
		})))))

	if minLogLevel > zap.DebugLevel {
		handleUSR1Signal(ctx, minLogLevel, &atomicLevel)
	}
}

// setLogLevelForDuration temporarily sets the global log level to the given level for a period of time.
func setLogLevelForDuration(ctx context.Context, doneChan chan<- struct{}, extendChan <-chan struct{}, originalLevel zapcore.Level, atomicLevel *zap.AtomicLevel) {
	log := zap.S().Named("logging")

	tmpLogLevelDuration := defaultTmpLogLevelDuration
	if td := os.Getenv("CERBOS_TEMP_LOG_LEVEL_DURATION"); td != "" {
		if d, err := time.ParseDuration(td); err == nil {
			tmpLogLevelDuration = d
		}
	}

	log.Infof("Temporarily setting global log level to %s for %s", zap.DebugLevel, tmpLogLevelDuration)
	atomicLevel.SetLevel(zap.DebugLevel)

	timer := time.NewTimer(tmpLogLevelDuration)
	defer func() {
		timer.Stop()
		log.Infof("Reverting global log level to %s", originalLevel)
		atomicLevel.SetLevel(originalLevel)
		doneChan <- struct{}{}
	}()

	extendCount := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if extendCount <= 0 {
				return
			}

			log.Infof("Extending %s log level for further %s", zap.DebugLevel, tmpLogLevelDuration)
			extendCount--
			timer.Reset(tmpLogLevelDuration)
		case <-extendChan:
			log.Infof("Log level will be %s for further %s", zap.DebugLevel, tmpLogLevelDuration)
			extendCount++
		}
	}
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

// ReqScopeLog returns a request-scoped logger with request fields populated.
func ReqScopeLog(ctx context.Context) *zap.Logger {
	log := FromContext(ctx)
	fields := GRPCLogFieldsToZap(logging.ExtractFields(ctx))
	return log.With(fields...)
}

func GRPCLogFieldsToZap(fields logging.Fields) []zap.Field {
	if len(fields) == 0 {
		return nil
	}

	out := make([]zap.Field, 0, len(fields)/2) //nolint:mnd
	iter := fields.Iterator()
	for iter.Next() {
		key, value := iter.At()
		switch v := value.(type) {
		case string:
			out = append(out, zap.String(key, v))
		case int:
			out = append(out, zap.Int(key, v))
		case bool:
			out = append(out, zap.Bool(key, v))
		default:
			out = append(out, zap.Any(key, v))
		}
	}

	return out
}
