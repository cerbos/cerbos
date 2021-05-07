// Copyright 2021 Zenauth Ltd.

package logging

import (
	"context"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/cerbos/cerbos/internal/util"
)

type ctxLog struct{}

var ctxLogKey = &ctxLog{}

// InitLogging initializes the global logger.
func InitLogging(level string) {
	if envLevel := os.Getenv("CERBOS_LOG_LEVEL"); envLevel != "" {
		doInitLogging(envLevel)
		return
	}

	doInitLogging(level)
}

func doInitLogging(level string) {
	var logger *zap.Logger

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

	encoderConf := zap.NewDevelopmentEncoderConfig()
	encoderConf.EncodeLevel = zapcore.CapitalColorLevelEncoder

	var consoleEncoder zapcore.Encoder
	if !isatty.IsTerminal(os.Stdout.Fd()) {
		encoderConf := zap.NewProductionEncoderConfig()
		encoderConf.MessageKey = "message"
		encoderConf.EncodeTime = zapcore.TimeEncoder(zapcore.ISO8601TimeEncoder)
		consoleEncoder = zapcore.NewJSONEncoder(encoderConf)
	} else {
		encoderConf := zap.NewDevelopmentEncoderConfig()
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

	zap.ReplaceGlobals(logger.Named(util.AppName))
	zap.RedirectStdLog(logger.Named("stdlog"))
}

func FromContext(ctx context.Context) *zap.Logger {
	log, ok := ctx.Value(ctxLogKey).(*zap.Logger)
	if !ok || log == nil {
		return zap.L()
	}

	return log
}

func ToContext(ctx context.Context, log *zap.Logger) context.Context {
	return context.WithValue(ctx, ctxLogKey, log)
}
