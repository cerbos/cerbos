// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"

	"go.elastic.co/ecszap"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/config"
)

const Backend = "file"

func init() {
	audit.RegisterBackend(Backend, func(_ context.Context, confW *config.Wrapper, decisionFilter audit.DecisionLogEntryFilter) (audit.Log, error) {
		conf := new(Conf)
		if err := confW.GetSection(conf); err != nil {
			return nil, fmt.Errorf("failed to read local audit log configuration: %w", err)
		}

		return NewLog(conf, decisionFilter)
	})
}

type Log struct {
	accessLog      *zap.Logger
	decisionLog    *zap.Logger
	decisionFilter audit.DecisionLogEntryFilter
}

func NewLog(conf *Conf, decisionFilter audit.DecisionLogEntryFilter) (*Log, error) {
	// remove level, time and message because they are not useful in this context
	encoderConf := ecszap.NewDefaultEncoderConfig().ToZapCoreEncoderConfig()
	encoderConf.LevelKey = ""
	encoderConf.TimeKey = ""
	encoderConf.MessageKey = ""

	outputPaths := append([]string{conf.Path}, conf.AdditionalPaths...)
	outputSyncers := make([]zapcore.WriteSyncer, len(outputPaths))

	for i, path := range outputPaths {
		switch path {
		case "stdout":
			outputSyncers[i] = zapcore.AddSync(syncErrIgnorer{WriteSyncer: os.Stdout})
		case "stderr":
			outputSyncers[i] = zapcore.AddSync(syncErrIgnorer{WriteSyncer: os.Stderr})
		default:
			rotator := &lumberjack.Logger{
				Filename: path,
				MaxSize:  math.MaxInt32,
			}

			if conf.LogRotation != nil {
				rotator.MaxSize = int(conf.LogRotation.MaxFileSizeMB)
				rotator.MaxAge = int(conf.LogRotation.MaxFileAgeDays)
				rotator.MaxBackups = int(conf.LogRotation.MaxFileCount)
			}

			outputSyncers[i] = zapcore.AddSync(rotator)
		}
	}

	encoder := zapcore.NewJSONEncoder(encoderConf)
	core := zapcore.NewCore(encoder, zapcore.NewMultiWriteSyncer(outputSyncers...), zap.NewAtomicLevelAt(zap.InfoLevel))
	logger := zap.New(core)

	return &Log{
		accessLog:      logger.Named("cerbos.audit").With(zap.String("log.kind", "access")),
		decisionLog:    logger.Named("cerbos.audit").With(zap.String("log.kind", "decision")),
		decisionFilter: decisionFilter,
	}, nil
}

func (l *Log) Backend() string {
	return Backend
}

func (l *Log) Enabled() bool {
	return true
}

func (l *Log) WriteAccessLogEntry(_ context.Context, record audit.AccessLogEntryMaker) error {
	rec, err := record()
	if err != nil {
		return err
	}

	l.accessLog.Info("", zap.Inline(protoMsg{msg: rec}))
	return nil
}

func (l *Log) WriteDecisionLogEntry(_ context.Context, record audit.DecisionLogEntryMaker) error {
	rec, err := record()
	if err != nil {
		return err
	}

	if l.decisionFilter != nil {
		rec = l.decisionFilter(rec)
		if rec == nil {
			return nil
		}
	}

	l.decisionLog.Info("", zap.Inline(protoMsg{msg: rec}))
	return nil
}

func (l *Log) Close() error {
	err1 := l.accessLog.Sync()
	err2 := l.decisionLog.Sync()

	return multierr.Combine(err1, err2)
}

type protoMsg struct {
	msg proto.Message
}

func (pm protoMsg) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if pm.msg == nil {
		return nil
	}

	pm.msg.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsMap():
			_ = enc.AddObject(fd.JSONName(), protoMap{m: v.Map(), valueFD: fd.MapValue()})
		case fd.IsList():
			_ = enc.AddArray(fd.JSONName(), protoList{l: v.List(), valueFD: fd})
		default:
			encodeSingular(enc, fd.JSONName(), fd, v)
		}

		return true
	})

	return nil
}

func encodeSingular(enc zapcore.ObjectEncoder, fieldName string, fd protoreflect.FieldDescriptor, v protoreflect.Value) {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		enc.AddBool(fieldName, v.Bool())
	case protoreflect.EnumKind:
		enumVal := fd.Enum().Values().ByNumber(v.Enum())
		enc.AddString(fieldName, string(enumVal.Name()))
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Int64Kind, protoreflect.Sint64Kind:
		enc.AddInt64(fieldName, v.Int())
	case protoreflect.Uint32Kind, protoreflect.Uint64Kind, protoreflect.Sfixed32Kind, protoreflect.Fixed32Kind, protoreflect.Sfixed64Kind, protoreflect.Fixed64Kind:
		enc.AddUint64(fieldName, v.Uint())
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		enc.AddFloat64(fieldName, v.Float())
	case protoreflect.StringKind:
		enc.AddString(fieldName, v.String())
	case protoreflect.BytesKind:
		enc.AddBinary(fieldName, v.Bytes())
	case protoreflect.MessageKind:
		msg := v.Message()

		// output readbale timestamps and values
		switch msg.Descriptor().FullName() {
		case "google.protobuf.Timestamp", "google.protobuf.Value":
			if val, err := protojson.Marshal(msg.Interface()); err == nil {
				_ = enc.AddReflected(fieldName, json.RawMessage(val))
				return
			}
		default:
			_ = enc.AddObject(fieldName, protoMsg{msg: msg.Interface()})
		}
	default:
		// do nothing
	}
}

type protoMap struct {
	m       protoreflect.Map
	valueFD protoreflect.FieldDescriptor
}

func (pm protoMap) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if pm.m == nil {
		return nil
	}

	pm.m.Range(func(mk protoreflect.MapKey, v protoreflect.Value) bool {
		encodeSingular(enc, mk.String(), pm.valueFD, v)
		return true
	})

	return nil
}

type protoList struct {
	l       protoreflect.List
	valueFD protoreflect.FieldDescriptor
}

func (pl protoList) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	if pl.l == nil {
		return nil
	}

	for i := range pl.l.Len() {
		v := pl.l.Get(i)

		switch pl.valueFD.Kind() {
		case protoreflect.BoolKind:
			enc.AppendBool(v.Bool())
		case protoreflect.EnumKind:
			enc.AppendInt32(int32(v.Enum()))
		case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Int64Kind, protoreflect.Sint64Kind:
			enc.AppendInt64(v.Int())
		case protoreflect.Uint32Kind, protoreflect.Uint64Kind, protoreflect.Sfixed32Kind, protoreflect.Fixed32Kind, protoreflect.Sfixed64Kind, protoreflect.Fixed64Kind:
			enc.AppendUint64(v.Uint())
		case protoreflect.FloatKind, protoreflect.DoubleKind:
			enc.AppendFloat64(v.Float())
		case protoreflect.StringKind:
			enc.AppendString(v.String())
		case protoreflect.MessageKind:
			_ = enc.AppendObject(protoMsg{msg: v.Message().Interface()})
		default:
			// do nothing
		}
	}

	return nil
}

type syncErrIgnorer struct {
	zapcore.WriteSyncer
}

func (s syncErrIgnorer) Sync() error {
	// https://github.com/uber-go/zap/issues/328
	_ = s.WriteSyncer.Sync()
	return nil
}
