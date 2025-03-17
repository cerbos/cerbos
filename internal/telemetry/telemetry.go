// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	statev1 "github.com/cerbos/cerbos/api/genpb/cerbos/state/v1"
	telemetryv1 "github.com/cerbos/cerbos/api/genpb/cerbos/telemetry/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/google/uuid"
	analytics "github.com/rudderlabs/analytics-go"
	"github.com/spf13/afero"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	doNotTrackEnvVar  = "DO_NOT_TRACK"
	noTelemetryEnvVar = "CERBOS_NO_TELEMETRY"

	eventBufferSize = 8
	stateFile       = "cerbos.telemetry.json"
)

var (
	WriteKey     string
	DataPlaneURL string

	reporter  Reporter = nopReporter{}
	startTime          = time.Now()
)

type Reporter interface {
	Report(*telemetryv1.Event) bool
	Intercept() Interceptors
	Stop() error
}

type nopReporter struct{}

func (nopReporter) Report(_ *telemetryv1.Event) bool {
	return true
}

func (nopReporter) Intercept() Interceptors {
	return nopInterceptors{}
}

func (nopReporter) Stop() error {
	return nil
}

func Start(ctx context.Context, store storage.Store) {
	logger := zap.L().Named("telemetry")

	conf := &Conf{}
	_ = config.GetSection(conf)

	if !isEnabled(conf) || WriteKey == "" || DataPlaneURL == "" {
		logger.Info("Telemetry disabled")
		return
	}

	if r := startReporter(ctx, conf, store, logger); r != nil {
		reporter = r
	}
}

func isEnabled(conf *Conf) bool {
	if conf.Disabled {
		return false
	}

	return !slices.ContainsFunc([]string{noTelemetryEnvVar, doNotTrackEnvVar}, disabledByEnvVar)
}

func disabledByEnvVar(name string) bool {
	v, ok := os.LookupEnv(name)
	// if the var is not defined, assume consent.
	if !ok {
		return false
	}

	set, err := strconv.ParseBool(v)
	if err != nil {
		// err on the side of caution and assume no consent.
		return true
	}

	return set
}

func startReporter(_ context.Context, conf *Conf, store storage.Store, logger *zap.Logger) *analyticsReporter {
	logger.Info(fmt.Sprintf("Anonymous telemetry enabled. Disable via the config file or by setting the %s=1 environment variable", noTelemetryEnvVar))

	fs := initStateFS(conf.StateDir)
	r, err := newAnalyticsReporter(conf, store, fs, logger)
	if err != nil {
		logger.Debug("Failed to create telemetry reporter", zap.Error(err))
		return nil
	}

	go r.start()
	return r
}

func initStateFS(dir string) afero.Fs {
	if dir == "" {
		confDir, err := os.UserConfigDir()
		if err != nil {
			confDir = os.TempDir()
		}

		dir = filepath.Join(confDir, util.AppName)
	}

	finfo, err := os.Stat(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return afero.NewMemMapFs()
		}

		//nolint:mnd
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return afero.NewMemMapFs()
		}
	}

	if finfo != nil && !finfo.IsDir() {
		return afero.NewMemMapFs()
	}

	return afero.NewBasePathFs(afero.NewOsFs(), dir)
}

func Stop() {
	_ = reporter.Stop()
}

func Report(event *telemetryv1.Event) bool {
	return reporter.Report(event)
}

func Intercept() Interceptors {
	return reporter.Intercept()
}

type analyticsReporter struct {
	state          *statev1.TelemetryState
	fsys           afero.Fs
	store          storage.Store
	eventChan      chan *telemetryv1.Event
	client         analytics.Client
	logger         *zap.Logger
	shutdownChan   chan struct{}
	reportInterval time.Duration
	closeOnce      sync.Once
}

func newAnalyticsReporter(conf *Conf, store storage.Store, fsys afero.Fs, logger *zap.Logger) (*analyticsReporter, error) {
	client, err := analytics.NewWithConfig(WriteKey, DataPlaneURL, analytics.Config{
		Logger: zapLogWrapper{logger: logger.Sugar()},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate Analytics client: %w", err)
	}

	return newAnalyticsReporterWithClient(client, conf, store, fsys, logger), nil
}

func newAnalyticsReporterWithClient(client analytics.Client, conf *Conf, store storage.Store, fsys afero.Fs, logger *zap.Logger) *analyticsReporter {
	return &analyticsReporter{
		state:          readState(fsys),
		fsys:           fsys,
		store:          store,
		logger:         logger,
		client:         client,
		reportInterval: conf.ReportInterval,
		eventChan:      make(chan *telemetryv1.Event, eventBufferSize),
		shutdownChan:   make(chan struct{}),
	}
}

func readState(fsys afero.Fs) *statev1.TelemetryState {
	stateBytes, err := afero.ReadFile(fsys, stateFile)
	if err != nil {
		return newState()
	}

	var state statev1.TelemetryState
	if err := protojson.Unmarshal(stateBytes, &state); err != nil {
		return newState()
	}

	return &state
}

func newState() *statev1.TelemetryState {
	var uuidStr string

	if id, err := uuid.NewRandom(); err != nil {
		uuidStr = "unknown"
	} else {
		uuidStr = id.String()
	}

	return &statev1.TelemetryState{
		Uuid: uuidStr,
	}
}

func (r *analyticsReporter) start() {
	defer func() {
		// don't let a panic in this goroutine crash the whole app.
		if err := recover(); err != nil {
			r.logger.Debug("Telemetry panic", zap.Any("cause", err))
		}
	}()

	r.reportServerLaunch()

	for event := range r.eventChan {
		switch t := event.Data.(type) {
		case *telemetryv1.Event_ApiActivity_:
			r.reportAPIActivity(t.ApiActivity)
		default:
			r.logger.Debug(fmt.Sprintf("Unhandled telemetry event type %T", t))
		}
	}
}

func (r *analyticsReporter) Intercept() Interceptors {
	return newStatsInterceptors(r, r.reportInterval, r.shutdownChan)
}

func (r *analyticsReporter) reportServerLaunch() {
	event := buildServerLaunch(r.store)
	if err := r.send("server_launch", event); err != nil {
		r.logger.Debug("Failed to send server launch event", zap.Error(err))
	}
}

func (r *analyticsReporter) Report(event *telemetryv1.Event) bool {
	select {
	case r.eventChan <- event:
		return true
	default:
		return false
	}
}

func (r *analyticsReporter) reportAPIActivity(event *telemetryv1.Event_ApiActivity) {
	if err := r.send("api_activity", event); err != nil {
		r.logger.Debug("Failed to send API activity event", zap.Error(err))
	}
}

func (r *analyticsReporter) Stop() error {
	var err error
	r.closeOnce.Do(func() {
		close(r.shutdownChan)
		close(r.eventChan)
		r.reportServerStop()
		err = r.client.Close()

		_ = r.writeState()
	})

	return err
}

func (r *analyticsReporter) reportServerStop() {
	event := &telemetryv1.ServerStop{
		Version:       "1.0.0",
		Uptime:        durationpb.New(time.Since(startTime)),
		RequestsTotal: atomic.LoadUint64(&totalReqCount),
	}

	if err := r.send("server_stop", event); err != nil {
		r.logger.Debug("Failed to send server stop event", zap.Error(err))
	}
}

func (r *analyticsReporter) writeState() error {
	stateBytes, err := protojson.Marshal(r.state)
	if err != nil {
		return fmt.Errorf("failed to marshal proto: %w", err)
	}

	//nolint:mnd
	if err := afero.WriteFile(r.fsys, stateFile, stateBytes, 0o600); err != nil {
		return fmt.Errorf("failed to write state: %w", err)
	}

	return nil
}

func (r *analyticsReporter) send(kind string, event proto.Message) error {
	props, err := mkProps(event)
	if err != nil {
		return fmt.Errorf("failed to create properties: %w", err)
	}

	if err := r.client.Enqueue(analytics.Track{
		AnonymousId: r.state.Uuid,
		Event:       kind,
		Properties:  props,
	}); err != nil {
		return fmt.Errorf("failed to enqueue event: %w", err)
	}

	r.state.LastTimestamp = timestamppb.Now()
	return nil
}

func mkProps(event proto.Message) (analytics.Properties, error) {
	evtBytes, err := protojson.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal event: %w", err)
	}

	var props map[string]any
	if err := json.Unmarshal(evtBytes, &props); err != nil {
		return nil, fmt.Errorf("failed to unmarshal evt: %w", err)
	}

	return analytics.Properties(props), nil
}

type zapLogWrapper struct {
	logger *zap.SugaredLogger
}

func (zlw zapLogWrapper) Logf(fmt string, args ...any) {
	zlw.logger.Debugf(fmt, args...)
}

func (zlw zapLogWrapper) Errorf(fmt string, args ...any) {
	zlw.logger.Warnf(fmt, args...)
}
