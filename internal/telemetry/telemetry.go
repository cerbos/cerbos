// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"time"

	statev1 "github.com/cerbos/cerbos/api/genpb/cerbos/state/v1"
	telemetryv1 "github.com/cerbos/cerbos/api/genpb/cerbos/telemetry/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/blob"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/git"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/spf13/afero"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	doNotTrackEnvVar  = "DO_NOT_TRACK"
	noTelemetryEnvVar = "CERBOS_NO_TELEMETRY"

	minReportInterval = 24 * time.Hour
	stateFile         = "cerbos.telemetry.json"
)

func Report(ctx context.Context, store storage.Store) {
	logger := zap.L().Named("telemetry")

	conf := &Conf{}
	_ = config.GetSection(conf)

	if conf.Disabled {
		logger.Info("Telemetry disabled")
		return
	}

	go doReport(ctx, store, conf, logger)
}

func doReport(ctx context.Context, store storage.Store, conf *Conf, logger *zap.Logger) {
	defer func() {
		// don't let a panic in this goroutine crash the whole app.
		if err := recover(); err != nil {
			logger.Debug("Telemetry panic", zap.Any("cause", err))
		}
	}()

	fs := initStateFS(conf.StateDir)
	r := newReporter(store, fs, logger)
	r.report(ctx, true)
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

		if err := os.MkdirAll(dir, 0o700); err != nil {
			return afero.NewMemMapFs()
		}
	}

	if finfo != nil && !finfo.IsDir() {
		return afero.NewMemMapFs()
	}

	return afero.NewBasePathFs(afero.NewOsFs(), dir)
}

type reporter struct {
	fsys   afero.Fs
	store  storage.Store
	logger *zap.Logger
}

func newReporter(store storage.Store, fsys afero.Fs, logger *zap.Logger) *reporter {
	return &reporter{
		fsys:   fsys,
		store:  store,
		logger: logger,
	}
}

func (r *reporter) report(ctx context.Context, publish bool) bool {
	if !r.shouldReport() {
		return false
	}

	ping := buildPing(ctx, r.store)
	if publish {
		//TODO send ping
	}

	if err := r.writeState(ping); err != nil {
		r.logger.Debug("Failed to persist telemetry state", zap.Error(err))
	}

	return true
}

func (r *reporter) shouldReport() bool {
	for _, v := range []string{noTelemetryEnvVar, doNotTrackEnvVar} {
		if disabledByEnvVar(v) {
			r.logger.Info("Telemetry disabled")
			return false
		}
	}

	r.logger.Info(fmt.Sprintf("Anonymous telemetry enabled. Disable via the config file or by setting the %s=1 environment variable", noTelemetryEnvVar))

	return r.reportIsDue()
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

func (r *reporter) reportIsDue() bool {
	state := r.readState()

	if state == nil || state.LastTimestamp == nil {
		return true
	}

	lastTS := state.LastTimestamp.AsTime()
	return time.Since(lastTS) > minReportInterval
}

func (r *reporter) readState() *statev1.TelemetryState {
	state := &statev1.TelemetryState{}

	stateBytes, err := afero.ReadFile(r.fsys, stateFile)
	if err != nil {
		return state
	}

	_ = protojson.Unmarshal(stateBytes, state)

	return state
}

func (r *reporter) writeState(ping *telemetryv1.Ping) error {
	state := &statev1.TelemetryState{
		LastTimestamp: timestamppb.Now(),
		LastPayload:   ping,
	}

	stateBytes, err := protojson.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal proto: %w", err)
	}

	if err := afero.WriteFile(r.fsys, stateFile, stateBytes, 0o600); err != nil {
		return fmt.Errorf("failed to write state: %w", err)
	}

	return nil
}

func buildPing(ctx context.Context, store storage.Store) *telemetryv1.Ping {
	ping := &telemetryv1.Ping{Version: "1.0.0"}
	ping.Source = extractSource()
	ping.Features = extractFeatures()

	if is, ok := store.(storage.Instrumented); ok {
		stats := is.RepoStats(ctx)
		ping.Stats = extractStats(stats)
	}

	return ping
}

func extractSource() *telemetryv1.Ping_Source {
	s := &telemetryv1.Ping_Source{
		Cerbos: &telemetryv1.Ping_Cerbos{
			Version:   util.Version,
			Commit:    util.Commit,
			BuildDate: util.BuildDate,
		},
		Os:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		NumCpus: uint32(runtime.NumCPU()),
	}

	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Sum != "" {
		s.Cerbos.ModuleVersion = info.Main.Version
		s.Cerbos.ModuleChecksum = info.Main.Sum
	}

	return s
}

func extractFeatures() *telemetryv1.Ping_Features {
	feats := &telemetryv1.Ping_Features{}

	if auditConf, err := audit.GetConf(); err == nil {
		feats.Audit = &telemetryv1.Ping_Features_Audit{
			Backend: auditConf.Backend,
			Enabled: auditConf.Enabled,
		}
	}

	if schemaConf, err := schema.GetConf(); err == nil {
		feats.Schema = &telemetryv1.Ping_Features_Schema{
			Enforcement: string(schemaConf.Enforcement),
		}
	}

	// avoid an import cycle by not using server.Conf to retrieve this value
	var adminAPIEnabled bool
	if err := config.Get("server.adminAPI.enabled", &adminAPIEnabled); err != nil {
		feats.AdminApi = &telemetryv1.Ping_Features_AdminApi{
			Enabled: adminAPIEnabled,
		}
	}

	if storageConf, err := storage.GetConf(); err == nil {
		feats.Storage = &telemetryv1.Ping_Features_Storage{
			Driver: storageConf.Driver,
		}

		switch storageConf.Driver {
		case disk.DriverName:
			if diskConf, err := disk.GetConf(); err == nil {
				feats.Storage.Store = &telemetryv1.Ping_Features_Storage_Disk_{
					Disk: &telemetryv1.Ping_Features_Storage_Disk{
						Watch: diskConf.WatchForChanges,
					},
				}
			}
		case git.DriverName:
			if gitConf, err := git.GetConf(); err == nil {
				feats.Storage.Store = &telemetryv1.Ping_Features_Storage_Git_{
					Git: &telemetryv1.Ping_Features_Storage_Git{
						Protocol:     gitConf.Protocol,
						PollInterval: durationpb.New(gitConf.UpdatePollInterval),
						Auth:         gitConf.SSH != nil || gitConf.HTTPS != nil,
					},
				}
			}
		case blob.DriverName:
			if blobConf, err := blob.GetConf(); err == nil {
				b := &telemetryv1.Ping_Features_Storage_Blob{
					PollInterval: durationpb.New(blobConf.UpdatePollInterval),
				}

				if scheme, err := url.Parse(blobConf.Bucket); err == nil {
					b.Provider = scheme.Scheme
				}

				feats.Storage.Store = &telemetryv1.Ping_Features_Storage_Blob_{Blob: b}
			}
		}
	}

	return feats
}

func extractStats(stats storage.RepoStats) *telemetryv1.Ping_Stats {
	pb := &telemetryv1.Ping_Stats{
		Policy: &telemetryv1.Ping_Stats_Policy{
			Count:             make(map[string]uint32, len(stats.PolicyCount)),
			AvgRuleCount:      make(map[string]float64, len(stats.AvgRuleCount)),
			AvgConditionCount: make(map[string]float64, len(stats.AvgConditionCount)),
		},
		Schema: &telemetryv1.Ping_Stats_Schema{
			Count: uint32(stats.SchemaCount),
		},
	}

	for k, v := range stats.PolicyCount {
		pb.Policy.Count[k.String()] = uint32(v)
	}

	for k, v := range stats.AvgConditionCount {
		pb.Policy.AvgConditionCount[k.String()] = v
	}

	for k, v := range stats.AvgRuleCount {
		pb.Policy.AvgRuleCount[k.String()] = v
	}

	return pb
}
