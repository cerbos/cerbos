// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"fmt"
	"net"
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
	r := newReporter(store)
	go r.report(ctx, true)
}

type reporter struct {
	conf   *Conf
	fsys   afero.Fs
	store  storage.Store
	logger *zap.Logger
}

func newReporter(store storage.Store) *reporter {
	fs := afero.NewBasePathFs(afero.NewOsFs(), stateDir())

	conf := &Conf{}
	_ = config.GetSection(conf)

	return newReporterWithArgs(conf, store, fs)
}

func newReporterWithArgs(conf *Conf, store storage.Store, fsys afero.Fs) *reporter {
	return &reporter{
		conf:   conf,
		fsys:   fsys,
		store:  store,
		logger: zap.L().Named("telemetry"),
	}
}

func stateDir() string {
	confDir, err := os.UserConfigDir()
	if err != nil {
		confDir = os.TempDir()
	}

	sdir := filepath.Join(confDir, util.AppName)
	if err := os.MkdirAll(sdir, 0o700); err != nil {
		return confDir
	}

	return sdir
}

func (r *reporter) report(ctx context.Context, publish bool) bool {
	defer func() {
		// don't let a panic in this goroutine crash the whole app.
		if err := recover(); err != nil {
			r.logger.Debug("Telemetry panic", zap.Any("cause", err))
		}
	}()

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
			r.logger.Info(fmt.Sprintf("Telemetry disabled by %s environment variable", v))
			return false
		}
	}

	if r.conf != nil && r.conf.Disabled {
		r.logger.Info("Telemetry disabled by configuration")
		return false
	}

	r.logger.Info("Anonymous telemetry enabled. Disable via the config file or by setting the CERBOS_NO_TELEMETRY=1 environment variable")

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

	if state == nil || state.GetLastTimestamp() == nil {
		return true
	}

	lastTS := state.GetLastTimestamp()
	return time.Since(lastTS.AsTime()) > minReportInterval
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

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return s
	}

	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if ok && !ipNet.IP.IsLoopback() {
			s.IpAddressHash = util.HashStr(ipNet.IP.String())
		}
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
		case "disk":
			if diskConf, err := disk.GetConf(); err == nil {
				feats.Storage.Disk = &telemetryv1.Ping_Features_Storage_Disk{
					Watch: diskConf.WatchForChanges,
				}
			}

		case "git":
			if gitConf, err := git.GetConf(); err == nil {
				feats.Storage.Git = &telemetryv1.Ping_Features_Storage_Git{
					Protocol:     gitConf.Protocol,
					PollInterval: durationpb.New(gitConf.UpdatePollInterval),
					Auth:         gitConf.SSH != nil || gitConf.HTTPS != nil,
				}
			}
		case "blob":
			if blobConf, err := blob.GetConf(); err == nil {
				feats.Storage.Blob = &telemetryv1.Ping_Features_Storage_Blob{
					PollInterval: durationpb.New(blobConf.UpdatePollInterval),
				}

				if scheme, err := url.Parse(blobConf.Bucket); err == nil {
					feats.Storage.Blob.Provider = scheme.Scheme
				}
			}
		}
	}

	return feats
}

func extractStats(stats storage.RepoStats) *telemetryv1.Ping_Stats {
	pb := &telemetryv1.Ping_Stats{
		PolicyCount:       make(map[string]uint32, len(stats.PolicyCount)),
		AvgRuleCount:      make(map[string]float64, len(stats.AvgRuleCount)),
		AvgConditionCount: make(map[string]float64, len(stats.AvgConditionCount)),
		SchemaCount:       uint32(stats.SchemaCount),
	}

	for k, v := range stats.PolicyCount {
		pb.PolicyCount[k.String()] = uint32(v)
	}

	for k, v := range stats.AvgConditionCount {
		pb.AvgConditionCount[k.String()] = v
	}

	for k, v := range stats.AvgRuleCount {
		pb.AvgRuleCount[k.String()] = v
	}

	return pb
}
