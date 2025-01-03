// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"net/url"
	"runtime"
	"runtime/debug"

	telemetryv1 "github.com/cerbos/cerbos/api/genpb/cerbos/telemetry/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/blob"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/git"
	"github.com/cerbos/cerbos/internal/storage/hub"
	"github.com/cerbos/cerbos/internal/util"
	"google.golang.org/protobuf/types/known/durationpb"
)

func buildServerLaunch(store storage.Store) *telemetryv1.ServerLaunch {
	evt := &telemetryv1.ServerLaunch{
		Version:  "1.0.0",
		Source:   extractSource(),
		Features: extractFeatures(store),
	}

	if is, ok := store.(storage.Instrumented); ok {
		stats := is.RepoStats(context.Background())
		evt.Stats = extractStats(stats)
	}

	return evt
}

func extractSource() *telemetryv1.ServerLaunch_Source {
	s := &telemetryv1.ServerLaunch_Source{
		Cerbos: &telemetryv1.ServerLaunch_Cerbos{
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

func extractFeatures(store storage.Store) *telemetryv1.ServerLaunch_Features {
	feats := &telemetryv1.ServerLaunch_Features{}

	if auditConf, err := audit.GetConf(); err == nil {
		feats.Audit = &telemetryv1.ServerLaunch_Features_Audit{
			Backend: auditConf.Backend,
			Enabled: auditConf.Enabled,
		}
	}

	if schemaConf, err := schema.GetConf(); err == nil {
		feats.Schema = &telemetryv1.ServerLaunch_Features_Schema{
			Enforcement: string(schemaConf.Enforcement),
		}
	}

	// avoid an import cycle by not using server.Conf to retrieve this value
	var adminAPIEnabled bool
	if err := config.Get("server.adminAPI.enabled", &adminAPIEnabled); err != nil {
		feats.AdminApi = &telemetryv1.ServerLaunch_Features_AdminApi{
			Enabled: adminAPIEnabled,
		}
	}

	//nolint:nestif
	if storageConf, err := storage.GetConf(); err == nil {
		feats.Storage = &telemetryv1.ServerLaunch_Features_Storage{
			Driver: storageConf.Driver,
		}

		switch storageConf.Driver {
		case disk.DriverName:
			if diskConf, err := disk.GetConf(); err == nil {
				feats.Storage.Store = &telemetryv1.ServerLaunch_Features_Storage_Disk_{
					Disk: &telemetryv1.ServerLaunch_Features_Storage_Disk{
						Watch: diskConf.WatchForChanges,
					},
				}
			}
		case git.DriverName:
			if gitConf, err := git.GetConf(); err == nil {
				feats.Storage.Store = &telemetryv1.ServerLaunch_Features_Storage_Git_{
					Git: &telemetryv1.ServerLaunch_Features_Storage_Git{
						Protocol:     gitConf.Protocol,
						PollInterval: durationpb.New(gitConf.UpdatePollInterval),
						Auth:         gitConf.SSH != nil || gitConf.HTTPS != nil,
					},
				}
			}
		case blob.DriverName:
			if blobConf, err := blob.GetConf(); err == nil {
				b := &telemetryv1.ServerLaunch_Features_Storage_Blob{
					PollInterval: durationpb.New(blobConf.UpdatePollInterval),
				}

				if scheme, err := url.Parse(blobConf.Bucket); err == nil {
					b.Provider = scheme.Scheme
				}

				feats.Storage.Store = &telemetryv1.ServerLaunch_Features_Storage_Blob_{Blob: b}
			}
		case hub.DriverName:
			if bundleConf, err := hub.GetConf(); err == nil {
				pdpID := util.PDPIdentifier(bundleConf.Credentials.PDPID)
				b := &telemetryv1.ServerLaunch_Features_Storage_Bundle{
					PdpId:    pdpID.GetInstance(),
					ClientId: bundleConf.Credentials.ClientID,
				}

				if src, ok := store.(hub.Source); ok {
					b.BundleSource = src.SourceKind()
				}

				feats.Storage.Store = &telemetryv1.ServerLaunch_Features_Storage_Bundle_{Bundle: b}
			}
		}
	}

	return feats
}

func extractStats(stats storage.RepoStats) *telemetryv1.ServerLaunch_Stats {
	pb := &telemetryv1.ServerLaunch_Stats{
		Policy: &telemetryv1.ServerLaunch_Stats_Policy{
			Count:             make(map[string]uint32, len(stats.PolicyCount)),
			AvgRuleCount:      make(map[string]float64, len(stats.AvgRuleCount)),
			AvgConditionCount: make(map[string]float64, len(stats.AvgConditionCount)),
		},
		Schema: &telemetryv1.ServerLaunch_Stats_Schema{
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
