// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0
package metrics

import (
	"go.opencensus.io/metric"
	"go.opencensus.io/metric/metricdata"
	"go.opencensus.io/metric/metricproducer"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
	"go.uber.org/zap"
)

var (
	registry   = metric.NewRegistry()
	cacheGauge *metric.Int64Gauge
)

func init() {
	metricproducer.GlobalManager().AddProducer(registry)

	var err error
	cacheGauge, err = registry.AddInt64Gauge("cerbos.dev/cache/live_objects",
		metric.WithDescription("Number of live objects in the cache"),
		metric.WithLabelKeys(KeyCacheKind.Name()),
		metric.WithUnit(metricdata.UnitDimensionless),
	)
	if err != nil {
		zap.L().Warn("Failed to create cache gauge", zap.Error(err))
	}
}

var (
	KeyAuditKind            = tag.MustNewKey("kind")
	KeyBundleSource         = tag.MustNewKey("source")
	KeyBundleOp             = tag.MustNewKey("op")
	KeyBundleOpStatus       = tag.MustNewKey("status")
	KeyBundleRemoteEvent    = tag.MustNewKey("remote_event")
	KeyCacheKind            = tag.MustNewKey("kind")
	KeyCacheResult          = tag.MustNewKey("result")
	KeyCompileStatus        = tag.MustNewKey("status")
	KeyEngineDecisionStatus = tag.MustNewKey("status")
	KeyEnginePlanStatus     = tag.MustNewKey("status")
	KeyIndexCRUDKind        = tag.MustNewKey("kind")
	KeyStoreDriver          = tag.MustNewKey("driver")
)

var (
	AuditErrorCount = stats.Int64(
		"cerbos.dev/audit/error_count",
		"Number of errors encountered while writing audit log entry",
		stats.UnitDimensionless,
	)

	AuditErrorCountView = &view.View{
		Measure:     AuditErrorCount,
		TagKeys:     []tag.Key{KeyAuditKind},
		Aggregation: view.Count(),
	}

	BundleFetchErrorsCount = stats.Int64(
		"cerbos.dev/store/bundle_fetch_errors_count",
		"Count of errors encountered during bundle downloads",
		stats.UnitNone,
	)

	BundleFetchErrorsCountView = &view.View{
		Measure:     BundleFetchErrorsCount,
		Aggregation: view.Count(),
	}

	BundleNotFoundErrorsCount = stats.Int64(
		"cerbos.dev/store/bundle_not_found_errors_count",
		"Count of bundle not found errors",
		stats.UnitNone,
	)

	BundleNotFoundErrorsCountView = &view.View{
		Measure:     BundleNotFoundErrorsCount,
		Aggregation: view.Count(),
	}

	BundleStoreLatency = stats.Float64(
		"cerbos.dev/store/bundle_op_latency",
		"Time to do an operation with the bundle store",
		stats.UnitMilliseconds,
	)

	BundleStoreLatencyView = &view.View{
		Measure:     BundleStoreLatency,
		TagKeys:     []tag.Key{KeyBundleSource, KeyBundleOp, KeyBundleOpStatus},
		Aggregation: defaultLatencyDistribution(),
	}

	BundleStoreRemoteEventsCount = stats.Int64(
		"cerbos.dev/store/bundle_remote_events_count",
		"Count of remote server events received by the bundle store",
		stats.UnitNone,
	)

	BundleStoreRemoteEventsCountView = &view.View{
		Measure:     BundleStoreRemoteEventsCount,
		TagKeys:     []tag.Key{KeyBundleRemoteEvent},
		Aggregation: view.Count(),
	}

	BundleStoreUpdatesCount = stats.Int64(
		"cerbos.dev/store/bundle_updates_count",
		"Count of bundle updates from remote source",
		stats.UnitNone,
	)

	BundleStoreUpdatesCountView = &view.View{
		Measure:     BundleStoreUpdatesCount,
		Aggregation: view.Count(),
	}

	CacheAccessCount = stats.Int64(
		"cerbos.dev/cache/access_count",
		"Counter of cache access",
		stats.UnitDimensionless,
	)

	CacheAccessCountView = &view.View{
		Measure:     CacheAccessCount,
		TagKeys:     []tag.Key{KeyCacheKind, KeyCacheResult},
		Aggregation: view.Count(),
	}

	CacheMaxSize = stats.Int64(
		"cerbos.dev/cache/max_size",
		"Maximum capacity of the cache",
		stats.UnitDimensionless,
	)

	CacheMaxSizeView = &view.View{
		Measure:     CacheMaxSize,
		TagKeys:     []tag.Key{KeyCacheKind},
		Aggregation: view.LastValue(),
	}

	HubConnectedCount = stats.Int64(
		"cerbos.dev/hub/connected",
		"Is the instance connected to Cerbos Hub",
		stats.UnitDimensionless,
	)

	HubConnectedCountView = &view.View{
		Measure:     HubConnectedCount,
		Aggregation: view.LastValue(),
	}

	CompileDuration = stats.Float64(
		"cerbos.dev/compiler/compile_duration",
		"Time to compile a set of policies",
		stats.UnitMilliseconds,
	)

	CompileDurationView = &view.View{
		Measure:     CompileDuration,
		TagKeys:     []tag.Key{KeyCompileStatus},
		Aggregation: defaultLatencyDistribution(),
	}

	EngineCheckLatency = stats.Float64(
		"cerbos.dev/engine/check_latency",
		"Time to match a request against a policy and provide a decision",
		stats.UnitMilliseconds,
	)

	EngineCheckLatencyView = &view.View{
		Measure:     EngineCheckLatency,
		TagKeys:     []tag.Key{KeyEngineDecisionStatus},
		Aggregation: defaultLatencyDistribution(),
	}

	EngineCheckBatchSize = stats.Int64(
		"cerbos.dev/engine/check_batch_size",
		"Batch size distribution of check requests",
		stats.UnitDimensionless,
	)

	EngineCheckBatchSizeView = &view.View{
		Measure:     EngineCheckBatchSize,
		Aggregation: view.Distribution(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16, 18, 20, 25, 30, 35, 40, 45, 50), //nolint:gomnd
	}

	EnginePlanLatency = stats.Float64(
		"cerbos.dev/engine/plan_latency",
		"Time to produce a query plan",
		stats.UnitMilliseconds,
	)

	EnginePlanLatencyView = &view.View{
		Measure:     EnginePlanLatency,
		TagKeys:     []tag.Key{KeyEnginePlanStatus},
		Aggregation: defaultLatencyDistribution(),
	}

	IndexCRUDCount = stats.Int64(
		"cerbos.dev/index/crud_count",
		"Number of create/update/delete operations",
		stats.UnitDimensionless,
	)

	IndexCRUDCountView = &view.View{
		Measure:     IndexCRUDCount,
		TagKeys:     []tag.Key{KeyIndexCRUDKind},
		Aggregation: view.Count(),
	}

	IndexEntryCount = stats.Int64(
		"cerbos.dev/index/entry_count",
		"Number of entries in the index",
		stats.UnitDimensionless,
	)

	IndexEntryCountView = &view.View{
		Measure:     IndexEntryCount,
		Aggregation: view.LastValue(),
	}

	StorePollCount = stats.Int64(
		"cerbos.dev/store/poll_count",
		"Number of times the remote store was polled for updates",
		stats.UnitDimensionless,
	)

	StorePollCountView = &view.View{
		Measure:     StorePollCount,
		TagKeys:     []tag.Key{KeyStoreDriver},
		Aggregation: view.Count(),
	}

	StoreSyncErrorCount = stats.Int64(
		"cerbos.dev/store/sync_error_count",
		"Number of errors encountered while syncing updates from the remote store",
		stats.UnitDimensionless,
	)

	StoreSyncErrorCountView = &view.View{
		Measure:     StoreSyncErrorCount,
		TagKeys:     []tag.Key{KeyStoreDriver},
		Aggregation: view.Count(),
	}
)

var DefaultCerbosViews = []*view.View{
	AuditErrorCountView,
	BundleFetchErrorsCountView,
	BundleNotFoundErrorsCountView,
	BundleStoreLatencyView,
	BundleStoreRemoteEventsCountView,
	BundleStoreUpdatesCountView,
	CacheAccessCountView,
	CacheMaxSizeView,
	CompileDurationView,
	EngineCheckLatencyView,
	EngineCheckBatchSizeView,
	EnginePlanLatencyView,
	HubConnectedCountView,
	IndexCRUDCountView,
	IndexEntryCountView,
	StorePollCountView,
	StoreSyncErrorCountView,
}

func defaultLatencyDistribution() *view.Aggregation {
	return view.Distribution(0.01, 0.05, 0.1, 0.3, 0.6, 0.8, 1, 2, 3, 4, 5, 6, 8, 10, 13, 16, 20, 25, 30, 40, 50, 65, 80, 100, 130, 160, 200, 250, 300, 400, 500, 650, 800, 1000, 2000, 5000, 10000, 20000, 50000, 100000) //nolint:gomnd
}

func MakeCacheGauge(kind string) CacheGauge {
	if cacheGauge == nil {
		return CacheGauge{}
	}

	return CacheGauge{
		lbl: metricdata.NewLabelValue(kind),
		g:   cacheGauge,
	}
}

type CacheGauge struct {
	g   *metric.Int64Gauge
	lbl metricdata.LabelValue
}

func (c CacheGauge) Add(v int64) {
	if c.g == nil {
		return
	}

	entry, err := c.g.GetEntry(c.lbl)
	if err == nil && entry != nil {
		entry.Add(v)
	}
}
