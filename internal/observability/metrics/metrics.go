package metrics

import (
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
)

var (
	KeyCompileStatus        = tag.MustNewKey("status")
	KeyEngineDecisionEffect = tag.MustNewKey("effect")
	KeyEngineDecisionStatus = tag.MustNewKey("status")
	KeyEngineUpdateType     = tag.MustNewKey("update_type")
	KeyEngineUpdateStatus   = tag.MustNewKey("update_status")
)

var (
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

	EngineDecisionLatency = stats.Float64(
		"cerbos.dev/engine/decision_latency",
		"Time to match a request against a policy and provide a decision",
		stats.UnitMilliseconds,
	)

	EngineDecisionLatencyView = &view.View{
		Measure:     EngineDecisionLatency,
		TagKeys:     []tag.Key{KeyEngineDecisionEffect, KeyEngineDecisionStatus},
		Aggregation: defaultLatencyDistribution(),
	}

	EngineUpdateLatency = stats.Float64(
		"cerbos.dev/engine/update_latency",
		"Time to apply an update to the engine",
		stats.UnitMilliseconds,
	)

	EngineUpdateLatencyView = &view.View{
		Measure:     EngineUpdateLatency,
		TagKeys:     []tag.Key{KeyEngineUpdateType, KeyEngineUpdateStatus},
		Aggregation: defaultLatencyDistribution(),
	}
)

var DefaultCerbosViews = []*view.View{
	CompileDurationView,
	EngineDecisionLatencyView,
	EngineUpdateLatencyView,
}

func defaultLatencyDistribution() *view.Aggregation {
	return view.Distribution(0.01, 0.05, 0.1, 0.3, 0.6, 0.8, 1, 2, 3, 4, 5, 6, 8, 10, 13, 16, 20, 25, 30, 40, 50, 65, 80, 100, 130, 160, 200, 250, 300, 400, 500, 650, 800, 1000, 2000, 5000, 10000, 20000, 50000, 100000) //nolint:gomnd
}
