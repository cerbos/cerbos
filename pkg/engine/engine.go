package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/cache"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cerbos/cerbos/pkg/compile"
	requestv1 "github.com/cerbos/cerbos/pkg/generated/request/v1"
	sharedv1 "github.com/cerbos/cerbos/pkg/generated/shared/v1"
	"github.com/cerbos/cerbos/pkg/namer"
	"github.com/cerbos/cerbos/pkg/storage"
)

var ErrNoPoliciesMatched = errors.New("no matching policies")

const (
	defaultEffect                = sharedv1.Effect_EFFECT_DENY
	maxQueryCacheSizeBytes int64 = 10 * 1024 * 1024 // 10 MiB
)

type Engine struct {
	log        *zap.SugaredLogger
	store      storage.Store
	compiler   *compile.Compiler
	queryCache cache.InterQueryCache
}

func New(ctx context.Context, store storage.Store) (*Engine, error) {
	compiler, err := compile.Compile(store.GetAllPolicies(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to compile policies: %w", err)
	}

	cacheSize := maxQueryCacheSizeBytes
	queryCache := cache.NewInterQueryCache(&cache.Config{
		InterQueryBuiltinCache: cache.InterQueryBuiltinCacheConfig{
			MaxSizeBytes: &cacheSize,
		},
	})

	engine := &Engine{
		log:        zap.S().Named("engine"),
		store:      store,
		compiler:   compiler,
		queryCache: queryCache,
	}

	go engine.watchNotifications(ctx)

	return engine, nil
}

func (engine *Engine) watchNotifications(ctx context.Context) {
	notificationChan := make(chan *compile.Incremental, 32) //nolint:gomnd
	defer close(notificationChan)

	engine.store.SetNotificationChannel(notificationChan)

	for {
		select {
		case <-ctx.Done():
			engine.log.Info("Stopping engine update watch")
			return
		case change := <-notificationChan:
			if errs := engine.compiler.Update(change); errs != nil {
				engine.log.Errorw("Failed to apply incremental update due to compilation error", "error", errs)
			} else {
				engine.log.Debug("Incremental update applied")
			}
		}
	}
}

func (engine *Engine) Check(ctx context.Context, req *requestv1.Request) (sharedv1.Effect, error) {
	log := engine.log.With("request_id", req.RequestId)

	var checks [2]*check
	count := 0

	if pc := engine.getPrincipalPolicyCheck(req); pc != nil {
		checks[count] = pc
		count++
	}

	if rc := engine.getResourcePolicyCheck(req); rc != nil {
		checks[count] = rc
		count++
	}

	if count == 0 {
		log.Debug("No applicable policies for request: denying")
		return defaultEffect, ErrNoPoliciesMatched
	}

	requestJSON, err := protojson.Marshal(req)
	if err != nil {
		log.Errorw("Failed to marshal request", "error", err)
		return defaultEffect, fmt.Errorf("failed to marshal request: %w", err)
	}

	input, err := ast.ValueFromReader(bytes.NewReader(requestJSON))
	if err != nil {
		log.Errorw("Failed to convert request", "error", err)
		return defaultEffect, fmt.Errorf("failed to convert request: %w", err)
	}

	for i := 0; i < count; i++ {
		c := checks[i]
		log.Debugw("Executing policy", "policy", c.policyName)

		effect, err := c.execute(ctx, engine.queryCache, input)
		if err != nil {
			log.Errorw("Policy execution failed", "policy", c.policyName, "error", err)
			return defaultEffect, fmt.Errorf("failed to execute policy %s: %w", c.policyName, err)
		}

		if effect != sharedv1.Effect_EFFECT_NO_MATCH {
			log.Debugw("Policy matched", "policy", c.policyName, "effect", sharedv1.Effect_name[int32(effect)])
			return effect, nil
		}
	}

	log.Warn("None of the policies produced a definitive answer")

	return defaultEffect, ErrNoPoliciesMatched
}

func (engine *Engine) getPrincipalPolicyCheck(req *requestv1.Request) *check {
	principal := req.Principal.Id
	version := req.Principal.Version

	if version == "" {
		version = namer.DefaultVersion
	}

	principalModID := namer.PrincipalPolicyModuleID(principal, version)
	if eval := engine.compiler.GetEvaluator(principalModID); eval != nil {
		return &check{
			policyName: fmt.Sprintf("%s:%s", principal, version),
			eval:       eval,
			query:      namer.EffectQueryForPrincipal(principal, version),
		}
	}

	return nil
}

func (engine *Engine) getResourcePolicyCheck(req *requestv1.Request) *check {
	resource := req.Resource.Name
	version := req.Resource.Version

	if version == "" {
		version = namer.DefaultVersion
	}

	resourceModID := namer.ResourcePolicyModuleID(resource, version)
	if eval := engine.compiler.GetEvaluator(resourceModID); eval != nil {
		return &check{
			policyName: fmt.Sprintf("%s:%s", resource, version),
			eval:       eval,
			query:      namer.EffectQueryForResource(resource, version),
		}
	}

	return nil
}

type check struct {
	policyName string
	eval       compile.Evaluator
	query      string
}

func (c *check) execute(ctx context.Context, queryCache cache.InterQueryCache, input ast.Value) (sharedv1.Effect, error) {
	return c.eval.EvalQuery(ctx, queryCache, c.query, input)
}
