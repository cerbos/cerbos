package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"

	requestv1 "github.com/charithe/menshen/pkg/generated/request/v1"
	sharedv1 "github.com/charithe/menshen/pkg/generated/shared/v1"
	"github.com/charithe/menshen/pkg/namer"
)

const defaultEffect = sharedv1.Effect_EFFECT_DENY

var (
	ErrUnexpectedResult  = errors.New("unexpected result")
	ErrNoPoliciesMatched = errors.New("no matching policies")
)

// Checker implements policy checking.
type Checker struct {
	log      *zap.SugaredLogger
	compiler *ast.Compiler
}

// Check evaluates matching policies against the request and returns an ALLOW or DENY.
func (c *Checker) Check(ctx context.Context, req *requestv1.Request) (sharedv1.Effect, error) {
	var queries [2]string
	i := 0

	log := c.log.With("request_id", req.RequestId)

	principal, principalVer := getPrincipalAndVersion(req)
	principalMod := namer.PrincipalPolicyModuleName(principal, principalVer)
	if _, exists := c.compiler.Modules[principalMod]; exists {
		queries[i] = namer.EffectQueryForPrincipal(principal, principalVer)
		i++

		log.Debugw("Found matching principal policy", "principal", principal, "version", principalVer)
	} else {
		log.Debugw("No matching principal policy", "principal", principal, "version", principalVer)
	}

	resource, resourceVer := getResourceAndVersion(req)
	resourceMod := namer.ResourcePolicyModuleName(resource, resourceVer)
	if _, exists := c.compiler.Modules[resourceMod]; exists {
		queries[i] = namer.EffectQueryForResource(resource, resourceVer)
		i++

		log.Debugw("Found matching resource policy", "resource", resource, "version", resourceVer)
	} else {
		log.Debugw("No matching resource policy", "resource", resource, "version", resourceVer)
	}

	if i == 0 {
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

	for ctr := 0; ctr < i; ctr++ {
		effect, err := c.evaluateQuery(ctx, queries[ctr], input)
		if err != nil {
			log.Errorw("Query evaluation failed", "error", err)
			return defaultEffect, err
		}

		if effect != sharedv1.Effect_EFFECT_NO_MATCH {
			return effect, nil
		}
	}

	return defaultEffect, ErrNoPoliciesMatched
}

func (c *Checker) evaluateQuery(ctx context.Context, query string, input ast.Value) (sharedv1.Effect, error) {
	r := rego.New(
		rego.Compiler(c.compiler),
		rego.ParsedInput(input),
		rego.Query(query))

	rs, err := r.Eval(ctx)
	if err != nil {
		return defaultEffect, fmt.Errorf("query evaluation failed: %w", err)
	}

	return extractEffect(rs)
}

func extractEffect(rs rego.ResultSet) (sharedv1.Effect, error) {
	if len(rs) == 0 || len(rs) > 1 || len(rs[0].Expressions) != 1 {
		return sharedv1.Effect_EFFECT_DENY, ErrUnexpectedResult
	}

	switch rs[0].Expressions[0].String() {
	case "allow":
		return sharedv1.Effect_EFFECT_ALLOW, nil
	case "deny":
		return sharedv1.Effect_EFFECT_DENY, nil
	case "no_match":
		return sharedv1.Effect_EFFECT_NO_MATCH, nil
	default:
		return sharedv1.Effect_EFFECT_DENY, nil
	}
}

func getPrincipalAndVersion(req *requestv1.Request) (principal, version string) {
	principal = req.Principal.Id
	version = req.Principal.Version

	if version == "" {
		version = namer.DefaultVersion
	}

	return
}

func getResourceAndVersion(req *requestv1.Request) (resource, version string) {
	resource = req.Resource.Name
	version = req.Resource.Version

	if version == "" {
		version = namer.DefaultVersion
	}

	return
}
