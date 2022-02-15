// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build loadtest
// +build loadtest

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/mattn/go-isatty"
	"go.elastic.co/ecszap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	"github.com/cerbos/cerbos/hack/loadtest/internal"
)

const (
	defaultLogLevel = "ERROR"

	numMatchExpr           = 1
	numRoleNames           = 1
	numDerivedRolesPerFile = 10

	fileWritePerm = 0o600
)

var (
	logger *zap.SugaredLogger
)

var cli struct {
	OutputDir      string `help:"Directory to write generated policy files" type:"path"`
	PolicySetCount int    `help:"Number of policy sets to generate"`
}

func init() {
	if envLevel := os.Getenv("GENRES_LOG_LEVEL"); envLevel != "" {
		doInitLogging(envLevel)
		return
	}
	doInitLogging(defaultLogLevel)
}

func main() {
	kong.Parse(&cli,
		kong.Description("Painless access controls for cloud-native applications"),
		kong.UsageOnError(),
	)

	policies, requests, err := mkPolicies(cli.PolicySetCount, 1)
	if err != nil {
		logger.Fatalf("failed to generate policies and http requests: %v", err)
	}

	policyIdx := make([]string, len(policies))
	requestIdx := make([]string, len(requests))
	for idx, p := range policies {
		data, err := protojson.Marshal(p)
		if err != nil {
			logger.Fatalf("failed to marshal the policy: %v", err)
		}

		err = os.WriteFile(filepath.Join(cli.OutputDir, "policies", fmt.Sprintf("%d.json", idx)), data, fileWritePerm)
		if err != nil {
			logger.Fatalf("failed to write generated policy to the file system: %v", err)
		}

		policyIdx[idx] = fmt.Sprintf("%d.json", idx)
	}

	for idx, r := range requests {
		data, err := protojson.Marshal(r)
		if err != nil {
			logger.Fatalf("failed to marshal the request: %v", err)
		}

		err = os.WriteFile(filepath.Join(cli.OutputDir, "requests", fmt.Sprintf("%d.json", idx)), data, fileWritePerm)
		if err != nil {
			logger.Fatalf("failed to write generated request to the file system: %v", err)
		}

		requestIdx[idx] = fmt.Sprintf("%d.json", idx)
	}

	policyIdxBytes, err := json.Marshal(policyIdx)
	if err != nil {
		logger.Fatalf("failed to marshal policy index: %v", err)
	}

	requestIdxBytes, err := json.Marshal(policyIdx)
	if err != nil {
		logger.Fatalf("failed to marshal request index: %v", err)
	}

	err = os.WriteFile(filepath.Join(cli.OutputDir, "policy-index.json"), policyIdxBytes, fileWritePerm)
	if err != nil {
		logger.Fatalf("failed to policy index to the file system: %v", err)
	}

	err = os.WriteFile(filepath.Join(cli.OutputDir, "request-index.json"), requestIdxBytes, fileWritePerm)
	if err != nil {
		logger.Fatalf("failed to request index to the file system: %v", err)
	}
}

type namer func() string

func prefix(prefix string) namer {
	counter := 1
	return func() string {
		name := fmt.Sprintf("%s%d", prefix, counter)
		counter++
		return name
	}
}

type namersParam struct {
	drNamer   namer
	rpNamer   namer
	roleNamer namer
}

func mkPolicies(numPolicySet, numDerivedRolesFiles int) ([]*policyv1.Policy, []*requestv1.CheckResourceSetRequest, error) {
	namers := namersParam{
		drNamer:   prefix("derived_roles_"),
		rpNamer:   prefix("resource_policies_"),
		roleNamer: prefix("role_"),
	}

	var policies []*policyv1.Policy
	var requests []*requestv1.CheckResourceSetRequest
	for i := 0; i < numPolicySet; i++ {
		var p []*policyv1.Policy
		var reqs []*requestv1.CheckResourceSetRequest
		var err error
		p, reqs, err = generateResourcePolicyWithRequests(namers, numDerivedRolesFiles)
		if err != nil {
			return nil, nil, err
		}
		policies = append(policies, p...)
		requests = append(requests, reqs...)
	}

	return policies, requests, nil
}

func mkCheckRequest(resPol *policyv1.Policy, attrs, roles, actions []string) ([]*requestv1.CheckResourceSetRequest, error) {
	reqs := make([]*requestv1.CheckResourceSetRequest, len(attrs))
	p, ok := resPol.PolicyType.(*policyv1.Policy_ResourcePolicy)
	if !ok {
		return nil, fmt.Errorf("policy kind must be resource")
	}

	const instanceName = "INS_XXX"
	mainAttr := attrs[0]
	for idx, attr := range attrs[1:] {
		attrMap := map[string]*structpb.Value{
			mainAttr: {
				Kind: &structpb.Value_StringValue{StringValue: mainAttr},
			},
			attr: {
				Kind: &structpb.Value_StringValue{StringValue: attr},
			},
		}

		req := &requestv1.CheckResourceSetRequest{
			RequestId: "REQ_XXX",
			Actions:   actions,
			Principal: &enginev1.Principal{
				Id:            "someuser",
				PolicyVersion: p.ResourcePolicy.Version,
				Roles:         roles,
				Attr:          attrMap,
			},
			Resource: &requestv1.ResourceSet{
				Kind:          p.ResourcePolicy.Resource,
				PolicyVersion: p.ResourcePolicy.Version,
				Instances: map[string]*requestv1.AttributesMap{
					instanceName: {Attr: attrMap},
				},
			},
		}
		reqs[idx] = req
	}

	return reqs, nil
}

// generateResourcePolicyWithRequests generates a single resource policy containing imports to numDerivedRolesFiles of derived roles.
// Each derived role file consists of numDerivedRolesPerFile.
func generateResourcePolicyWithRequests(namers namersParam, numDerivedRolesFiles int) ([]*policyv1.Policy, []*requestv1.CheckResourceSetRequest, error) {
	resource := namers.rpNamer()
	rp := internal.NewResourcePolicyBuilder(resource, "default")

	var policies []*policyv1.Policy
	var attrs []string
	var roles []string
	var actions []string
	for i := 0; i < numDerivedRolesFiles; i++ {
		drName := namers.drNamer()
		resExpr, resAttrs := mkMatchExpr(numMatchExpr)
		attrs = append(attrs, resAttrs...)
		action := fmt.Sprintf("action_%d", i)
		actions = append(actions, action)

		rr := internal.NewResourceRule(action).WithEffect(effectv1.Effect_EFFECT_ALLOW).WithMatchExpr(resExpr...)
		dr := internal.NewDerivedRolesBuilder(drName)
		for j := 0; j < numDerivedRolesPerFile; j++ {
			name := namers.roleNamer()
			drExpr, drAttrs := mkMatchExpr(numMatchExpr)
			attrs = append(attrs, drAttrs...)
			parentRole := mkParentRoleNames(numRoleNames)
			roles = append(roles, parentRole...)
			dr = dr.AddRoleWithMatch(name, parentRole, drExpr...)
			rr = rr.WithDerivedRoles(name)
		}

		drPol := dr.Build()
		policies = append(policies, drPol)
		rp = rp.WithDerivedRolesImports(drName).WithRules(rr.Build())
	}

	rpPol := rp.Build()
	requests, err := mkCheckRequest(rpPol, attrs, roles, actions)
	if err != nil {
		return nil, nil, err
	}

	policies = append(policies, rpPol)

	return policies, requests, nil
}

var attrNamer = prefix("attr_")

func mkMatchExpr(n int) ([]string, []string) {
	exprs := make([]string, n)
	attrNames := make([]string, n)
	for i := 0; i < n; i++ {
		attrName := attrNamer()
		exprs[i] = fmt.Sprintf("request.principal.attr.%s == request.resource.attr.%s", attrName, attrName)
		attrNames[i] = attrName
	}

	return exprs, attrNames
}

var parentRoleNamer = prefix("parent_role_")

func mkParentRoleNames(n int) []string {
	roles := make([]string, n)
	for i := 0; i < n; i++ {
		roles[i] = parentRoleNamer()
	}

	return roles
}

func doInitLogging(level string) {
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

	encoderConf := ecszap.NewDefaultEncoderConfig().ToZapCoreEncoderConfig()
	var consoleEncoder zapcore.Encoder

	if !isatty.IsTerminal(os.Stdout.Fd()) {
		consoleEncoder = zapcore.NewJSONEncoder(encoderConf)
	} else {
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
	l := zap.New(core, zap.AddStacktrace(stackTraceEnabler))

	zap.ReplaceGlobals(l.Named("confdocs"))
	zap.RedirectStdLog(l.Named("stdlog"))

	logger = l.Sugar()
}
