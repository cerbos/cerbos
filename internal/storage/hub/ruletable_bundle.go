// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"go.uber.org/zap"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/util"
	bundleapi "github.com/cerbos/cloud-api/bundle"
	"github.com/cerbos/cloud-api/crypto"
	bundlev2 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v2"
)

var ErrUnsupportedOperation = errors.New("operation not supported by bundle")

const cerbosSchemaPrefix = schema.URLScheme + ":///"

type RuleTableBundle struct {
	ruleTable *ruletable.RuleTable
}

func OpenRuleTableBundle(opts OpenOpts) (*RuleTableBundle, error) {
	logger := zap.L().Named(DriverName).With(zap.String("path", opts.BundlePath))
	logger.Info("Opening rule table bundle")

	protoRT, err := decryptRuleTableBundle(opts, logger)
	if err != nil {
		return nil, err
	}

	ruleTable, err := ruletable.NewRuleTable(index.NewMem(), protoRT)
	if err != nil {
		return nil, err
	}

	logger.Info("Rule table bundle opened", zap.String("id", protoRT.GetManifest().GetBundleId()))
	return &RuleTableBundle{ruleTable: ruleTable}, nil
}

func decryptRuleTableBundle(opts OpenOpts, logger *zap.Logger) (*runtimev1.RuleTable, error) {
	input, err := os.Open(opts.BundlePath)
	if err != nil {
		logger.Debug("Failed to open rule table bundle", zap.Error(err))
		return nil, fmt.Errorf("failed to open rule table bundle at path %q: %w", opts.BundlePath, err)
	}
	defer input.Close()

	var decrypted io.Reader
	if opts.EncryptionKey == nil {
		decrypted = input
	} else {
		logger.Debug("Decrypting bundle")

		d := new(bytes.Buffer)
		if _, err := crypto.DecryptChaCha20Poly1305Stream(opts.EncryptionKey, input, d); err != nil {
			return nil, fmt.Errorf("failed to decrypt: %w", err)
		}

		decrypted = d
	}

	decryptedBytes, err := io.ReadAll(decrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted bundle contents: %w", err)
	}

	ruleTable := &runtimev1.RuleTable{}
	if err := ruleTable.UnmarshalVT(decryptedBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rule table: %w", err)
	}

	return ruleTable, nil
}

func (rtb *RuleTableBundle) ID() string {
	if rtb == nil || rtb.ruleTable == nil {
		return bundleapi.BundleIDUnknown
	}
	return rtb.ruleTable.GetManifest().GetBundleId()
}

func (*RuleTableBundle) Type() bundlev2.BundleType {
	return bundlev2.BundleType_BUNDLE_TYPE_RULE_TABLE
}

func (*RuleTableBundle) GetFirstMatch(_ context.Context, _ []namer.ModuleID) (*runtimev1.RunnablePolicySet, error) {
	return nil, ErrUnsupportedOperation
}

func (*RuleTableBundle) GetAll(_ context.Context) ([]*runtimev1.RunnablePolicySet, error) {
	return nil, ErrUnsupportedOperation
}

func (*RuleTableBundle) GetAllMatching(_ context.Context, _ []namer.ModuleID) ([]*runtimev1.RunnablePolicySet, error) {
	return nil, ErrUnsupportedOperation
}

func (*RuleTableBundle) InspectPolicies(_ context.Context, _ storage.ListPolicyIDsParams) (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	return nil, ErrUnsupportedOperation
}

func (rtb *RuleTableBundle) ListPolicyIDs(_ context.Context, params storage.ListPolicyIDsParams) ([]string, error) {
	if rtb == nil {
		return nil, ErrBundleNotLoaded
	}

	policyFQNs := make(map[string]struct{})
	for _, meta := range rtb.ruleTable.RuleTable.GetMeta() {
		policyFQNs[meta.GetFqn()] = struct{}{}
	}

	filteredSize := len(policyFQNs)
	var ss util.StringSet
	if len(params.IDs) > 0 {
		ss = util.ToStringSet(params.IDs)
		filteredSize = len(ss)
	}

	output := make([]string, 0, filteredSize)
	for fqn := range policyFQNs {
		if len(params.IDs) > 0 {
			if ss.Contains(fqn) {
				output = append(output, namer.PolicyKeyFromFQN(fqn))
			}
		} else {
			output = append(output, namer.PolicyKeyFromFQN(fqn))
		}
	}

	return output, nil
}

func (rtb *RuleTableBundle) ListSchemaIDs(_ context.Context) ([]string, error) {
	if rtb == nil {
		return nil, ErrBundleNotLoaded
	}

	schemas := rtb.ruleTable.GetJsonSchemas()
	output := make([]string, 0, len(schemas))
	for schemaName := range schemas {
		output = append(output, strings.TrimPrefix(schemaName, cerbosSchemaPrefix))
	}

	return output, nil
}

func (rtb *RuleTableBundle) LoadSchema(_ context.Context, path string) (io.ReadCloser, error) {
	if rtb == nil {
		return nil, ErrBundleNotLoaded
	}

	qualifiedPath := cerbosSchemaPrefix + path

	schemaDef, exists := rtb.ruleTable.GetJsonSchemas()[qualifiedPath]
	if exists {
		return io.NopCloser(bytes.NewReader(schemaDef.GetContent())), nil
	}

	return nil, fmt.Errorf("schema %s not found", path)
}

func (rtb *RuleTableBundle) GetRuleTable() (*runtimev1.RuleTable, error) {
	if rtb == nil || rtb.ruleTable == nil {
		return nil, ErrBundleNotLoaded
	}

	return rtb.ruleTable.RuleTable, nil
}

func (rtb *RuleTableBundle) Release() error {
	if rtb != nil {
		rtb.ruleTable = nil
	}

	return nil
}

func (*RuleTableBundle) Close() error {
	return nil
}
