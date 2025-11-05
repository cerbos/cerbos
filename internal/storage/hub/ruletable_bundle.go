// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"

	"go.uber.org/zap"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/storage"
	bundleapi "github.com/cerbos/cloud-api/bundle"
	"github.com/cerbos/cloud-api/crypto"
)

var ErrUnsupportedOperation = errors.New("operation not supported by bundle")

type RuleTableBundle struct {
	hash      string
	ruleTable *runtimev1.RuleTable
}

func OpenRuleTableBundle(opts OpenOpts) (*RuleTableBundle, error) {
	logger := zap.L().Named(DriverName).With(zap.String("path", opts.BundlePath))
	logger.Info("Opening rule table bundle")

	ruleTable, hash, err := decryptRuleTableBundle(opts, logger)
	if err != nil {
		return nil, err
	}

	logger.Info("Rule table bundle opened", zap.String("hash", hash))
	return &RuleTableBundle{ruleTable: ruleTable, hash: hash}, nil
}

func decryptRuleTableBundle(opts OpenOpts, logger *zap.Logger) (*runtimev1.RuleTable, string, error) {
	input, err := os.Open(opts.BundlePath)
	if err != nil {
		logger.Debug("Failed to open rule table bundle", zap.Error(err))
		return nil, "", fmt.Errorf("failed to open rule table bundle at path %q: %w", opts.BundlePath, err)
	}
	defer input.Close()

	var decrypted io.Reader
	if opts.EncryptionKey == nil {
		decrypted = input
	} else {
		logger.Debug("Decrypting bundle")

		d := new(bytes.Buffer)
		if _, err := crypto.DecryptChaCha20Poly1305Stream(opts.EncryptionKey, input, d); err != nil {
			return nil, "", fmt.Errorf("failed to decrypt: %w", err)
		}

		decrypted = d
	}

	// The hashing here is done because rule tables don't have identifiers like the legacy bundles.
	// We need to be able to look at the logs and identify when distinct bundles are swapped in. The hash would help with that.
	hasher := sha256.New()
	decryptedStream := io.TeeReader(decrypted, hasher)
	decryptedBytes, err := io.ReadAll(decryptedStream)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read decrypted bundle contents: %w", err)
	}

	ruleTable := &runtimev1.RuleTable{}
	if err := ruleTable.UnmarshalVT(decryptedBytes); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal rule table: %w", err)
	}

	hash := sha256.Sum256(nil)

	return ruleTable, hex.EncodeToString(hash[:]), nil
}

func (rtb *RuleTableBundle) ID() string {
	if rtb == nil {
		return bundleapi.BundleIDUnknown
	}
	return rtb.hash
}

func (*RuleTableBundle) Driver() string {
	return DriverName
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

func (*RuleTableBundle) ListPolicyIDs(_ context.Context, _ storage.ListPolicyIDsParams) ([]string, error) {
	// TODO: This can probably be implemented using the data from the rule table.
	return nil, ErrUnsupportedOperation
}

func (rtb *RuleTableBundle) ListSchemaIDs(_ context.Context) ([]string, error) {
	if rtb == nil {
		return nil, ErrBundleNotLoaded
	}

	schemas := rtb.ruleTable.GetJsonSchemas()
	output := slices.Collect(maps.Keys(schemas))

	return output, nil
}

func (rtb *RuleTableBundle) LoadSchema(_ context.Context, path string) (io.ReadCloser, error) {
	if rtb == nil {
		return nil, ErrBundleNotLoaded
	}

	schemaDef, exists := rtb.ruleTable.GetJsonSchemas()[path]
	if exists {
		return io.NopCloser(bytes.NewReader(schemaDef.GetContent())), nil
	}

	return nil, fmt.Errorf("schema %s not found", path)
}

func (rtb *RuleTableBundle) GetRuleTable() (*runtimev1.RuleTable, error) {
	if rtb == nil {
		return nil, ErrBundleNotLoaded
	}

	return rtb.ruleTable, nil
}

func (rtb *RuleTableBundle) Release() error {
	if rtb != nil {
		rtb.ruleTable = nil
		rtb.hash = ""
	}

	return nil
}

func (*RuleTableBundle) Close() error {
	return nil
}
