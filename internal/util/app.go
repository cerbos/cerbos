// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package util

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec
	"crypto/sha256"
	"fmt"
	"os"
	"sync"

	pdpv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/pdp/v1"
	"github.com/google/uuid"
	"github.com/keygen-sh/machineid"
	"go.uber.org/zap"
)

func DeprecationWarning(deprecated string) {
	zap.S().Warnf("[DEPRECATED CONFIG] %s is deprecated and will be removed in a future release.", deprecated)
}

func DeprecationReplacedWarning(deprecated, replacement string) {
	zap.S().Warnf("[DEPRECATED CONFIG] %s is deprecated and will be removed in a future release. Please use %s instead.", deprecated, replacement)
}

var getPdpID = sync.OnceValue(func() string {
	machineID, err := machineid.ID()
	if err != nil || machineID == "" {
		//nolint:gosec
		uuidNodeID := md5.Sum(uuid.NodeID())
		return fmt.Sprintf("%X-%d", uuidNodeID, os.Getpid())
	}

	mac := hmac.New(sha256.New, []byte(machineID))
	mac.Write(appID)
	safeID := mac.Sum(nil)
	if len(safeID) > nodeIDLen {
		safeID = safeID[:nodeIDLen]
	}

	return fmt.Sprintf("%X-%d", safeID, os.Getpid())
})

func PDPIdentifier(pdpID string) *pdpv1.Identifier {
	if pdpID == "" {
		pdpID = getPdpID()
	}

	return &pdpv1.Identifier{
		Instance: pdpID,
		Version:  AppShortVersion(),
	}
}
