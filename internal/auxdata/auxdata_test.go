// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auxdata

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	"github.com/cerbos/cerbos/internal/test"
)

func TestExtract(t *testing.T) {
	verifyKey := "verify_key.jwk"
	keysDir := filepath.Join(test.PathToDir(t, "auxdata"), "keys")
	ctx, cancelFn := context.WithCancel(t.Context())
	t.Cleanup(cancelFn)

	auxData := NewFromConf(ctx, &Conf{
		JWT: &JWTConf{
			AcceptableTimeSkew: 1 * time.Minute,
			KeySets: []JWTKeySet{
				{
					ID:    "local_file",
					Local: &LocalSource{File: filepath.Join(keysDir, verifyKey)},
				},
			},
		},
	})

	t.Run("SingleJWT/Success", func(t *testing.T) {
		expiry := time.Now().Add(1 * time.Hour)
		have, err := auxData.Extract(t.Context(), &requestv1.AuxData{Jwt: &requestv1.AuxData_JWT{
			Token: mkSignedToken(t, expiry),
		}})
		require.NoError(t, err)

		want := &enginev1.AuxData{Jwt: mkExpectedTokenData(t, expiry)}
		require.Empty(t, cmp.Diff(want, have, protocmp.Transform()))
	})

	t.Run("SingleJWT/Failure", func(t *testing.T) {
		expiry := time.Now().Add(-1 * time.Hour)
		_, err := auxData.Extract(t.Context(), &requestv1.AuxData{Jwt: &requestv1.AuxData_JWT{
			Token: mkSignedToken(t, expiry),
		}})
		require.ErrorIs(t, err, ErrFailedToExtractJWT)
	})

	t.Run("MultipleJWTs/Success", func(t *testing.T) {
		expiry := time.Now().Add(1 * time.Hour)
		have, err := auxData.Extract(t.Context(), &requestv1.AuxData{
			Jwts: map[string]*requestv1.AuxData_JWT{
				"a": {Token: mkSignedToken(t, expiry)},
				"b": {Token: mkSignedToken(t, expiry)},
				"c": {Token: mkSignedToken(t, expiry)},
				"d": {Token: mkSignedToken(t, expiry)},
				"e": {Token: mkSignedToken(t, expiry)},
			},
		})
		require.NoError(t, err)

		want := &enginev1.AuxData{
			Jwts: map[string]*enginev1.AuxData_JWT{
				"a": {Claims: mkExpectedTokenData(t, expiry)},
				"b": {Claims: mkExpectedTokenData(t, expiry)},
				"c": {Claims: mkExpectedTokenData(t, expiry)},
				"d": {Claims: mkExpectedTokenData(t, expiry)},
				"e": {Claims: mkExpectedTokenData(t, expiry)},
			},
		}
		require.Empty(t, cmp.Diff(want, have, protocmp.Transform()))
	})

	t.Run("MultipleJWTs/Failure", func(t *testing.T) {
		expiry := time.Now().Add(1 * time.Hour)
		_, err := auxData.Extract(t.Context(), &requestv1.AuxData{
			Jwts: map[string]*requestv1.AuxData_JWT{
				"a": {Token: mkSignedToken(t, expiry)},
				"b": {Token: mkSignedToken(t, expiry)},
				"c": {Token: mkSignedToken(t, time.Now().Add(-1*time.Hour))},
				"d": {Token: mkSignedToken(t, expiry)},
				"e": {Token: mkSignedToken(t, expiry)},
			},
		})
		require.ErrorIs(t, err, ErrFailedToExtractJWT)
	})
}
