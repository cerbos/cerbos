// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auxdata

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	"github.com/cerbos/cerbos/internal/test"
)

func TestKeySet(t *testing.T) {
	t.Parallel()

	keysDir := test.PathToDir(t, filepath.Join("auxdata", "keys"))
	keys := findKeys(t, keysDir)

	ts := httptest.NewServer(http.FileServer(http.Dir(keysDir)))
	t.Cleanup(ts.Close)

	for _, k := range keys {
		k := k
		isPEM := filepath.Ext(k) == ".pem"

		t.Run(fmt.Sprintf("local/file/%s", filepath.Base(k)), func(t *testing.T) {
			t.Parallel()
			conf := &LocalSource{
				File: k,
				PEM:  isPEM,
			}

			lks := newLocalKeySet(conf)
			ks, err := lks.keySet(context.Background())
			require.NoError(t, err)
			require.NotNil(t, ks)
			require.True(t, ks.Len() > 0)
		})

		t.Run(fmt.Sprintf("local/data/%s", filepath.Base(k)), func(t *testing.T) {
			t.Parallel()
			contents, err := os.ReadFile(k)
			require.NoError(t, err, "Failed to read file %s", k)

			conf := &LocalSource{
				Data: base64.StdEncoding.EncodeToString(contents),
				PEM:  isPEM,
			}

			lks := newLocalKeySet(conf)
			ks, err := lks.keySet(context.Background())
			require.NoError(t, err)
			require.NotNil(t, ks)
			require.True(t, ks.Len() > 0)
		})

		if !isPEM {
			t.Run(fmt.Sprintf("remote/%s", filepath.Base(k)), func(t *testing.T) {
				t.Parallel()
				conf := &RemoteSource{
					URL: fmt.Sprintf("%s/%s", ts.URL, filepath.Base(k)),
				}

				ctx, cancelFn := context.WithTimeout(context.Background(), 1*time.Second)
				defer cancelFn()

				rks := newRemoteKeySet(jwk.NewAutoRefresh(ctx), conf)
				ks, err := rks.keySet(ctx)

				require.NoError(t, err)
				require.NotNil(t, ks)
				require.True(t, ks.Len() > 0)
			})
		}
	}
}

func findKeys(t *testing.T, keysDir string) []string {
	t.Helper()

	entries, err := os.ReadDir(keysDir)
	require.NoError(t, err)

	keys := make([]string, len(entries))
	for i, entry := range entries {
		keys[i] = filepath.Join(keysDir, entry.Name())
	}

	return keys
}

func TestExtract_MultipleKeySets(t *testing.T) {
	verifyKey := "verify_key.jwk"
	keysDir := test.PathToDir(t, "auxdata")

	ts := httptest.NewServer(http.FileServer(http.Dir(keysDir)))
	t.Cleanup(ts.Close)

	keyBytes, err := os.ReadFile(filepath.Join(keysDir, verifyKey))
	require.NoError(t, err)

	conf := &JWTConf{
		KeySets: []JWTKeySet{
			{
				ID:     "remote",
				Remote: &RemoteSource{URL: fmt.Sprintf("%s/%s", ts.URL, verifyKey)},
			},
			{
				ID:    "local_file",
				Local: &LocalSource{File: filepath.Join(keysDir, verifyKey)},
			},
			{
				ID:    "local_data",
				Local: &LocalSource{Data: base64.StdEncoding.EncodeToString(keyBytes)},
			},
		},
	}

	ctx, cancelFn := context.WithCancel(context.Background())
	t.Cleanup(cancelFn)

	jh := newJWTHelper(ctx, conf)
	expiry := time.Now().Add(1 * time.Hour)

	tokens := []struct {
		token string
		valid bool
	}{
		{
			token: mkSignedToken(t, expiry),
			valid: true,
		},
		{
			token: mkSignedToken(t, time.Now().Add(-1*time.Hour)),
			valid: false,
		},
	}

	want := mkExpectedTokenData(t, expiry)

	for _, token := range tokens {
		tok := token
		for _, keySetID := range []string{"remote", "local_file", "local_data"} {
			ksID := keySetID
			validOrInvalid := "invalid"
			if tok.valid {
				validOrInvalid = "valid"
			}

			t.Run(fmt.Sprintf("%s/%s", validOrInvalid, ksID), func(t *testing.T) {
				input := &requestv1.AuxData_JWT{
					Token:    tok.token,
					KeySetId: ksID,
				}

				have, err := jh.extract(context.Background(), input)
				if !token.valid {
					require.Error(t, err)
					return
				}

				require.NoError(t, err)
				require.NotNil(t, have)
				require.Empty(t, cmp.Diff(want, have, protocmp.Transform()))
			})
		}
	}

	t.Run("no_token", func(t *testing.T) {
		input := &requestv1.AuxData_JWT{}

		have, err := jh.extract(context.Background(), input)
		require.NoError(t, err)
		require.Empty(t, have)
	})

	t.Run("no_keyset_id", func(t *testing.T) {
		input := &requestv1.AuxData_JWT{
			Token: mkSignedToken(t, time.Now().Add(1*time.Hour)),
		}

		_, err := jh.extract(context.Background(), input)
		require.Error(t, err)
	})

	t.Run("unknown_keyset_id", func(t *testing.T) {
		input := &requestv1.AuxData_JWT{
			Token:    mkSignedToken(t, time.Now().Add(1*time.Hour)),
			KeySetId: "blah",
		}

		_, err := jh.extract(context.Background(), input)
		require.Error(t, err)
	})
}

func TestExtract_SingleKeySet(t *testing.T) {
	verifyKey := "verify_key.jwk"
	keysDir := test.PathToDir(t, "auxdata")

	conf := &JWTConf{
		KeySets: []JWTKeySet{
			{
				ID:    "local_file",
				Local: &LocalSource{File: filepath.Join(keysDir, verifyKey)},
			},
		},
	}

	ctx, cancelFn := context.WithCancel(context.Background())
	t.Cleanup(cancelFn)

	jh := newJWTHelper(ctx, conf)
	expiry := time.Now().Add(1 * time.Hour)

	tokens := []struct {
		token string
		valid bool
	}{
		{
			token: mkSignedToken(t, expiry),
			valid: true,
		},
		{
			token: mkSignedToken(t, time.Now().Add(-1*time.Hour)),
			valid: false,
		},
	}

	want := mkExpectedTokenData(t, expiry)

	for _, token := range tokens {
		tok := token
		validOrInvalid := "invalid"
		if tok.valid {
			validOrInvalid = "valid"
		}

		t.Run(validOrInvalid, func(t *testing.T) {
			input := &requestv1.AuxData_JWT{
				Token: tok.token,
			}

			have, err := jh.extract(context.Background(), input)
			if !token.valid {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, have)
			require.Empty(t, cmp.Diff(want, have, protocmp.Transform()))
		})
	}
}

func TestExtract_NoKeySets(t *testing.T) {
	ctx, cancelFn := context.WithCancel(context.Background())
	t.Cleanup(cancelFn)

	jh := newJWTHelper(ctx, nil)

	tokens := []struct {
		token string
		valid bool
	}{
		{
			token: mkSignedToken(t, time.Now().Add(1*time.Hour)),
			valid: true,
		},
		{
			token: mkSignedToken(t, time.Now().Add(-1*time.Hour)),
			valid: false,
		},
	}

	for _, token := range tokens {
		tok := token
		validOrInvalid := "invalid"
		if tok.valid {
			validOrInvalid = "valid"
		}

		t.Run(validOrInvalid, func(t *testing.T) {
			input := &requestv1.AuxData_JWT{
				Token: tok.token,
			}

			_, err := jh.extract(context.Background(), input)
			require.Error(t, err)
		})
	}
}

func mkSignedToken(t *testing.T, expiry time.Time) string {
	t.Helper()

	token := jwt.New()
	require.NoError(t, token.Set(jwt.IssuerKey, "cerbos-test-suite"))
	require.NoError(t, token.Set(jwt.AudienceKey, "cerbos-jwt-tests"))
	require.NoError(t, token.Set(jwt.ExpirationKey, expiry))
	require.NoError(t, token.Set("customString", "foobar"))
	require.NoError(t, token.Set("customInt", 42))
	require.NoError(t, token.Set("customArray", []string{"A", "B", "C"}))
	require.NoError(t, token.Set("customMap", map[string]interface{}{"A": "AA", "B": "BB", "C": "CC"}))

	keyData, err := os.ReadFile(filepath.Join(test.PathToDir(t, "auxdata"), "signing_key.jwk"))
	require.NoError(t, err)

	keySet, err := jwk.ParseKey(keyData)
	require.NoError(t, err)

	tokenBytes, err := jwt.Sign(token, jwa.ES384, keySet)
	require.NoError(t, err)

	return string(tokenBytes)
}

func mkExpectedTokenData(t *testing.T, expiry time.Time) map[string]*structpb.Value {
	t.Helper()

	wantAud, err := structpb.NewList([]interface{}{"cerbos-jwt-tests"})
	require.NoError(t, err)

	wantArray, err := structpb.NewList([]interface{}{"A", "B", "C"})
	require.NoError(t, err)

	wantMap, err := structpb.NewStruct(map[string]interface{}{"A": "AA", "B": "BB", "C": "CC"})
	require.NoError(t, err)

	return map[string]*structpb.Value{
		"iss":          structpb.NewStringValue("cerbos-test-suite"),
		"aud":          structpb.NewListValue(wantAud),
		"exp":          structpb.NewStringValue(expiry.UTC().Format(time.RFC3339)),
		"customString": structpb.NewStringValue("foobar"),
		"customInt":    structpb.NewNumberValue(42),
		"customArray":  structpb.NewListValue(wantArray),
		"customMap":    structpb.NewStructValue(wantMap),
	}
}

func TestLongLivedToken(t *testing.T) {
	// generate a long-lived token for tests
	t.Log(mkSignedToken(t, time.Now().Add((10*365*24)*time.Hour)))
}
