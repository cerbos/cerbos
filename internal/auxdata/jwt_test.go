// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auxdata

import (
	"bytes"
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
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestKeySet(t *testing.T) {
	t.Parallel()

	testCases := test.LoadTestCases(t, "auxdata")
	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			tc := readTestCase(t, testCase)
			keysDir := t.TempDir()

			if tc.GetWantErr() != "" && (tc.GetWantLocalErr() != "" || tc.GetWantRemoteErr() != "") {
				t.Fatalf("specify wantError or wantLocalErr/wantRemoteErr, not both")
			}

			fileName := filepath.Base(t.Name())
			path := filepath.Join(keysDir, fileName)
			require.NoError(t, os.WriteFile(path, []byte(tc.GetInput().GetKey()), 0o600))

			ts := httptest.NewServer(http.FileServer(http.Dir(keysDir)))
			t.Cleanup(ts.Close)

			t.Run("local", func(t *testing.T) {
				t.Parallel()

				t.Run("data", func(t *testing.T) {
					t.Parallel()

					lks := newLocalKeySet(&LocalSource{
						Data: base64.StdEncoding.EncodeToString([]byte(tc.GetInput().GetKey())),
						PEM:  tc.GetInput().GetPem(),
					}, nil, nil)

					ks, opts, err := lks.keySet(t.Context())
					switch {
					case tc.GetWantErr() != "":
						require.ErrorContains(t, err, tc.GetWantErr())
						return
					case tc.GetWantLocalErr() != "":
						require.ErrorContains(t, err, tc.GetWantLocalErr())
						return
					}

					require.NoError(t, err)
					require.NotNil(t, ks)
					require.True(t, ks.Len() > 0)
					require.Nil(t, opts)
				})

				t.Run("file", func(t *testing.T) {
					t.Parallel()

					lks := newLocalKeySet(&LocalSource{
						File: path,
						PEM:  tc.GetInput().GetPem(),
					}, nil, nil)

					ks, opts, err := lks.keySet(t.Context())
					switch {
					case tc.GetWantErr() != "":
						require.ErrorContains(t, err, tc.GetWantErr())
						return
					case tc.GetWantLocalErr() != "":
						require.ErrorContains(t, err, tc.GetWantLocalErr())
						return
					}

					require.NoError(t, err)
					require.NotNil(t, ks)
					require.True(t, ks.Len() > 0)
					require.Nil(t, opts)
				})
			})

			if !tc.Input.Pem {
				t.Run("remote", func(t *testing.T) {
					t.Parallel()

					ctx, cancelFn := context.WithTimeout(t.Context(), 1*time.Second)
					defer cancelFn()

					cache, err := jwk.NewCache(ctx, httprc.NewClient())
					require.NoError(t, err, "failed to create JWK cache")

					rks := newRemoteKeySet(ctx, cache, &RemoteSource{
						URL: fmt.Sprintf("%s/%s", ts.URL, fileName),
					}, nil, nil)

					ks, opts, err := rks.keySet(ctx)
					switch {
					case tc.GetWantErr() != "":
						require.ErrorContains(t, err, tc.GetWantErr())
						return
					case tc.GetWantRemoteErr() != "":
						require.ErrorContains(t, err, tc.GetWantRemoteErr())
						return
					}

					require.NoError(t, err)
					require.NotNil(t, ks)
					require.True(t, ks.Len() > 0)
					require.Len(t, opts, 0)
				})
			}
		})
	}
}

func readTestCase(t *testing.T, testCase test.Case) *privatev1.AuxDataTestCase {
	t.Helper()

	tc := &privatev1.AuxDataTestCase{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(testCase.Input), tc))

	return tc
}

func TestExtract_MultipleKeySets(t *testing.T) {
	verifyKey := "verify_key.jwk"
	keysDir := filepath.Join(test.PathToDir(t, "auxdata"), "keys")

	ts := httptest.NewServer(http.FileServer(http.Dir(keysDir)))
	t.Cleanup(ts.Close)

	keyBytes, err := os.ReadFile(filepath.Join(keysDir, verifyKey))
	require.NoError(t, err)

	conf := &JWTConf{
		AcceptableTimeSkew: 1 * time.Minute,
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
			{
				ID:     "remote_insecure",
				Remote: &RemoteSource{URL: fmt.Sprintf("%s/%s", ts.URL, verifyKey)},
				Insecure: InsecureKeySetOpt{
					OptionalAlg: true,
					OptionalKid: true,
				},
			},
			{
				ID:    "local_file_insecure",
				Local: &LocalSource{File: filepath.Join(keysDir, verifyKey)},
				Insecure: InsecureKeySetOpt{
					OptionalAlg: true,
					OptionalKid: true,
				},
			},
			{
				ID:    "local_data_insecure",
				Local: &LocalSource{Data: base64.StdEncoding.EncodeToString(keyBytes)},
				Insecure: InsecureKeySetOpt{
					OptionalAlg: true,
					OptionalKid: true,
				},
			},
		},
	}

	ctx, cancelFn := context.WithCancel(t.Context())
	t.Cleanup(cancelFn)

	jh := newJWTHelper(ctx, conf)

	testCases := []struct {
		name   string
		expiry time.Time
		valid  bool
	}{
		{
			name:   "Valid",
			expiry: time.Now().Add(1 * time.Hour),
			valid:  true,
		},
		{
			name:   "ValidWithinSkew",
			expiry: time.Now().Add(-2 * time.Second),
			valid:  true,
		},
		{
			name:   "ExpiredJustBeyondSkew",
			expiry: time.Now().Add(-61 * time.Second),
			valid:  false,
		},
		{
			name:   "Expired",
			expiry: time.Now().Add(-1 * time.Hour),
			valid:  false,
		},
	}

	for _, tc := range testCases {
		for _, keySetID := range []string{"remote", "local_file", "local_data", "remote_insecure", "local_file_insecure", "local_data_insecure"} {
			ksID := keySetID
			t.Run(fmt.Sprintf("%s/%s", tc.name, ksID), func(t *testing.T) {
				input := &requestv1.AuxData_JWT{
					Token:    mkSignedToken(t, tc.expiry),
					KeySetId: ksID,
				}

				have, err := jh.extract(t.Context(), input)
				if !tc.valid {
					require.Error(t, err)
					return
				}

				want := mkExpectedTokenData(t, tc.expiry)
				require.NoError(t, err)
				require.NotNil(t, have)
				require.Empty(t, cmp.Diff(want, have, protocmp.Transform()))
			})
		}
	}

	t.Run("no_token", func(t *testing.T) {
		input := &requestv1.AuxData_JWT{}

		have, err := jh.extract(t.Context(), input)
		require.NoError(t, err)
		require.Empty(t, have)
	})

	t.Run("no_keyset_id", func(t *testing.T) {
		input := &requestv1.AuxData_JWT{
			Token: mkSignedToken(t, time.Now().Add(1*time.Hour)),
		}

		_, err := jh.extract(t.Context(), input)
		require.Error(t, err)
	})

	t.Run("unknown_keyset_id", func(t *testing.T) {
		input := &requestv1.AuxData_JWT{
			Token:    mkSignedToken(t, time.Now().Add(1*time.Hour)),
			KeySetId: "blah",
		}

		_, err := jh.extract(t.Context(), input)
		require.Error(t, err)
	})
}

func TestExtract_SingleKeySet(t *testing.T) {
	verifyKey := "verify_key.jwk"
	keysDir := filepath.Join(test.PathToDir(t, "auxdata"), "keys")

	conf := &JWTConf{
		AcceptableTimeSkew: 1 * time.Minute,
		KeySets: []JWTKeySet{
			{
				ID:    "local_file",
				Local: &LocalSource{File: filepath.Join(keysDir, verifyKey)},
			},
		},
	}

	ctx, cancelFn := context.WithCancel(t.Context())
	t.Cleanup(cancelFn)

	jh := newJWTHelper(ctx, conf)

	testCases := []struct {
		name   string
		valid  bool
		expiry time.Time
	}{
		{
			name:   "Valid",
			expiry: time.Now().Add(1 * time.Hour),
			valid:  true,
		},
		{
			name:   "ValidWithinSkew",
			expiry: time.Now().Add(-2 * time.Second),
			valid:  true,
		},
		{
			name:   "Expired",
			expiry: time.Now().Add(-1 * time.Hour),
			valid:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			want := mkExpectedTokenData(t, tc.expiry)
			input := &requestv1.AuxData_JWT{
				Token: mkSignedToken(t, tc.expiry),
			}

			have, err := jh.extract(t.Context(), input)
			if !tc.valid {
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
	ctx, cancelFn := context.WithCancel(t.Context())
	t.Cleanup(cancelFn)

	jh := newJWTHelper(ctx, nil)

	testCases := []struct {
		name   string
		expiry time.Time
		valid  bool
	}{
		{
			name:   "Valid",
			expiry: time.Now().Add(1 * time.Hour),
			valid:  true,
		},
		{
			name:   "Expired",
			expiry: time.Now().Add(-1 * time.Hour),
			valid:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := &requestv1.AuxData_JWT{
				Token: mkSignedToken(t, tc.expiry),
			}

			_, err := jh.extract(t.Context(), input)
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
	require.NoError(t, token.Set("customMap", map[string]any{"A": "AA", "B": "BB", "C": "CC"}))

	keyData, err := os.ReadFile(filepath.Join(test.PathToDir(t, "auxdata"), "keys", "signing_key.jwk"))
	require.NoError(t, err)

	keySet, err := jwk.ParseKey(keyData)
	require.NoError(t, err)

	tokenBytes, err := jwt.Sign(token, jwt.WithKey(jwa.ES384(), keySet))
	require.NoError(t, err)

	return string(tokenBytes)
}

func mkExpectedTokenData(t *testing.T, expiry time.Time) map[string]*structpb.Value {
	t.Helper()

	wantAud, err := structpb.NewList([]any{"cerbos-jwt-tests"})
	require.NoError(t, err)

	wantArray, err := structpb.NewList([]any{"A", "B", "C"})
	require.NoError(t, err)

	wantMap, err := structpb.NewStruct(map[string]any{"A": "AA", "B": "BB", "C": "CC"})
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
