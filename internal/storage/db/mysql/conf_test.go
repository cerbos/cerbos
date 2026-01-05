// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package mysql

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConf(t *testing.T) {
	testCases := []struct {
		name    string
		conf    *Conf
		want    string
		wantErr bool
	}{
		{
			name: "DSN only",
			conf: &Conf{DSN: "user:password@tcp(localhost:3306)/db?interpolateParams=true"},
			want: "user:password@tcp(localhost:3306)/db?interpolateParams=true",
		},
		{
			name: "With TLS",
			conf: &Conf{
				DSN: "user:password@tcp(localhost:3306)/db?interpolateParams=true&tls=mytls",
				TLS: map[string]TLSConf{
					"mytls": {
						CACert: "testdata/CerbosTestCA.crt",
						Cert:   "testdata/cerbos-mysql-test.crt",
						Key:    "testdata/cerbos-mysql-test.key",
					},
				},
			},
			want: "user:password@tcp(localhost:3306)/db?interpolateParams=true&tls=mytls",
		},
		{
			name: "Missing cert",
			conf: &Conf{
				DSN: "user:password@tcp(localhost:3306)/db?interpolateParams=true&tls=mytls",
				TLS: map[string]TLSConf{
					"mytls": {
						CACert: "testdata/CerbosTestCA.crt",
						Cert:   "testdata/some-cert.crt",
						Key:    "testdata/cerbos-mysql-test.key",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Undefined TLS config",
			conf: &Conf{
				DSN: "user:password@tcp(localhost:3306)/db?interpolateParams=true&tls=sometls",
				TLS: map[string]TLSConf{
					"mytls": {
						CACert: "testdata/CerbosTestCA.crt",
						Cert:   "testdata/cerbos-mysql-test.crt",
						Key:    "testdata/cerbos-mysql-test.key",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "With Server public key",
			conf: &Conf{
				DSN:          "user:password@tcp(localhost:3306)/db?interpolateParams=true&serverPubKey=mykey",
				ServerPubKey: map[string]string{"mykey": "testdata/server_public_key.pem"},
			},
			want: "user:password@tcp(localhost:3306)/db?interpolateParams=true&serverPubKey=mykey",
		},
		{
			name: "Undefined Server public key",
			conf: &Conf{
				DSN:          "user:password@tcp(localhost:3306)/db?interpolateParams=true&serverPubKey=somekey",
				ServerPubKey: map[string]string{"mykey": "testdata/server_public_key.pem"},
			},
			wantErr: true,
		},
		{
			name: "Missing Server public key",
			conf: &Conf{
				DSN:          "user:password@tcp(localhost:3306)/db?interpolateParams=true&serverPubKey=mykey",
				ServerPubKey: map[string]string{"mykey": "testdata/somekey.pem"},
			},
			wantErr: true,
		},
		{
			name: "With TLS and server public key",
			conf: &Conf{
				DSN:          "user:password@tcp(localhost:3306)/db?interpolateParams=true&tls=mytls&serverPubKey=mykey",
				ServerPubKey: map[string]string{"mykey": "testdata/server_public_key.pem"},
				TLS: map[string]TLSConf{
					"mytls": {
						CACert: "testdata/CerbosTestCA.crt",
						Cert:   "testdata/cerbos-mysql-test.crt",
						Key:    "testdata/cerbos-mysql-test.key",
					},
				},
			},
			want: "user:password@tcp(localhost:3306)/db?interpolateParams=true&serverPubKey=mykey&tls=mytls",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			have, err := buildDSN(tc.conf)
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, have)
		})
	}
}
