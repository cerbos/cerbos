// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"os"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cloud-api/credentials"
)

type EnvVarKey int

const (
	BundleLabelKey EnvVarKey = iota
	ClientIDKey
	ClientSecretKey
	OfflineKey
	PDPIDKey
	WorkspaceSecretKey
)

var envVars = map[EnvVarKey][]string{
	BundleLabelKey:     {"CERBOS_HUB_BUNDLE", "CERBOS_CLOUD_BUNDLE"},
	ClientIDKey:        {"CERBOS_HUB_CLIENT_ID", "CERBOS_CLOUD_CLIENT_ID"},
	ClientSecretKey:    {"CERBOS_HUB_CLIENT_SECRET", "CERBOS_CLOUD_CLIENT_SECRET"},
	OfflineKey:         {"CERBOS_HUB_OFFLINE", "CERBOS_CLOUD_OFFLINE"},
	PDPIDKey:           {"CERBOS_HUB_PDP_ID", "CERBOS_PDP_ID"},
	WorkspaceSecretKey: {"CERBOS_HUB_WORKSPACE_SECRET", "CERBOS_CLOUD_SECRET_KEY"},
}

func GetEnv(key EnvVarKey) string {
	varNames, ok := envVars[key]
	if !ok {
		return ""
	}

	for _, v := range varNames {
		val, ok := os.LookupEnv(v)
		if ok {
			return val
		}
	}

	return ""
}

const (
	confKey = "hub"

	DefaultAPIEndpoint   = "https://api.cerbos.cloud"
	DefaultBootstrapHost = "https://cdn.cerbos.cloud"
)

type Conf struct {
	// Credentials holds Cerbos Hub client credentials.
	Credentials CredentialsConf `yaml:"credentials"`
}

func (conf *Conf) Key() string {
	return confKey
}

// CredentialsConf holds credentials for accessing Cerbos Hub.
type CredentialsConf struct {
	// PDPID is the unique identifier for this Cerbos instance. Defaults to the value of the CERBOS_HUB_PDP_ID environment variable.
	PDPID string `yaml:"pdpID" conf:",example=crb-004"`
	// ClientID of the Cerbos Hub credential. Defaults to the value of the CERBOS_HUB_CLIENT_ID environment variable.
	ClientID string `yaml:"clientID" conf:",example=92B0K05B6HOF"`
	// ClientSecret of the Cerbos Hub credential. Defaults to the value of the CERBOS_HUB_CLIENT_SECRET environment variable.
	ClientSecret string `yaml:"clientSecret" conf:",example=${CERBOS_HUB_CLIENT_SECRET}"`
	// WorkspaceSecret used to decrypt the bundles. Defaults to the value of the CERBOS_HUB_WORKSPACE_SECRET environment variable.
	WorkspaceSecret string `yaml:"workspaceSecret" conf:",example=${CERBOS_HUB_WORKSPACE_SECRET}"`
	// Deprecated: Use PDPID
	InstanceID string `yaml:"instanceID" conf:",ignore"`
	// Deprecated: Use WorkspaceSecret
	SecretKey string `yaml:"secretKey" conf:",ignore"`
}

func (cc CredentialsConf) IsUnset() bool {
	return cc == CredentialsConf{}
}

func (cc *CredentialsConf) Validate() (outErr error) {
	// SecretKey was renamed to WorkspaceSecret in Cerbos 0.31.0
	if cc.WorkspaceSecret == "" && cc.SecretKey != "" {
		cc.WorkspaceSecret = cc.SecretKey
	}

	// InstanceID was renamed to PDPID in Cerbos 0.31.0
	if cc.PDPID == "" && cc.InstanceID != "" {
		cc.PDPID = cc.InstanceID
	}

	// We don't do any validation here because some fields are optional depending on the use case.

	return nil
}

func (cc CredentialsConf) ToCredentials() (*credentials.Credentials, error) {
	return credentials.New(cc.ClientID, cc.ClientSecret, cc.WorkspaceSecret)
}

func (conf *Conf) SetDefaults() {
	conf.Credentials = CredentialsConf{
		ClientID:        GetEnv(ClientIDKey),
		ClientSecret:    GetEnv(ClientSecretKey),
		PDPID:           GetEnv(PDPIDKey),
		WorkspaceSecret: GetEnv(WorkspaceSecretKey),
	}
}

func (conf *Conf) Validate() error {
	return conf.Credentials.Validate()
}

func GetConf() (*Conf, error) {
	conf := &Conf{}
	err := config.GetSection(conf)

	return conf, err
}
