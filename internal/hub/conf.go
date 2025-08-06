// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"os"
	"time"

	"github.com/cerbos/cloud-api/credentials"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/util"
)

type EnvVarKey int

const (
	BundleLabelKey EnvVarKey = iota
	ClientIDKey
	ClientSecretKey
	OfflineKey
	PDPIDKey
	WorkspaceSecretKey
	BundleVersionKey
	DeploymentIDKey
	PlaygroundIDKey
)

var envVars = map[EnvVarKey][]string{
	BundleLabelKey:     {"CERBOS_HUB_BUNDLE", "CERBOS_CLOUD_BUNDLE"},
	ClientIDKey:        {"CERBOS_HUB_CLIENT_ID", "CERBOS_CLOUD_CLIENT_ID"},
	ClientSecretKey:    {"CERBOS_HUB_CLIENT_SECRET", "CERBOS_CLOUD_CLIENT_SECRET"},
	OfflineKey:         {"CERBOS_HUB_OFFLINE", "CERBOS_CLOUD_OFFLINE"},
	PDPIDKey:           {"CERBOS_HUB_PDP_ID", "CERBOS_PDP_ID"},
	WorkspaceSecretKey: {"CERBOS_HUB_WORKSPACE_SECRET", "CERBOS_CLOUD_SECRET_KEY"},
	BundleVersionKey:   {"CERBOS_HUB_BUNDLE_VERSION"},
	DeploymentIDKey:    {"CERBOS_HUB_DEPLOYMENT_ID"},
	PlaygroundIDKey:    {"CERBOS_HUB_PLAYGROUND_ID"},
}

func GetEnv(key EnvVarKey) string {
	varNames, ok := envVars[key]
	if !ok {
		return ""
	}

	for i, v := range varNames {
		val, ok := os.LookupEnv(v)
		if ok {
			if i > 0 {
				util.DeprecationReplacedWarning(v, varNames[0])
			}
			return val
		}
	}

	return ""
}

const (
	confKey                  = "hub"
	defaultAPIEndpoint       = "https://api.cerbos.cloud"
	defaultBootstrapHost     = "https://cdn.cerbos.cloud"
	defaultHeartbeatInterval = 180 * time.Second
	defaultMaxRetryWait      = 120 * time.Second
	defaultMinRetryWait      = 1 * time.Second
	defaultNumRetries        = 5
	minHeartbeatInterval     = 30 * time.Second
)

type Conf struct {
	// Credentials holds Cerbos Hub client credentials.
	Credentials CredentialsConf `yaml:"credentials"`
	// Connection holds advanced connection settings for Cerbos Hub.
	Connection ConnectionConf `yaml:"connection" conf:",ignore"`
}

func (conf *Conf) Key() string {
	return confKey
}

func (conf *Conf) SetDefaults() {
	conf.Credentials = CredentialsConf{
		ClientID:        GetEnv(ClientIDKey),
		ClientSecret:    GetEnv(ClientSecretKey),
		PDPID:           GetEnv(PDPIDKey),
		WorkspaceSecret: GetEnv(WorkspaceSecretKey),
	}
}

func (conf *Conf) Validate() (outErr error) {
	_ = conf.Connection.Validate()
	return conf.Credentials.Validate()
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

func (cc *CredentialsConf) Validate() (outErr error) {
	// SecretKey was renamed to WorkspaceSecret in Cerbos 0.31.0
	if cc.WorkspaceSecret == "" && cc.SecretKey != "" {
		util.DeprecationReplacedWarning("credentials.secretKey", "credentials.workspaceSecret")
		cc.WorkspaceSecret = cc.SecretKey
	}

	// InstanceID was renamed to PDPID in Cerbos 0.31.0
	if cc.PDPID == "" && cc.InstanceID != "" {
		util.DeprecationReplacedWarning("credentials.instanceID", "credentials.pdpID")
		cc.PDPID = cc.InstanceID
	}

	// We don't do any validation here because some fields are optional depending on the use case.

	return nil
}

func (cc *CredentialsConf) LoadFromEnv() {
	if cc.ClientID == "" {
		cc.ClientID = GetEnv(ClientIDKey)
	}

	if cc.ClientSecret == "" {
		cc.ClientSecret = GetEnv(ClientSecretKey)
	}

	if cc.PDPID == "" {
		cc.PDPID = GetEnv(PDPIDKey)
	}

	if cc.WorkspaceSecret == "" {
		cc.WorkspaceSecret = GetEnv(WorkspaceSecretKey)
	}
}

func (cc CredentialsConf) ToCredentials() (*credentials.Credentials, error) {
	return credentials.New(cc.ClientID, cc.ClientSecret, cc.WorkspaceSecret)
}

// ConnectionConf holds configuration for the remote connection.
type ConnectionConf struct {
	// TLS defines settings for TLS connections.
	TLS TLSConf `yaml:"tls"`
	// APIEndpoint is the address of the API server.
	APIEndpoint string `yaml:"apiEndpoint" conf:"required,example=https://api.cerbos.cloud"`
	// BootstrapEndpoint is the addresses of the server serving the bootstrap configuration.
	BootstrapEndpoint string `yaml:"bootstrapEndpoint" conf:"required,example=https://cdn.cerbos.cloud"`
	// MinRetryWait is the minimum amount of time to wait between retries.
	MinRetryWait time.Duration `yaml:"minRetryWait" conf:",example=1s"`
	// MaxRetryWait is the maximum amount of time to wait between retries.
	MaxRetryWait time.Duration `yaml:"maxRetryWait" conf:",example=120s"`
	// NumRetries is the number of times to retry before giving up.
	NumRetries uint `yaml:"numRetries" conf:",example=5"`
	// HeartbeatInterval is the interval for sending regular heartbeats.
	HeartbeatInterval time.Duration `yaml:"heartbeatInterval" conf:",example=2m"`
}

func (cc ConnectionConf) IsUnset() bool {
	return cc == ConnectionConf{}
}

func (cc *ConnectionConf) Validate() error {
	if cc.APIEndpoint == "" {
		cc.APIEndpoint = defaultAPIEndpoint
	}

	if cc.BootstrapEndpoint == "" {
		cc.BootstrapEndpoint = defaultBootstrapHost
	}

	if cc.MinRetryWait == 0 {
		cc.MinRetryWait = defaultMinRetryWait
	}

	if cc.MaxRetryWait == 0 {
		cc.MaxRetryWait = defaultMaxRetryWait
	}

	if cc.NumRetries == 0 {
		cc.NumRetries = defaultNumRetries
	}

	switch {
	case cc.HeartbeatInterval < 0:
		cc.HeartbeatInterval = 0
	case cc.HeartbeatInterval == 0:
		cc.HeartbeatInterval = defaultHeartbeatInterval
	case cc.HeartbeatInterval > 0 && cc.HeartbeatInterval < minHeartbeatInterval:
		cc.HeartbeatInterval = minHeartbeatInterval
	}

	return nil
}

// TLSConf holds TLS configuration for the remote connection.
type TLSConf struct {
	// Authority overrides the Cerbos Hub server authority if it is different from what is provided in the API and bootstrap endpoints.
	Authority string `yaml:"authority" conf:",example=domain.tld"`
	// CACert is the path to the CA certificate chain to use for certificate verification.
	CACert string `yaml:"caCert" conf:",example=/path/to/CA_certificate"`
}

func GetConf() (*Conf, error) {
	conf := &Conf{}
	err := config.GetSection(conf)

	return conf, err
}
