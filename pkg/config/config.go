package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"

	"github.com/charithe/menshen/pkg/util"
)

var conf Config

// Config holds all configuration values.
type Config struct {
	LogLevel string
	Server   ServerConf
	Storage  StorageConf
}

type ServerConf struct {
	ListenAddr string
	TLS        TLSConf
}

type TLSConf struct {
	Static *TLSStaticConf
}

type TLSStaticConf struct {
	TLSCert string
	TLSKey  string
}

type StorageConf struct {
	Driver string
	Disk   *DiskStorageConf
}

type DiskStorageConf struct {
	Directory string
	ReadOnly  bool
}

// Init loads the config file at the given path.
func Init(confFile string) error {
	v := viper.New()
	v.SetConfigFile(confFile)
	v.SetEnvPrefix(strings.ToUpper(util.AppName) + "_")

	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	if err := v.UnmarshalExact(&conf); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return nil
}

// Get returns the current config.
func Get() Config {
	return conf
}
