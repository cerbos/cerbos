package server

import "github.com/charithe/menshen/pkg/config"

const (
	confKey = "server"
)

// Conf holds configuration pertaining to the server.
type Conf struct {
	// ListenAddr is the address the server should listen on. Defaults to :9999.
	ListenAddr string `yaml:"listenAddr"`
	// TLS defines the TLS configuration for the server.
	TLS *TLSConf `yaml:"tls"`
}

// TLSConf holds TLS configuration.
type TLSConf struct {
	// Static defines statically defined TLS settings.
	Static *TLSStaticConf `yaml:"static"`
}

// TLSStaticConf holds static TLS configuration values.
type TLSStaticConf struct {
	// Cert is the path to the TLS certificate file.
	Cert string `yaml:"cert"`
	// Key is the path to the TLS private key file.
	Key string `yaml:"key"`
}

func getServerConf(listenAddrFlag string) (Conf, error) {
	conf := Conf{}

	if err := config.Get(confKey, &conf); err != nil {
		return conf, err
	}

	// override the listenAddr if the flag is defined.
	if listenAddrFlag != "" {
		conf.ListenAddr = listenAddrFlag
	}

	return conf, nil
}
