package storage

import (
	"github.com/charithe/menshen/pkg/config"
	"github.com/charithe/menshen/pkg/storage/disk"
	"github.com/charithe/menshen/pkg/storage/git"
)

const confKey = "storage"

// Conf holds storage configuration.
type Conf struct {
	// Driver is the storage driver to use.
	Driver string `yaml:"driver"`
	// Disk defines the	configuration for disk storage.
	Disk *disk.Conf `yaml:"disk,omitempty"`
	// Git defines the configuration for git storage.
	Git *git.Conf `yaml:"git,omitempty"`
}

func getStorageConf() (Conf, error) {
	conf := Conf{}

	err := config.Get(confKey, &conf)

	return conf, err
}
