package disk

const DriverName = "disk"

// Conf holds the configuration for disk storage driver.
type Conf struct {
	// Directory is the path on disk where policies are stored.
	Directory string `yaml:"directory"`
	// ReadOnly defines that the server cannot write or update policies on disk.
	ReadOnly bool `yaml:"readOnly"`
}
