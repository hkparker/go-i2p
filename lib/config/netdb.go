package config

import (
	"path/filepath"
)

// local network database configuration
type NetDbConfig struct {
	// path to network database directory
	Path string
}

// default settings for netdb
var DefaultNetDbConfig = NetDbConfig{
	Path: filepath.Join(".", "netDb"),
}
