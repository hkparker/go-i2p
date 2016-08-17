package config

// configuration for 1 reseed server
type ReseedConfig struct {
	// url of reseed server
	Url string
	// fingerprint of reseed su3 signing key
	SU3Fingerprint string
}

type BootstrapConfig struct {
	// if we have less than this many peers we should reseed
	LowPeerThreshold int
	// reseed servers
	ReseedServers []*ReseedConfig
}

// default configuration for network bootstrap
var DefaultBootstrapConfig = BootstrapConfig{
	LowPeerThreshold: 10,
	// TODO: add reseed servers
	ReseedServers: []*ReseedConfig{},
}
