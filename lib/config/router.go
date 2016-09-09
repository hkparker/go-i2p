package config

// router.config options
type RouterConfig struct {
	// netdb configuration
	NetDb *NetDbConfig
	// configuration for bootstrapping into the network
	Bootstrap *BootstrapConfig
}

// defaults for router
var DefaultRouterConfig = &RouterConfig{
	NetDb:     &DefaultNetDbConfig,
	Bootstrap: &DefaultBootstrapConfig,
}
