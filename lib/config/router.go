package config

// router.config options
type RouterConfig struct {
	NetDbDir string

	Bootstrap BootstrapConfig
}

// defaults for router
var Router = &RouterConfig{
	NetDbDir: "./netDb",
}
