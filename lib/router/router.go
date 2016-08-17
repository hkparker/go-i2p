package router

import (
	"github.com/hkparker/go-i2p/lib/config"
	"github.com/hkparker/go-i2p/lib/netdb"
)

// i2p router type
type Router struct {
	cfg *config.RouterConfig
	ndb netdb.StdNetDB
}

// create router with default configuration
func CreateRouter() (r *Router, err error) {
	cfg := config.DefaultRouterConfig
	r, err = FromConfig(cfg)
	return
}

// create router from configuration
func FromConfig(c *config.RouterConfig) (r *Router, err error) {
	r = new(Router)
	r.cfg = c
	return
}

// run i2p router mainloop
func (r *Router) Run() {
	r.ndb = netdb.StdNetDB(r.cfg.NetDb.Path)
	// make sure the netdb is ready
	err := r.ndb.Ensure()
	if err == nil {
		// netdb ready
	}
}
