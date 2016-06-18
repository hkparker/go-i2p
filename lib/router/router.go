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

func CreateRouter() (r *Router, err error) {
	cfg := config.Router
	r = &Router{
		cfg: cfg,
		ndb: netdb.StdNetDB(cfg.NetDbDir),
	}
	return
}

// run i2p router mainloop
func (r *Router) Run() {
	// make sure the netdb is ready
	err := r.ndb.Ensure(r.cfg.Bootstrap.LowPeerThreshold)
	if err == nil {
		// netdb ready
	}
}
