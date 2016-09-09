package netdb

import (
	"github.com/hkparker/go-i2p/lib/common"
	"github.com/hkparker/go-i2p/lib/tunnel"
	"time"
)

// resolves router infos with recursive kademlia lookup
type kadResolver struct {
	// netdb to store result into
	netDB NetworkDatabase
	// what tunnel pool to use when doing lookup
	// if nil the lookup will be done directly
	pool *tunnel.Pool
}

// TODO: implement
func (kr *kadResolver) Lookup(h common.Hash, timeout time.Duration) (chnl chan common.RouterInfo) {
	return
}

// create a new resolver that stores result into a NetworkDatabase and uses a tunnel pool for the lookup
func KademliaResolver(netDb NetworkDatabase, pool *tunnel.Pool) (r Resolver) {
	if pool != nil && netDb != nil {
		r = &kadResolver{
			netDB: netDb,
			pool:  pool,
		}
	}
	return
}
