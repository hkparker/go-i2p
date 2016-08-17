package netdb

import (
	"github.com/hkparker/go-i2p/lib/bootstrap"
	"github.com/hkparker/go-i2p/lib/common"
	"time"
)

// resolves unknown RouterInfos given the hash of their RouterIdentity
type Resolver interface {
	// resolve a router info by hash
	// return a chan that yields the found RouterInfo or nil if it could not be found after timeout
	Lookup(hash common.Hash, timeout time.Duration) chan common.RouterInfo
}

// i2p network database, storage of i2p RouterInfos
type NetworkDatabase interface {
	// obtain a RouterInfo by its hash locally
	// return a RouterInfo if we found it locally
	// return nil if the RouterInfo cannot be found locally
	GetRouterInfo(hash common.Hash) common.RouterInfo

	// store a router info locally
	StoreRouterInfo(ri common.RouterInfo)

	// try obtaining more peers with a bootstrap instance until we get minRouters number of router infos
	// returns error if bootstrap.GetPeers returns an error otherwise returns nil
	Reseed(b bootstrap.Bootstrap, minRouters int) error

	// return how many router infos we have
	Size() int

	// ensure underlying resources exist , i.e. directories, files, configs
	Ensure() error
}
