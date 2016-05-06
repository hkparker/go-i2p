package netdb

import (
	"github.com/bounce-chat/go-i2p/lib/common"
)

// i2p network database, storage of i2p RouterInfos
type NetworkDatabase interface {
	// obtain a RouterInfo by its hash
	// return a channel that gives 1 RouterInfo or nil if the RouterInfo cannot be found
	GetRouterInfo(hash common.Hash) chan *common.RouterInfo
	// store a router info locally
	StoreRouterInfo(ri *common.RouterInfo)
}
