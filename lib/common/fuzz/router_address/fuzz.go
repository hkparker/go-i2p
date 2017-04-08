package exportable

import "github.com/hkparker/go-i2p/lib/common"

func Fuzz(data []byte) int {
	router_address, _, _ := common.ReadRouterAddress(data)
	router_address.Cost()
	router_address.Expiration()
	router_address.Options()
	router_address.TransportStyle()
	return 0
}
