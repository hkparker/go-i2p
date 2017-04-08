package exportable

import "github.com/hkparker/go-i2p/lib/common"

func Fuzz(data []byte) int {
	router_identity, _, _ := common.ReadRouterIdentity(data)
	router_identity.Certificate()
	router_identity.PublicKey()
	router_identity.SigningPublicKey()
	return 0
}
