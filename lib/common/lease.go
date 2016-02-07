package common

import (
	"github.com/bounce-chat/go-i2p/lib/tunnel"
)

type Lease [44]byte

func (lease Lease) TunnelGateway() (h Hash) {
	copy(lease[:32], h[:])
	return
}

func (lease Lease) TunnelID() tunnel.TunnelID {
	return tunnel.TunnelID(
		Integer(lease[32:36]),
	)
}

func (lease Lease) Date() (d Date) {
	copy(lease[36:], d[:])
	return
}
