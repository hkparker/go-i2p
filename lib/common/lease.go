package common

import (
	"github.com/bounce-chat/go-i2p/lib/tunnel"
)

const (
	LEASE_SIZE = 44
)

type Lease [LEASE_SIZE]byte

func (lease Lease) TunnelGateway() (h IdentHash) {
	copy(lease[:32], h[:])
	return
}

func (lease Lease) TunnelID() tunnel.TunnelID {
	return tunnel.TunnelID(
		Integer(lease[32:36]...),
	)
}

func (lease Lease) Date() (d Date) {
	copy(lease[36:], d[:])
	return
}
