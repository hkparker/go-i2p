package tunnel

import (
	"encoding/binary"
	"github.com/bounce-chat/go-i2p/lib/crypto"
)

type TunnelID uint32

// data sent down a tunnel
type TunnelMessage crypto.TunnelData

func (tm TunnelMessage) ID() (tid TunnelID) {
	tid = TunnelID(binary.BigEndian.Uint32(tm[:4]))
	return
}

func (tm TunnelMessage) IV() crypto.TunnelIV {
	return tm[4:20]
}
