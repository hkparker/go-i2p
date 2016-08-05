package tunnel

import (
	"encoding/binary"
	"github.com/hkparker/go-i2p/lib/crypto"
)

type TunnelID uint32

type EncryptedTunnelMessage crypto.TunnelData

func (tm EncryptedTunnelMessage) ID() (tid TunnelID) {
	tid = TunnelID(binary.BigEndian.Uint32(tm[:4]))
	return
}

func (tm EncryptedTunnelMessage) IV() crypto.TunnelIV {
	return tm[4:20]
}

func (tm EncryptedTunnelMessage) Data() crypto.TunnelIV {
	return tm[24:]
}

type DecryptedTunnelMessage [1028]byte

func (decrypted_tunnel_message DecryptedTunnelMessage) ID() TunnelID {
	return TunnelID(binary.BigEndian.Uint32(
		decrypted_tunnel_message[:4],
	))
}

func (decrypted_tunnel_message DecryptedTunnelMessage) IV() crypto.TunnelIV {
	return decrypted_tunnel_message[4:20]
}

func (decrypted_tunnel_message DecryptedTunnelMessage) Checksum() crypto.TunnelIV {
	return decrypted_tunnel_message[24:28]
}
