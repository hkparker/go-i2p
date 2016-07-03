package tunnel

import (
	"github.com/hkparker/go-i2p/lib/crypto"
)

type Participant struct {
	decryption *crypto.Tunnel
}
