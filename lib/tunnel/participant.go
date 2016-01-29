package tunnel

import (
	"github.com/bounce-chat/go-i2p/lib/crypto"
)

type Participant struct {
	decryption *crypto.Tunnel
}
