package common

import (
	"github.com/bounce-chat/go-i2p/lib/common/base32"
	"github.com/bounce-chat/go-i2p/lib/common/base64"
	"github.com/bounce-chat/go-i2p/lib/crypto"
	"strings"
)

type Destination []byte

func (destination Destination) PublicKey() (crypto.ElgPublicKey, error) {
	return KeysAndCert(destination).PublicKey()
}

func (destination Destination) SigningPublicKey() (crypto.SigningPublicKey, error) {
	return KeysAndCert(destination).SigningPublicKey()
}

func (destination Destination) Certificate() (Certificate, error) {
	return KeysAndCert(destination).Certificate()
}

func (destination Destination) Base32Address() string {
	hash := crypto.SHA256(destination)
	str := strings.Trim(base32.EncodeToString(hash[:]), "=")
	return str + ".b32.i2p"
}

func (destination Destination) Base64() string {
	return base64.EncodeToString(destination)
}
