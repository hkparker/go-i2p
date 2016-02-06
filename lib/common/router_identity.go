package common

import (
	"github.com/bounce-chat/go-i2p/lib/crypto"
)

type RouterIdentity []byte

func (router_identity RouterIdentity) PublicKey() (key crypto.ElgPublicKey) {
	return KeysAndCert(router_identity).PublicKey()
}

func (router_identity RouterIdentity) SigningPublicKey() (key crypto.SigningPublicKey) {
	return KeysAndCert(router_identity).SigningPublicKey()
}

func (router_identity RouterIdentity) Certificate() (cert Certificate) {
	return KeysAndCert(router_identity).Certificate()
}

func ReadRouterIdentity(data []byte) (RouterIdentity, []byte, error) {
	keys_and_certs, remainder, err := ReadKeysAndCert(data)
	return RouterIdentity(keys_and_certs), remainder, err
}
