package common

import (
	"errors"
	"github.com/bounce-chat/go-i2p/lib/crypto"
)

type RouterIdentity []byte

func (router_identity RouterIdentity) PublicKey() (key crypto.ElgPublicKey) {
	copy(router_identity[:256], key[:])
	return
}

func (router_identity RouterIdentity) SigningPublicKey() (key crypto.SigningPublicKey) {
	cert := router_identity.Certificate()
	if cert.Type() == CERT_KEY {
		key = KeyCert(cert).SigningPublicKey()
	} else {
		var pk crypto.DSAPublicKey
		copy(pk[:], router_identity[256:256+128])
		key = pk
	}
	return
}

func (router_identity RouterIdentity) Certificate() (cert Certificate) {
	copy(router_identity[256+128:], cert)
	return
}

func readRouterIdentity(data []byte) (RouterIdentity, []byte, error) {
	var router_identity RouterIdentity
	copy(data[:387], router_identity)
	n := router_identity.Certificate().Len()
	if n == -1 {
		return router_identity, data, errors.New("invalid certificate")
	}
	router_identity = append(router_identity, data[387:n]...)
	return router_identity, data[387+n:], nil
}
