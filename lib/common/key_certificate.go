package common

import (
	"github.com/bounce-chat/go-i2p/lib/crypto"
)

type KeyCertificate []byte

func (key_certificate KeyCertificate) Type() byte {
	return Certificate(key_certificate).Type()
}

func (key_certificate KeyCertificate) Data() ([]byte, error) {
	return Certificate(key_certificate).Data()
}

// get the signing public key from this key cert
func (key_certificate KeyCertificate) SigningPublicKey() (k crypto.SigningPublicKey) {
	data, err := key_certificate.Data()
	if err != nil {
		return
	}
	ktype := Integer(data[:2])
	// set data to be the key data now
	data = data[4:]
	// determine the key type
	if ktype == KEYCERT_SIGN_DSA_SHA1 {
		var pk crypto.DSAPublicKey
		copy(pk[:], data[:pk.Len()])
		k = pk
	} else if ktype == KEYCERT_SIGN_P256 {
		var pk crypto.ECP256PublicKey
		copy(pk[:], data[:pk.Len()])
		k = pk
	} else if ktype == KEYCERT_SIGN_P384 {
		var pk crypto.ECP384PublicKey
		copy(pk[:], data[:pk.Len()])
		k = pk
	} else if ktype == KEYCERT_SIGN_P521 {
		var pk crypto.ECP521PublicKey
		copy(pk[:], data[:pk.Len()])
		k = pk
	}
	// TODO: rsa/eddsa
	return
}
