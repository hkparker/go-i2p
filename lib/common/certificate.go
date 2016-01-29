package common

import (
	"encoding/binary"
	"github.com/bounce-chat/go-i2p/lib/crypto"
)

const (
	CERT_NULL = iota
	CERT_HASHCASH
	CERT_HIDDEN
	CERT_SIGNED
	CERT_MULTIPLE
	CERT_KEY
)

const (
	KEYCERT_SIGN_DSA_SHA1 = iota
	KEYCERT_SIGN_P256
	KEYCERT_SIGN_P384
	KEYCERT_SIGN_P521
	KEYCERT_SIGN_RSA2048
	KEYCERT_SIGN_RSA3072
	KEYCERT_SIGN_RSA4096
	KEYCERT_SIGN_ED25519
)

const (
	KEYCERT_CRYPTO_ELG = iota
)

// used to append data to existing data structures
type Certificate []byte

// return the type of this certificate
func (c Certificate) Type() byte {
	return c[0]
}

// get the length of the data in this certificate
func (c Certificate) Len() int {
	return int(binary.BigEndian.Uint16(c[1:3]))
}

// get the data for this certificate or null if non exists
func (c Certificate) Data() (d []byte) {
	l := c.Len()
	if l > 0 {
		// TODO(psi): check bounds correctly?
		d = c[3 : 3+l]
	}
	return
}

// a Certificate of type KEY
type KeyCert []byte

func (c KeyCert) Type() byte {
	return Certificate(c).Type()
}

func (c KeyCert) Data() []byte {
	return Certificate(c).Data()
}

// get the signing public key from this key cert
func (c KeyCert) SigningPublicKey() (k crypto.SigningPublicKey) {
	data := c.Data()
	ktype := binary.BigEndian.Uint16(data[:2])
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
