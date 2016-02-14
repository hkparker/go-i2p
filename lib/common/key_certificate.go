package common

import (
	"errors"
	"github.com/bounce-chat/go-i2p/lib/crypto"
)

// Key Certificate Signing Key Types
const (
	KEYCERT_SIGN_DSA_SHA1 = iota
	KEYCERT_SIGN_P256
	KEYCERT_SIGN_P384
	KEYCERT_SIGN_P521
	KEYCERT_SIGN_RSA2048
	KEYCERT_SIGN_RSA3072
	KEYCERT_SIGN_RSA4096
	KEYCERT_SIGN_ED25519
	KEYCERT_SIGN_ED25519PH
)

// Key Certificate Public Key Types
const (
	KEYCERT_CRYPTO_ELG = iota
)

// SigningPublicKey sizes for Signing Key Types
const (
	KEYCERT_SIGN_DSA_SHA1_SIZE  = 128
	KEYCERT_SIGN_P256_SIZE      = 64
	KEYCERT_SIGN_P384_SIZE      = 96
	KEYCERT_SIGN_P521_SIZE      = 132
	KEYCERT_SIGN_RSA2048_SIZE   = 256
	KEYCERT_SIGN_RSA3072_SIZE   = 384
	KEYCERT_SIGN_RSA4096_SIZE   = 512
	KEYCERT_SIGN_ED25519_SIZE   = 32
	KEYCERT_SIGN_ED25519PH_SIZE = 32
)

// PublicKey sizes for Public Key Types
const (
	KEYCERT_CRYPTO_ELG_SIZE = 256
)

type KeyCertificate []byte

//
// The data contained in the Certificate.
//
func (key_certificate KeyCertificate) Data() ([]byte, error) {
	return Certificate(key_certificate).Data()
}

//
//
//
func (key_certificate KeyCertificate) SigningPublicKeyType() (signing_pubkey_type int, err error) {
	data, err := key_certificate.Data()
	if err != nil {
		return
	}
	if len(data) < 2 {
		err = errors.New("")
		return
	}
	signing_pubkey_type = Integer(data[:2])
	return
}

//
//
//
func (key_certificate KeyCertificate) PublicKeyType() (pubkey_type int, err error) {
	data, err := key_certificate.Data()
	if err != nil {
		return
	}
	if len(data) < 4 {
		err = errors.New("")
		return
	}
	pubkey_type = Integer(data[2:4])
	return
}

//
//
//
func (key_certificate KeyCertificate) ConstructPublicKey(data []byte) (public_key crypto.PublicKey, err error) {
	key_type, err := key_certificate.PublicKeyType()
	if err != nil {
		return
	}
	if len(data) < 256 {
		err = errors.New("")
		return
	}
	switch key_type {
	case KEYCERT_CRYPTO_ELG:
		var elg_key crypto.ElgPublicKey
		copy(elg_key[:], data[256-KEYCERT_CRYPTO_ELG_SIZE:256])
		public_key = elg_key
	}
	return
}

//
//
//
func (key_certificate KeyCertificate) ConstructSigningPublicKey(data []byte) (signing_public_key crypto.SigningPublicKey) {
	signing_key_type, err := key_certificate.PublicKeyType()
	if err != nil {
		return
	}
	if len(data) < 128 {
		err = errors.New("")
		return
	}
	switch signing_key_type {
	case KEYCERT_SIGN_DSA_SHA1:
		var dsa_key crypto.DSAPublicKey
		copy(dsa_key[:], data[128-KEYCERT_SIGN_DSA_SHA1_SIZE:128])
		signing_public_key = dsa_key
	case KEYCERT_SIGN_P256:
		var ec_key crypto.ECP256PublicKey
		copy(ec_key[:], data[128-KEYCERT_SIGN_P256_SIZE:128])
		signing_public_key = ec_key
	case KEYCERT_SIGN_P384:
		var ec_key crypto.ECP384PublicKey
		copy(ec_key[:], data[128-KEYCERT_SIGN_P384_SIZE:128])
		signing_public_key = ec_key
	case KEYCERT_SIGN_P521:
		var ec_key crypto.ECP521PublicKey
		extra := KEYCERT_SIGN_P521_SIZE - 128
		copy(ec_key[:], data)
		copy(ec_key[128:], key_certificate[4:4+extra])
		signing_public_key = ec_key
	case KEYCERT_SIGN_RSA2048:
		//var rsa_key crypto.RSA2048PublicKey
		//extra := KEYCERT_SIGN_RSA2048_SIZE - 128
		//copy(rsa_key[:], data)
		//copy(rsa_key[128:], key_certificate[4:4+extra])
		//signing_public_key = rsa_key
	case KEYCERT_SIGN_RSA3072:
	case KEYCERT_SIGN_RSA4096:
	case KEYCERT_SIGN_ED25519:
	case KEYCERT_SIGN_ED25519PH:
	}
	return
}
