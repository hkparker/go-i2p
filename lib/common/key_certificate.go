package common

/*
I2P Key Certificate
https://geti2p.net/spec/common-structures#certificate
Accurate for version 0.9.24

+----+----+----+----+----+-//
|type| length  | payload
+----+----+----+----+----+-//

type :: Integer
        length -> 1 byte

        case 0 -> NULL
        case 1 -> HASHCASH
        case 2 -> HIDDEN
        case 3 -> SIGNED
        case 4 -> MULTIPLE
        case 5 -> KEY

length :: Integer
          length -> 2 bytes

payload :: data
           length -> $length bytes
*/

import (
	"errors"
	log "github.com/Sirupsen/logrus"
	"github.com/hkparker/go-i2p/lib/crypto"
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

// Sizes of structures in KeyCertificates
const (
	KEYCERT_PUBKEY_SIZE = 256
	KEYCERT_SPK_SIZE    = 128
)

type KeyCertificate []byte

//
// The data contained in the Key Certificate.
//
func (key_certificate KeyCertificate) Data() ([]byte, error) {
	return Certificate(key_certificate).Data()
}

//
// The SigningPublicKey type this Key Certificate describes and any errors encountered
// parsing the KeyCertificate.
//
func (key_certificate KeyCertificate) SigningPublicKeyType() (signing_pubkey_type int, err error) {
	data, err := key_certificate.Data()
	if err != nil {
		return
	}
	data_len := len(data)
	if data_len < 2 {
		log.WithFields(log.Fields{
			"at":           "(KeyCertificate) SigningPublicKeyType",
			"data_len":     data_len,
			"required_len": 2,
			"reason":       "not enough data",
		}).Error("error parsing key certificate")
		err = errors.New("error parsing key certificate: not enough data")
		return
	}
	signing_pubkey_type = Integer(data[:2])
	return
}

//
// The PublicKey type this Key Certificate describes and any errors encountered parsing
// this KeyCertificate.
//
func (key_certificate KeyCertificate) PublicKeyType() (pubkey_type int, err error) {
	data, err := key_certificate.Data()
	if err != nil {
		return
	}
	data_len := len(data)
	if data_len < 4 {
		log.WithFields(log.Fields{
			"at":           "(KeyCertificate) PublicKeyType",
			"data_len":     data_len,
			"required_len": 4,
			"reason":       "not enough data",
		}).Error("error parsing key certificate")
		err = errors.New("error parsing key certificate: not enough data")
		return
	}
	pubkey_type = Integer(data[2:4])
	return
}

//
// Given some bytes, build a PublicKey using any excess data that may be stored in the KeyCertificate and return
// it along with any errors encountered constructing the PublicKey.
//
func (key_certificate KeyCertificate) ConstructPublicKey(data []byte) (public_key crypto.PublicKey, err error) {
	key_type, err := key_certificate.PublicKeyType()
	if err != nil {
		return
	}
	data_len := len(data)
	if data_len < KEYCERT_PUBKEY_SIZE {
		log.WithFields(log.Fields{
			"at":           "(KeyCertificate) ConstructPublicKey",
			"data_len":     data_len,
			"required_len": KEYCERT_PUBKEY_SIZE,
			"reason":       "not enough data",
		}).Error("error constructing public key")
		err = errors.New("error constructing public key: not enough data")
		return
	}
	switch key_type {
	case KEYCERT_CRYPTO_ELG:
		var elg_key crypto.ElgPublicKey
		copy(elg_key[:], data[KEYCERT_PUBKEY_SIZE-KEYCERT_CRYPTO_ELG_SIZE:KEYCERT_PUBKEY_SIZE])
		public_key = elg_key
	}
	return
}

//
// Given some bytes, build a SigningPublicKey using any excess data that may be stored in the KeyCertificate and return
// it along with any errors encountered constructing the SigningPublicKey.
//
func (key_certificate KeyCertificate) ConstructSigningPublicKey(data []byte) (signing_public_key crypto.SigningPublicKey, err error) {
	signing_key_type, err := key_certificate.PublicKeyType()
	if err != nil {
		return
	}
	data_len := len(data)
	if data_len < KEYCERT_SPK_SIZE {
		log.WithFields(log.Fields{
			"at":           "(KeyCertificate) ConstructSigningPublicKey",
			"data_len":     data_len,
			"required_len": KEYCERT_SPK_SIZE,
			"reason":       "not enough data",
		}).Error("error constructing signing public key")
		err = errors.New("error constructing signing public key: not enough data")
		return
	}
	switch signing_key_type {
	case KEYCERT_SIGN_DSA_SHA1:
		var dsa_key crypto.DSAPublicKey
		copy(dsa_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_DSA_SHA1_SIZE:KEYCERT_SPK_SIZE])
		signing_public_key = dsa_key
	case KEYCERT_SIGN_P256:
		var ec_key crypto.ECP256PublicKey
		copy(ec_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_P256_SIZE:KEYCERT_SPK_SIZE])
		signing_public_key = ec_key
	case KEYCERT_SIGN_P384:
		var ec_key crypto.ECP384PublicKey
		copy(ec_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_P384_SIZE:KEYCERT_SPK_SIZE])
		signing_public_key = ec_key
	case KEYCERT_SIGN_P521:
		var ec_key crypto.ECP521PublicKey
		extra := KEYCERT_SIGN_P521_SIZE - KEYCERT_SPK_SIZE
		copy(ec_key[:], data)
		copy(ec_key[KEYCERT_SPK_SIZE:], key_certificate[4:4+extra])
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

//
// Return the size of a Signature corresponding to the Key Certificate's
// SigningPublicKey type.
//
func (key_certificate KeyCertificate) SignatureSize() (size int) {
	sizes := map[int]int{
		KEYCERT_SIGN_DSA_SHA1:  40,
		KEYCERT_SIGN_P256:      64,
		KEYCERT_SIGN_P384:      96,
		KEYCERT_SIGN_P521:      132,
		KEYCERT_SIGN_RSA2048:   256,
		KEYCERT_SIGN_RSA3072:   384,
		KEYCERT_SIGN_RSA4096:   512,
		KEYCERT_SIGN_ED25519:   64,
		KEYCERT_SIGN_ED25519PH: 64,
	}
	key_type, err := key_certificate.SigningPublicKeyType()
	if err != nil {
		return 0
	}
	return sizes[int(key_type)]
}
