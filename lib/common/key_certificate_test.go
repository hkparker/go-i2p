package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSingingPublicKeyTypeReturnsCorrectInteger(t *testing.T) {
	assert := assert.New(t)

	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x03, 0x00, 0x00})
	pk_type, err := key_cert.SigningPublicKeyType()

	assert.Nil(err, "SigningPublicKeyType() returned error with valid data")
	assert.Equal(pk_type, KEYCERT_SIGN_P521, "SigningPublicKeyType() did not return correct typec")
}

func TestSingingPublicKeyTypeReportsWhenDataTooSmall(t *testing.T) {
	assert := assert.New(t)

	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x01, 0x00})
	_, err := key_cert.SigningPublicKeyType()

	if assert.NotNil(err) {
		assert.Equal("error parsing key certificate: not enough data", err.Error(), "correct error message should be returned")
	}
}

func TestPublicKeyTypeReturnsCorrectInteger(t *testing.T) {
	assert := assert.New(t)

	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03})
	pk_type, err := key_cert.PublicKeyType()

	assert.Nil(err, "PublicKey() returned error with valid data")
	assert.Equal(pk_type, KEYCERT_SIGN_P521, "PublicKeyType() did not return correct typec")
}

func TestPublicKeyTypeReportsWhenDataTooSmall(t *testing.T) {
	assert := assert.New(t)

	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x02, 0x00, 0x00})
	_, err := key_cert.PublicKeyType()

	if assert.NotNil(err) {
		assert.Equal("error parsing key certificate: not enough data", err.Error(), "correct error message should be returned")
	}
}

func TestConstructPublicKeyReportsWhenDataTooSmall(t *testing.T) {
	assert := assert.New(t)

	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00})
	data := make([]byte, 255)
	_, err := key_cert.ConstructPublicKey(data)

	if assert.NotNil(err) {
		assert.Equal("error constructing public key: not enough data", err.Error(), "correct error message should be returned")
	}
}

func TestConstructPublicKeyReturnsCorrectDataWithElg(t *testing.T) {
	assert := assert.New(t)

	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00})
	data := make([]byte, 256)
	pk, err := key_cert.ConstructPublicKey(data)

	assert.Nil(err, "ConstructPublicKey() returned error with valid data")
	assert.Equal(pk.Len(), 256, "ConstructPublicKey() did not return public key with correct length")
}

func TestConstructSigningPublicKeyReportsWhenDataTooSmall(t *testing.T) {
	assert := assert.New(t)

	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00})
	data := make([]byte, 127)
	_, err := key_cert.ConstructSigningPublicKey(data)

	if assert.NotNil(err) {
		assert.Equal("error constructing signing public key: not enough data", err.Error(), "correct error message should be returned")
	}
}

func TestConstructSigningPublicKeyWithDSASHA1(t *testing.T) {
	assert := assert.New(t)

	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00})
	data := make([]byte, 128)
	spk, err := key_cert.ConstructSigningPublicKey(data)

	assert.Nil(err, "ConstructSigningPublicKey() with DSA SHA1 returned error with valid data")
	assert.Equal(spk.Len(), KEYCERT_SIGN_DSA_SHA1_SIZE, "ConstructSigningPublicKey() with DSA SHA1 returned incorrect SigningPublicKey length")
}

func TestConstructSigningPublicKeyWithP256(t *testing.T) {
	assert := assert.New(t)

	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01})
	data := make([]byte, 128)
	spk, err := key_cert.ConstructSigningPublicKey(data)

	assert.Nil(err, "ConstructSigningPublicKey() with P256 returned err on valid data")
	assert.Equal(spk.Len(), KEYCERT_SIGN_P256_SIZE, "ConstructSigningPublicKey() with P256 returned incorrect SigningPublicKey length")
}

func TestConstructSigningPublicKeyWithP384(t *testing.T) {
	assert := assert.New(t)

	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x02, 0x00, 0x02})
	data := make([]byte, 128)
	spk, err := key_cert.ConstructSigningPublicKey(data)

	assert.Nil(err, "ConstructSigningPublicKey() with P384 returned err on valid data")
	assert.Equal(spk.Len(), KEYCERT_SIGN_P384_SIZE, "ConstructSigningPublicKey() with P384 returned incorrect SigningPublicKey length")
}

func TestConstructSigningPublicKeyWithP521(t *testing.T) {
	assert := assert.New(t)

	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x08, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00})
	data := make([]byte, 128)
	spk, err := key_cert.ConstructSigningPublicKey(data)

	assert.Nil(err, "ConstructSigningPublicKey() with P521 returned err on valid data")
	assert.Equal(spk.Len(), KEYCERT_SIGN_P521_SIZE, "ConstructSigningPublicKey() with P521 returned incorrect SigningPublicKey length")
}
