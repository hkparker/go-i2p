package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func keysAndCertWithoutCertificate() {
}

func keysAndCertWithKeyCertificate() {
}

func TestCertificateWithMissingData(t *testing.T) {
}

func TestCertificateWithValidData(t *testing.T) {
}

func TestPublicKeyWithBadCertificate(t *testing.T) {
}

func TestPublicKeyWithZeroLengthCertificate(t *testing.T) {
}

func TestPublicKeyWithKeyCertificate(t *testing.T) {
}

func TestPublicKeyWithOtherCertType(t *testing.T) {
}

func TestSigningPublicKeyWithBadCertificate(t *testing.T) {
}

func TestSigningPublicKeyWithZeroLengthCertificate(t *testing.T) {
}

func TestSigningPublicKeyWithKeyCertificate(t *testing.T) {
}

func TestSigningPublicKeyWithOtherCertType(t *testing.T) {
}

func TestReadKeysAndCertWithMissingData(t *testing.T) {
	assert := assert.New(t)

	cert_data := make([]byte, 128)
	keys_and_cert, remainder, err := ReadKeysAndCert(cert_data)
	assert.Equal(0, len(remainder))
	if assert.NotNil(err) {
		assert.Equal("error parsing KeysAndCert: data is smaller than minimum valid size", err.Error())
	}

	_, err = keys_and_cert.PublicKey()
	if assert.NotNil(err) {
		assert.Equal("error parsing KeysAndCert: data is smaller than minimum valid size", err.Error())
	}
	_, err = keys_and_cert.SigningPublicKey()
	if assert.NotNil(err) {
		assert.Equal("error parsing KeysAndCert: data is smaller than minimum valid size", err.Error())
	}
	_, err = keys_and_cert.Certificate()
	if assert.NotNil(err) {
		assert.Equal("error parsing KeysAndCert: data is smaller than minimum valid size", err.Error())
	}
}

func TestReadKeysAndCertWithMissingCertData(t *testing.T) {
	assert := assert.New(t)

	cert_data := make([]byte, 128+256)
	cert_data = append(cert_data, []byte{0x05, 0x00, 0x04, 0x00, 0x01}...)
	keys_and_cert, remainder, err := ReadKeysAndCert(cert_data)
	assert.Equal(0, len(remainder))
	if assert.NotNil(err) {
		assert.Equal("certificate parsing warning: certificate data is shorter than specified by length", err.Error())
	}

	_, err = keys_and_cert.PublicKey()
	if assert.NotNil(err) {
		assert.Equal("certificate parsing warning: certificate data is shorter than specified by length", err.Error())
	}
	_, err = keys_and_cert.SigningPublicKey()
	if assert.NotNil(err) {
		assert.Equal("certificate parsing warning: certificate data is shorter than specified by length", err.Error())
	}
	_, err = keys_and_cert.Certificate()
	if assert.NotNil(err) {
		assert.Equal("certificate parsing warning: certificate data is shorter than specified by length", err.Error())
	}
}

func TestReadKeysAndCertWithValidDataWithCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := make([]byte, 128+256)
	cert_data = append(cert_data, []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}...)
	keys_and_cert, remainder, err := ReadKeysAndCert(cert_data)
	assert.Equal(0, len(remainder))
	assert.Nil(err)

	_, err = keys_and_cert.PublicKey()
	assert.Nil(err, "keys_and_cert.PublicKey() returned error with valid data containing certificate")
	_, err = keys_and_cert.SigningPublicKey()
	assert.Nil(err, "keys_and_cert.SigningPublicKey() returned error with valid data containing certificate")
	_, err = keys_and_cert.Certificate()
	assert.Nil(err, "keys_and_cert.Certificate() returned error with valid data containing certificate")
}

func TestReadKeysAndCertWithValidDataWithoutCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := make([]byte, 128+256)
	cert_data = append(cert_data, []byte{0x00, 0x00, 0x00}...)
	keys_and_cert, remainder, err := ReadKeysAndCert(cert_data)
	assert.Equal(0, len(remainder))
	assert.Nil(err)

	_, err = keys_and_cert.PublicKey()
	assert.Nil(err, "keys_and_cert.PublicKey() returned error with valid data not containing certificate")
	_, err = keys_and_cert.SigningPublicKey()
	assert.Nil(err, "keys_and_cert.SigningPublicKey() returned error with valid data not containing certificate")
	_, err = keys_and_cert.Certificate()
	assert.Nil(err, "keys_and_cert.Certificate() returned error with valid data not containing certificate")
}

func TestReadKeysAndCertWithValidDataWithCertificateAndRemainder(t *testing.T) {
	assert := assert.New(t)

	cert_data := make([]byte, 128+256)
	cert_data = append(cert_data, []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x41}...)
	keys_and_cert, remainder, err := ReadKeysAndCert(cert_data)
	if assert.Equal(1, len(remainder)) {
		assert.Equal("A", string(remainder[0]))
	}
	assert.Nil(err)

	_, err = keys_and_cert.PublicKey()
	assert.Nil(err, "keys_and_cert.PublicKey() returned error with valid data containing certificate")
	_, err = keys_and_cert.SigningPublicKey()
	assert.Nil(err, "keys_and_cert.SigningPublicKey() returned error with valid data containing certificate")
	_, err = keys_and_cert.Certificate()
	assert.Nil(err, "keys_and_cert.Certificate() returned error with valid data containing certificate")
}

func TestReadKeysAndCertWithValidDataWithoutCertificateAndRemainder(t *testing.T) {
	assert := assert.New(t)

	cert_data := make([]byte, 128+256)
	cert_data = append(cert_data, []byte{0x00, 0x00, 0x00, 0x41}...)
	keys_and_cert, remainder, err := ReadKeysAndCert(cert_data)
	if assert.Equal(1, len(remainder)) {
		assert.Equal("A", string(remainder[0]))
	}
	assert.Nil(err)

	_, err = keys_and_cert.PublicKey()
	assert.Nil(err, "keys_and_cert.PublicKey() returned error with valid data not containing certificate")
	_, err = keys_and_cert.SigningPublicKey()
	assert.Nil(err, "keys_and_cert.SigningPublicKey() returned error with valid data not containing certificate")
	_, err = keys_and_cert.Certificate()
	assert.Nil(err, "keys_and_cert.Certificate() returned error with valid data not containing certificate")
}
