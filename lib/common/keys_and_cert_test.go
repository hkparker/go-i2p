package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCertificateWithMissingData(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01}
	data := make([]byte, 128+256)
	data = append(data, cert_data...)
	keys_and_cert := KeysAndCert(data)

	cert, err := keys_and_cert.Certificate()
	if assert.NotNil(err) {
		assert.Equal("certificate parsing warning: certificate data is shorter than specified by length", err.Error())
	}
	cert_bytes := []byte(cert)
	if assert.Equal(len(cert_data), len(cert_bytes)) {
		assert.Equal(cert_bytes, cert_data, "keys_and_cert.Certificate() did not return available data when cert was missing some data")
	}
}

func TestCertificateWithValidData(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	data := make([]byte, 128+256)
	data = append(data, cert_data...)
	keys_and_cert := KeysAndCert(data)

	cert, err := keys_and_cert.Certificate()
	assert.Nil(err)
	cert_bytes := []byte(cert)
	if assert.Equal(len(cert_data), len(cert_bytes)) {
		assert.Equal(cert_bytes, cert_data, "keys_and_cert.Certificate() did not return correct data with valid cert")
	}
}

func TestPublicKeyWithBadData(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	pub_key_data := make([]byte, 193)
	data := make([]byte, 128)
	data = append(data, pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert := KeysAndCert(data)

	pub_key, err := keys_and_cert.PublicKey()
	if assert.NotNil(err) {
		assert.Equal("error parsing KeysAndCert: data is smaller than minimum valid size", err.Error())
	}
	assert.Nil(pub_key)
}

func TestPublicKeyWithBadCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01}
	pub_key_data := make([]byte, 256)
	data := make([]byte, 128)
	data = append(data, pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert := KeysAndCert(data)

	pub_key, err := keys_and_cert.PublicKey()
	if assert.NotNil(err) {
		assert.Equal("certificate parsing warning: certificate data is shorter than specified by length", err.Error())
	}
	assert.Nil(pub_key)
}

func TestPublicKeyWithNullCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x00, 0x00, 0x00}
	pub_key_data := make([]byte, 256)
	data := make([]byte, 128)
	data = append(data, pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert := KeysAndCert(data)

	pub_key, err := keys_and_cert.PublicKey()
	assert.Nil(err)
	assert.Equal(len(pub_key_data), pub_key.Len())
}

func TestPublicKeyWithKeyCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	pub_key_data := make([]byte, 256)
	data := make([]byte, 128)
	data = append(data, pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert := KeysAndCert(data)

	pub_key, err := keys_and_cert.PublicKey()
	assert.Nil(err)
	assert.Equal(len(pub_key_data), pub_key.Len())
}

func TestSigningPublicKeyWithBadData(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	pub_key_data := make([]byte, 256)
	data := make([]byte, 93)
	data = append(data, pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert := KeysAndCert(data)

	signing_pub_key, err := keys_and_cert.SigningPublicKey()
	if assert.NotNil(err) {
		assert.Equal("error parsing KeysAndCert: data is smaller than minimum valid size", err.Error())
	}
	assert.Nil(signing_pub_key)
}

func TestSigningPublicKeyWithBadCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01}
	pub_key_data := make([]byte, 256)
	data := make([]byte, 128)
	data = append(data, pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert := KeysAndCert(data)

	signing_pub_key, err := keys_and_cert.SigningPublicKey()
	if assert.NotNil(err) {
		assert.Equal("certificate parsing warning: certificate data is shorter than specified by length", err.Error())
	}
	assert.Nil(signing_pub_key)
}

func TestSigningPublicKeyWithNullCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x00, 0x00, 0x00}
	pub_key_data := make([]byte, 256)
	signing_pub_key_data := make([]byte, 128)
	data := append(pub_key_data, signing_pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert := KeysAndCert(data)

	signing_pub_key, err := keys_and_cert.SigningPublicKey()
	assert.Nil(err)
	assert.Equal(len(signing_pub_key_data), signing_pub_key.Len())
}

func TestSigningPublicKeyWithKeyCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	pub_key_data := make([]byte, 256)
	signing_pub_key_data := make([]byte, 128)
	data := append(pub_key_data, signing_pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert := KeysAndCert(data)

	signing_pub_key, err := keys_and_cert.SigningPublicKey()
	assert.Nil(err)
	assert.Equal(len(signing_pub_key_data), signing_pub_key.Len())
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
