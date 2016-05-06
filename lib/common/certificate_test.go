package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCertificateTypeIsFirstByte(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x03, 0x00, 0x00}
	certificate := Certificate(bytes)
	cert_type, err := certificate.Type()

	assert.Equal(cert_type, 3, "certificate.Type() should be the first bytes in a certificate")
	assert.Nil(err)
}

func TestCertificateLengthCorrect(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x03, 0x00, 0x02, 0xff, 0xff}
	certificate := Certificate(bytes)
	cert_len, err := certificate.Length()

	assert.Equal(cert_len, 2, "certificate.Length() should return integer from second two bytes")
	assert.Nil(err)
}

func TestCertificateLengthErrWhenTooShort(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x03, 0x01}
	certificate := Certificate(bytes)
	cert_len, err := certificate.Length()

	assert.Equal(cert_len, 0, "certificate.Length() did not return zero length for missing length data")
	if assert.NotNil(err) {
		assert.Equal("error parsing certificate length: certificate is too short", err.Error(), "correct error message should be returned")
	}
}

func TestCertificateLengthErrWhenDataTooShort(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x03, 0x00, 0x02, 0xff}
	certificate := Certificate(bytes)
	cert_len, err := certificate.Length()

	assert.Equal(cert_len, 2, "certificate.Length() did not return indicated length when data was actually missing")
	if assert.NotNil(err) {
		assert.Equal("certificate parsing warning: certificate data is shorter than specified by length", err.Error(), "correct error message should be returned")
	}
}

func TestCertificateDataWhenCorrectSize(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x03, 0x00, 0x01, 0xaa}
	certificate := Certificate(bytes)
	cert_data, err := certificate.Data()

	assert.Nil(err, "certificate.Data() returned error with valid data")
	cert_len := len(cert_data)
	assert.Equal(cert_len, 1, "certificate.Length() did not return indicated length when data was valid")
	assert.Equal(170, int(cert_data[0]), "certificate.Data() returned incorrect data")
}

func TestCertificateDataWhenTooLong(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x03, 0x00, 0x02, 0xff, 0xff, 0xaa, 0xaa}
	certificate := Certificate(bytes)
	cert_data, err := certificate.Data()

	if assert.NotNil(err) {
		assert.Equal("certificate parsing warning: certificate contains data beyond length", err.Error(), "correct error message should be returned")
	}
	cert_len := len(cert_data)
	assert.Equal(cert_len, 2, "certificate.Length() did not return indicated length when data was too long")
	if cert_data[0] != 0xff || cert_data[1] != 0xff {
		t.Fatal("certificate.Data() returned incorrect data when data was too long")
	}
}

func TestCertificateDataWhenTooShort(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x03, 0x00, 0x02, 0xff}
	certificate := Certificate(bytes)
	cert_data, err := certificate.Data()

	if assert.NotNil(err) {
		assert.Equal("certificate parsing warning: certificate data is shorter than specified by length", err.Error(), "correct error message should be returned")
	}
	cert_len := len(cert_data)
	assert.Equal(cert_len, 1, "certificate.Data() did not return correct amount of data when data too short")
	assert.Equal(255, int(cert_data[0]), "certificate.Data() did not return correct data values when data was too short")
}

func TestReadCertificateWithCorrectData(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x00, 0x00, 0x02, 0xff, 0xff}
	cert, remainder, err := ReadCertificate(bytes)

	assert.Equal(len(cert), 5, "ReadCertificate() did not return correct amount of data for valid certificate")
	assert.Equal(len(remainder), 0, "ReadCertificate() did not return a zero length remainder on a valid certificate")
	assert.Nil(err, "ReadCertificate() should not return an error with valid data")
}

func TestReadCertificateWithDataTooShort(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x00, 0x00, 0x02, 0xff}
	cert, remainder, err := ReadCertificate(bytes)

	assert.Equal(len(cert), 4, "ReadCertificate() did not return correct amount of data for certificate with missing data")
	assert.Equal(len(remainder), 0, "ReadCertificate() did not return a zero length remainder on certificate with missing data")
	if assert.NotNil(err) {
		assert.Equal("certificate parsing warning: certificate data is shorter than specified by length", err.Error(), "correct error message should be returned")
	}
}

func TestReadCertificateWithRemainder(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x00, 0x00, 0x02, 0xff, 0xff, 0x01}
	cert, remainder, err := ReadCertificate(bytes)

	assert.Equal(len(cert), 5, "ReadCertificate() did not return correct amount of data for certificate with extra data")
	assert.Equal(len(remainder), 1, "ReadCertificate() returned incorrect length remainder on certificate with extra data")
	assert.Equal(1, int(remainder[0]), "ReadCertificate() did not return correct remainder value")
	assert.Nil(err)
}

func TestReadCertificateWithInvalidLength(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x00, 0x00}
	cert, remainder, err := ReadCertificate(bytes)

	assert.Equal(len(cert), 2, "ReadCertificate() should populate the certificate with the provided data even when invalid")
	assert.Equal(len(remainder), 0, "ReadCertificate() returned non-zero length remainder on invalid certificate")
	if assert.NotNil(err) {
		assert.Equal("error parsing certificate length: certificate is too short", err.Error(), "correct error message should be returned")
	}
}
