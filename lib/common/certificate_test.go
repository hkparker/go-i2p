package common

import (
	"testing"
)

func TestCertificateTypeIsFirstByte(t *testing.T) {
	bytes := []byte{0x03, 0x00, 0x00}
	certificate := Certificate(bytes)
	cert_type, err := certificate.Type()
	if cert_type != 3 {
		t.Fatal("certificate.Type() is not first byte")
	}
	if err != nil {
		t.Fatal("certificate.Type returned error on valid data:", err)
	}
}

func TestCertificateLengthCorrect(t *testing.T) {
	bytes := []byte{0x03, 0x00, 0x02, 0xff, 0xff}
	certificate := Certificate(bytes)
	cert_len, err := certificate.Length()
	if cert_len != 2 {
		t.Fatal("certificate.Length() is not correct:", cert_len)
	}
	if err != nil {
		t.Fatal("certificate.Length() returned err", err)
	}
}

func TestCertificateLengthErrWhenTooShort(t *testing.T) {
	bytes := []byte{0x03, 0x00}
	certificate := Certificate(bytes)
	cert_len, err := certificate.Length()
	if cert_len != 0 {
		t.Fatal("certificate.Length() is not correct:", cert_len)
	}
	if err == nil || err.Error() != "error parsing certificate length: certificate is too short" {
		t.Fatal("certificate.Length() did not return correct err:", err)
	}
}

func TestCertificateLengthErrWhenDataTooShort(t *testing.T) {
	bytes := []byte{0x03, 0x00, 0x02, 0xff}
	certificate := Certificate(bytes)
	cert_len, err := certificate.Length()
	if cert_len != 2 {
		t.Fatal("certificate.Length() is not correct:", cert_len)
	}
	if err == nil || err.Error() != "certificate parsing warning: certificate data is shorter than specified by length" {
		t.Fatal("certificate.Length() did not return correct err:", err)
	}
}

func TestCertificateDataWhenCorrectSize(t *testing.T) {
	bytes := []byte{0x03, 0x00, 0x02, 0xff, 0xff}
	certificate := Certificate(bytes)
	cert_data, err := certificate.Data()
	if err != nil {
		t.Fatal("certificate.Data() returned error", err)
	}
	cert_len := len(cert_data)
	if cert_len != 2 {
		t.Fatal("certificate.Data() did not return correct length:", cert_len)
	}
	if cert_data[0] != 0xff || cert_data[1] != 0xff {
		t.Fatal("certificate.Data() returned incorrect data")
	}
}

func TestCertificateDataWhenTooLong(t *testing.T) {
	bytes := []byte{0x03, 0x00, 0x02, 0xff, 0xff, 0xaa, 0xaa}
	certificate := Certificate(bytes)
	cert_data, err := certificate.Data()
	if err == nil || err.Error() != "certificate parsing warning: certificate contains data beyond length" {
		t.Fatal("certificate.Data() returned wrong error:", err)
	}
	cert_len := len(cert_data)
	if cert_len != 2 {
		t.Fatal("certificate.Data() did not return correct length:", cert_len)
	}
	if cert_data[0] != 0xff || cert_data[1] != 0xff {
		t.Fatal("certificate.Data() returned incorrect data")
	}
}

func TestCertificateDataWhenTooShort(t *testing.T) {
	bytes := []byte{0x03, 0x00, 0x02, 0xff}
	certificate := Certificate(bytes)
	cert_data, err := certificate.Data()
	if err == nil || err.Error() != "certificate parsing warning: certificate data is shorter than specified by length" {
		t.Fatal("certificate.Data() did not return correct error:", err)
	}
	cert_len := len(cert_data)
	if cert_len != 1 {
		t.Fatal("certificate.Data() did not return correct length when too short:", cert_len)
	}
	if cert_data[0] != 0xff {
		t.Fatal("certificate.Data() returned incorrect data")
	}

}

func TestReadCertificateWithCorrectData(t *testing.T) {
	bytes := []byte{0x00, 0x00, 0x02, 0xff, 0xff}
	cert, remainder, err := ReadCertificate(bytes)
	cert_len := len(cert)
	if cert_len != 5 {
		t.Fatal("ReadCertificate() did not return correct certificate length:", cert_len)
	}
	if len(remainder) != 0 {
		t.Fatal("ReadCertificate() returned a remainder incorrectly:", len(remainder))
	}
	if err != nil {
		t.Fatal("ReadCertificate returned error:", err)
	}
}

func TestReadCertificateWithDataTooShort(t *testing.T) {
	bytes := []byte{0x00, 0x00, 0x02, 0xff}
	cert, remainder, err := ReadCertificate(bytes)
	cert_len := len(cert)
	if cert_len != 4 {
		t.Fatal("ReadCertificate() did not return correct certificate length:", cert_len)
	}
	if len(remainder) != 0 {
		t.Fatal("ReadCertificate() returned a remainder incorrectly when data too short:", len(remainder))
	}
	if err == nil || err.Error() != "certificate parsing warning: certificate data is shorter than specified by length" {
		t.Fatal("ReadCertificate returned incorrect error:", err)
	}
}

func TestReadCertificateWithRemainder(t *testing.T) {
	bytes := []byte{0x00, 0x00, 0x02, 0xff, 0xff, 0x00}
	cert, remainder, err := ReadCertificate(bytes)
	cert_len := len(cert)
	if cert_len != 5 {
		t.Fatal("ReadCertificate() did not return correct certificate length:", cert_len)
	}
	if len(remainder) != 1 {
		t.Fatal("ReadCertificate() returned a remainder incorrectly:", len(remainder))
	}
	if remainder[0] != 0x00 {
		t.Fatal("ReadCertificate() did not return correct remainder value")
	}
	if err != nil {
		t.Fatal("ReadCertificate returned error:", err)
	}
}

func TestReadCertificateWithInvalidLength(t *testing.T) {
	bytes := []byte{0x00, 0x00}
	cert, remainder, err := ReadCertificate(bytes)
	cert_len := len(cert)
	if cert_len != 2 {
		t.Fatal("ReadCertificate() did not populate certificate even though data invalid", cert_len)
	}
	remainder_len := len(remainder)
	if remainder_len != 0 {
		t.Fatal("ReadCertificate() did not return 0 length remainder with invalid length:", remainder_len)
	}
	if err == nil || err.Error() != "error parsing certificate length: certificate is too short" {
		t.Fatal("ReadCertificate() returned an incorrect error with invalid length:", err)
	}
}
