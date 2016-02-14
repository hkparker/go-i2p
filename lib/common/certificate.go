package common

import (
	"errors"
)

// Certificate Types
const (
	CERT_NULL = iota
	CERT_HASHCASH
	CERT_HIDDEN
	CERT_SIGNED
	CERT_MULTIPLE
	CERT_KEY
)

type Certificate []byte

func (certificate Certificate) Type() (cert_type int, err error) {
	if len(certificate) < 1 {
		err = errors.New("")
		return
	}
	cert_type = Integer([]byte{certificate[0]})
	return
}

//
// Look up the length of the certificate, reporting
// errors if the certificate is invalid or the specified
// length does not match the provided data.
//
func (certificate Certificate) Length() (int, error) {
	if len(certificate) < 3 {
		// log
		return 0, errors.New("error parsing certificate length: certificate is too short")
	}
	length := Integer(certificate[1:3])
	inferred_len := length + 3
	cert_len := len(certificate)
	if inferred_len > cert_len {
		// log
		return length, errors.New("certificate parsing warning: certificate data is shorter than specified by length")
	} else if cert_len > inferred_len {
		//log
		return length, errors.New("certificate parsing warning: certificate contains data beyond length")
	}
	return length, nil
}

//
// Return the certificate data and any errors
// encountered by Length.
//
func (certificate Certificate) Data() ([]byte, error) {
	length, err := certificate.Length()
	if err != nil {
		switch err.Error() {
		case "error parsing certificate length: certificate is too short":
			return make([]byte, 0), err
		case "certificate parsing warning: certificate data is shorter than specified by length":
			return certificate[3:], err
		case "certificate parsing warning: certificate contains data beyond length":
			return certificate[3 : length+3], err
		}
	}
	return certificate[3:], nil
}

//
// Read a certificate from a slice of bytes, returning
// any extra data on the end of the slice.
//
func ReadCertificate(data []byte) (Certificate, []byte, error) {
	certificate := Certificate(data)
	length, err := certificate.Length()
	if err != nil {
		switch err.Error() {
		case "error parsing certificate length: certificate is too short":
			return Certificate{}, make([]byte, 0), err
		case "certificate parsing warning: certificate data is shorter than specified by length":
			return certificate, make([]byte, 0), err
		case "certificate parsing warning: certificate contains data beyond length":
			return Certificate(certificate[:length+3]), certificate[length+3:], nil
		}
	}
	return certificate, make([]byte, 0), nil
}
