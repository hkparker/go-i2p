package common

/*
I2P Certificate
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
	log "github.com/sirupsen/logrus"
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

// Minimum size of a valid Certificate
const (
	CERT_MIN_SIZE = 3
)

type Certificate []byte

//
// Return the Certificate Type specified in the first byte of the Certificate,
// and an error if the certificate is shorter than the minimum certificate size.
//
func (certificate Certificate) Type() (cert_type int, err error) {
	cert_len := len(certificate)
	if cert_len < CERT_MIN_SIZE {
		log.WithFields(log.Fields{
			"at": "(Certificate) Type",
			"certificate_bytes_length": cert_len,
			"reason":                   "too short (len < CERT_MIN_SIZE)",
		}).Error("invalid certificate")
		err = errors.New("error parsing certificate length: certificate is too short")
		return
	}
	cert_type = Integer([]byte{certificate[0]})
	return
}

//
// Look up the length of the Certificate, reporting errors if the certificate is
// shorter than the minimum certificate size or if the reported length doesn't
// match the provided data.
//
func (certificate Certificate) Length() (length int, err error) {
	cert_len := len(certificate)
	_, err = certificate.Type()
	if err != nil {
		return
	}
	length = Integer(certificate[1:CERT_MIN_SIZE])
	inferred_len := length + CERT_MIN_SIZE
	if inferred_len > cert_len {
		log.WithFields(log.Fields{
			"at": "(Certificate) Length",
			"certificate_bytes_length": cert_len,
			"certificate_length_field": length,
			"expected_bytes_length":    inferred_len,
			"reason":                   "data shorter than specified",
		}).Warn("certificate format warning")
		err = errors.New("certificate parsing warning: certificate data is shorter than specified by length")
	} else if cert_len > inferred_len {
		log.WithFields(log.Fields{
			"at": "(Certificate) Length",
			"certificate_bytes_length": cert_len,
			"certificate_length_field": length,
			"expected_bytes_length":    inferred_len,
			"reason":                   "data longer than expected",
		}).Warn("certificate format warning")
		err = errors.New("certificate parsing warning: certificate contains data beyond length")
	}
	return
}

//
// Return the Certificate data and any errors encountered parsing the Certificate.
//
func (certificate Certificate) Data() (data []byte, err error) {
	length, err := certificate.Length()
	if err != nil {
		switch err.Error() {
		case "error parsing certificate length: certificate is too short":
			return
		case "certificate parsing warning: certificate data is shorter than specified by length":
			data = certificate[CERT_MIN_SIZE:]
			return
		case "certificate parsing warning: certificate contains data beyond length":
			data = certificate[CERT_MIN_SIZE : length+CERT_MIN_SIZE]
			return
		}
	}
	data = certificate[CERT_MIN_SIZE:]
	return
}

//
// Read a Certificate from a slice of bytes, returning any extra data on the end of the slice
// and any errors if a valid Certificate could not be read.
//
func ReadCertificate(data []byte) (certificate Certificate, remainder []byte, err error) {
	certificate = Certificate(data)
	length, err := certificate.Length()
	if err != nil && err.Error() == "certificate parsing warning: certificate contains data beyond length" {
		certificate = Certificate(data[:length+CERT_MIN_SIZE])
		remainder = data[length+CERT_MIN_SIZE:]
		err = nil
	}
	return
}
