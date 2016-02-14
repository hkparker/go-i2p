package common

import (
	"errors"
	"github.com/bounce-chat/go-i2p/lib/crypto"
)

type KeysAndCert []byte

//
// Return the ElgPublicKey for this KeysAndCert, reading from the Key Certificate
// if it is present first, then the first 256 bytes of the KeysAndCert.
//
func (keys_and_cert KeysAndCert) PublicKey() (key crypto.PublicKey, err error) {
	cert, err := keys_and_cert.Certificate()
	cert_len, err := cert.Length()
	if err != nil {
		return
	}
	if cert_len == 0 {
		// No Certificate is present, return the 256 byte
		// PublicKey space as ElgPublicKey.
		var elg_key crypto.ElgPublicKey
		copy(keys_and_cert[:256], elg_key[:])
		key = elg_key
	} else {
		// A Certificate is present in this KeysAndCert
		cert_type, _ := cert.Type()
		if cert_type == CERT_KEY {
			// This KeysAndCert contains a Key Certificate, construct
			// a PublicKey from the data in the KeysAndCert and
			// any additional data in the Certificate.
			key, err = KeyCertificate(cert).ConstructPublicKey(keys_and_cert[:256])
		} else {
			// Key Certificate is not present, return the 256 byte
			// PublicKey space as ElgPublicKey.  No other Certificate
			// types are currently in use
			var elg_key crypto.ElgPublicKey
			copy(keys_and_cert[:256], elg_key[:])
			key = elg_key
		}

	}
	return
}

//
// Return the SigningPublicKey for this KeysAndCert, reading from the Key Certificate
// if it is present first, then the SigningPublicKey space in the KeysAndCert.
//
func (keys_and_cert KeysAndCert) SigningPublicKey() (signing_public_key crypto.SigningPublicKey, err error) {
	cert, err := keys_and_cert.Certificate()
	cert_len, err := cert.Length()
	if err != nil {
		return
	}
	if cert_len == 0 {
		// No Certificate is present, return the 128 byte
		// SigningPublicKey space as legacy DSA SHA1 SigningPublicKey.
		var dsa_pk crypto.DSAPublicKey
		copy(dsa_pk[:], keys_and_cert[256:256+128])
		signing_public_key = dsa_pk
	} else {
		// A Certificate is present in this KeysAndCert
		cert_type, _ := cert.Type()
		if cert_type == CERT_KEY {
			// This KeysAndCert contains a Key Certificate, construct
			// a SigningPublicKey from the data in the KeysAndCert and
			// any additional data in the Certificate.
			signing_public_key = KeyCertificate(cert).ConstructSigningPublicKey(keys_and_cert[256 : 256+128])
		} else {
			// Key Certificate is not present, return the 128 byte
			// SigningPublicKey space as legacy SHA DSA1 SigningPublicKey.
			// No other Certificate types are currently in use.
			var dsa_pk crypto.DSAPublicKey
			copy(dsa_pk[:], keys_and_cert[256:256+128])
			signing_public_key = dsa_pk
		}

	}
	return
}

//
// Return the Certificate cointained in the KeysAndCert and errors encountered
// while parsing the KeysAndCert or Certificate.
//
func (keys_and_cert KeysAndCert) Certificate() (cert Certificate, err error) {
	keys_cert_len := len(keys_and_cert)
	if keys_cert_len < 387 {
		err = errors.New("warning parsing KeysAndCert: data is smaller than minimum valid size")
		return
	}
	cert, _, err = ReadCertificate(keys_and_cert[256+128:])
	return
}

//
//
//
func ReadKeysAndCert(data []byte) (keys_and_cert KeysAndCert, remainder []byte, err error) {
	if len(data) < 387 {
		err = errors.New("error parsing KeysAndCert: data is smaller than minimum valid size")
		return
	}
	copy(data[:387], keys_and_cert)
	cert, _ := keys_and_cert.Certificate()
	n, err := cert.Length()
	if err != nil {
		remainder = data[387:]
		return
	}
	keys_and_cert = append(keys_and_cert, data[387:n+3]...)
	remainder = data[387+n+3:]
	return
}
