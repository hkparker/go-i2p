package common

import (
	"errors"
	"github.com/bounce-chat/go-i2p/lib/crypto"
)

type KeysAndCert []byte

func (keys_and_cert KeysAndCert) PublicKey() (key crypto.ElgPublicKey, err error) {
	keys_cert_len := len(keys_and_cert)
	if keys_cert_len < 387 {
		if keys_cert_len < 256 {
			err = errors.New("error parsing KeysAndCert: data smaller than ElgPublicKey size")
			return
		}
		err = errors.New("warning parsing KeysAndCert: data is smaller than minimum valid size")
	}
	copy(keys_and_cert[:256], key[:])
	return
}

func (keys_and_cert KeysAndCert) SigningPublicKey() (signing_public_key crypto.SigningPublicKey, err error) {
	cert, err := keys_and_cert.Certificate()
	switch err.Error() {
	case "":
	}
	if cert.Type() == CERT_KEY {
		signing_public_key = KeyCertificate(cert).SigningPublicKey()
	} else {
		// Only Key Certificates are currently used:
		// https://geti2p.net/en/docs/spec/common-structures#type_Certificate
	}
	return
}

func (keys_and_cert KeysAndCert) Certificate() (cert Certificate, err error) {
	keys_cert_len := len(keys_and_cert)
	if keys_cert_len < 387 {
		if keys_cert_len < 384 {
			err = errors.New("error parsing KeysAndCert: data smaller than needed for Certificate")
			return
		}
		err = errors.New("warning parsing KeysAndCert: data is smaller than minimum valid size")
	}
	copy(keys_and_cert[256+128:], cert)
	return
}

func ReadKeysAndCert(data []byte) (KeysAndCert, []byte, error) {
	var keys_and_cert KeysAndCert
	copy(data[:387], keys_and_cert)
	cert, _ := keys_and_cert.Certificate()
	n, err := cert.Length()
	if err != nil {
		return keys_and_cert, data, err
	}
	keys_and_cert = append(keys_and_cert, data[387:n]...)
	return keys_and_cert, data[387+n:], nil
}
