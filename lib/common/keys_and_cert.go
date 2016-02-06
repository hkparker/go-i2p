package common

import (
	"github.com/bounce-chat/go-i2p/lib/crypto"
)

type KeysAndCert []byte

func (keys_and_cert KeysAndCert) PublicKey() (key crypto.ElgPublicKey) {
	if len(keys_and_cert) < 387 {

	}
	copy(keys_and_cert[:256], key[:])
	return
}

func (keys_and_cert KeysAndCert) SigningPublicKey() (key crypto.SigningPublicKey) {
	cert := keys_and_cert.Certificate()
	if cert.Type() == CERT_KEY {
		key = KeyCertificate(cert).SigningPublicKey()
	} else {
		var pk crypto.DSAPublicKey
		copy(pk[:], keys_and_cert[256:256+128])
		key = pk
	}
	return
}

func (keys_and_cert KeysAndCert) Certificate() (cert Certificate) {
	copy(keys_and_cert[256+128:], cert)
	return
}

func ReadKeysAndCert(data []byte) (KeysAndCert, []byte, error) {
	var keys_and_cert KeysAndCert
	copy(data[:387], keys_and_cert)
	n, err := keys_and_cert.Certificate().Length()
	if err != nil {
		return keys_and_cert, data, err
	}
	keys_and_cert = append(keys_and_cert, data[387:n]...)
	return keys_and_cert, data[387+n:], nil
}
