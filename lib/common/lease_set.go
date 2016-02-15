package common

import (
	"errors"
	"github.com/bounce-chat/go-i2p/lib/crypto"
)

type LeaseSet []byte

func (lease_set LeaseSet) Destination() (destination Destination, err error) {
	keys_and_cert, _, err := ReadKeysAndCert(lease_set)
	destination = Destination(keys_and_cert)
	return
}

func (lease_set LeaseSet) PublicKey() (public_key crypto.ElgPublicKey, err error) {
	_, remainder, err := ReadKeysAndCert(lease_set)
	if len(remainder) < 256 {
		err = errors.New("error parsing public key: not enough data")
		copy(public_key[:], remainder)
		return
	}
	copy(public_key[:], remainder[:256])
	return
}

func (lease_set LeaseSet) SigningKey() (signing_public_key crypto.SigningPublicKey, err error) {
	destination, err := lease_set.Destination()
	if err != nil {
		return
	}
	offset := len(destination) + 256
	cert, err := destination.Certificate()
	if err != nil {
		return
	}
	cert_len, err := cert.Length()
	if err != nil {
		return
	}
	if len(lease_set) < offset+128 {
		err = errors.New("")
		return
	}
	if cert_len == 0 {
		// No Certificate is present, return the 128 byte
		// SigningPublicKey space as legacy DSA SHA1 SigningPublicKey.
		var dsa_pk crypto.DSAPublicKey
		copy(dsa_pk[:], lease_set[offset:offset+128])
		signing_public_key = dsa_pk
	} else {
		// A Certificate is present in this LeaseSet's Destination
		cert_type, _ := cert.Type()
		if cert_type == CERT_KEY {
			// This LeaseSet's Destination's Certificate is a Key Certificate,
			// create the signing publickey key using any data that might be
			// contained in the key certificate.
			signing_public_key = KeyCertificate(cert).ConstructSigningPublicKey(lease_set[offset : offset+128])
		} else {
			// No Certificate is present, return the 128 byte
			// SigningPublicKey space as legacy DSA SHA1 SigningPublicKey.
			var dsa_pk crypto.DSAPublicKey
			copy(dsa_pk[:], lease_set[offset:offset+128])
			signing_public_key = dsa_pk
		}

	}
	return
}

func (lease_set LeaseSet) LeaseCount() (count int, err error) {
	_, remainder, err := ReadKeysAndCert(lease_set)
	if err != nil {
		return
	}
	if len(remainder) < 256+128+1 {
		err = errors.New("error parsing lease count: not enough data")
		return
	}
	count = Integer([]byte{remainder[256+128]})
	return
}

func (lease_set LeaseSet) Leases() (leases []Lease, err error) {
	destination, err := lease_set.Destination()
	if err != nil {
		return
	}
	offset := len(destination) + 256 + 128 + 1
	count, err := lease_set.LeaseCount()
	if err != nil {
		return
	}
	for i := 0; i < count; i++ {
		start := offset + (i * 44)
		end := start + 44
		if len(lease_set) < end {
			err = errors.New("")
			return
		}
		var lease Lease
		copy(lease[:], lease_set[start:end])
		leases = append(leases, lease)
	}
	return
}

func (lease_set LeaseSet) Signature() (signature Signature, err error) {
	destination, err := lease_set.Destination()
	if err != nil {
		return
	}
	lease_count, err := lease_set.LeaseCount()
	if err != nil {
		return
	}
	start := len(destination) + 256 + 128 + 1 + (44 * lease_count)
	cert, err := destination.Certificate()
	if err != nil {

	}
	cert_type, _ := cert.Type()
	var end int
	if cert_type == CERT_KEY {
		end = start + KeyCertificate(cert).SignatureSize()
	} else {
		end = start + 40
	}
	if len(lease_set) < end {
		err = errors.New("")
		return
	}
	copy(signature[:], lease_set[start:end])
	return
}

func (lease_set LeaseSet) Verify() error {
	//data_end := len(destination) +
	//	256 +
	//	128 +
	//	1 +
	//	(44 * lease_set.LeaseCount())
	//data := lease_set[:data_end]
	//spk, _ := lease_set.
	//	Destination().
	//	SigningPublicKey()
	//verifier, err := spk.NewVerifier()
	//if err != nil {
	//	return err
	//}
	return nil // verifier.Verify(data, lease_set.Signature())
}

func (lease_set LeaseSet) OldestExpiration() (date Date, err error) {
	return
}
