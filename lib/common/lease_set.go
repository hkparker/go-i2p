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
	// check if the destination has a cert, if its a key cert, etc
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

func (lease_set LeaseSet) Leases() []Lease {
	leases := make([]Lease, 0)
	offset := 0
	count, err := lease_set.LeaseCount()
	if err != nil {
		return leases
	}
	// read as many as possible, returning errors
	for i := 0; i < count; i++ {
		start := offset + (i * 44)
		end := offset + (start + 44)
		var lease Lease
		copy(lease[:], lease_set[start:end])
		leases = append(leases, lease)
	}
	return leases
}

func (lease_set LeaseSet) Signature() (signature Signature, err error) {
	return
}

func (lease_set LeaseSet) Verify() error {
	//data_end := 387 +
	//	256 +
	//	lease_set.signingKeySize() +
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
