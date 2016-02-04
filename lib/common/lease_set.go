package common

import (
	"github.com/bounce-chat/go-i2p/lib/crypto"
)

type LeaseSet []byte

func (lease_set LeaseSet) Destination() Destination {
	return Destination(lease_set[:387])
}

func (lease_set LeaseSet) EncryptionKey() (k crypto.ElgPublicKey) {
	copy(lease_set[387:387+256], k[:])
	return
}

func (lease_set LeaseSet) SigningKey() (k []byte) {
	size := lease_set.signingKeySize()
	head := 387 + 256
	copy(lease_set[head:head+size], k)
	return
}

func (lease_set LeaseSet) LeaseCount() int {
	head := 387 + 256 + lease_set.signingKeySize()
	return Integer(lease_set[head+1])
}

func (lease_set LeaseSet) Leases() []Lease {
	leases := make([]Lease, 0)
	offset := 387 + 256 + lease_set.signingKeySize() + 1
	for i := 0; i < lease_set.LeaseCount(); i++ {
		start := offset + (i * LEASE_SIZE)
		end := offset + (start + LEASE_SIZE)
		var lease Lease
		copy(lease_set[start:end], lease[:])
		leases = append(leases, lease)
	}
	return leases
}

func (lease_set LeaseSet) Signature() []byte {
	data_end := 387 +
		256 +
		lease_set.signingKeySize() +
		1 +
		(LEASE_SIZE * lease_set.LeaseCount())
	sig_size := lease_set.
		Destination().
		Certificate().
		signatureSize()
	return lease_set[data_end : data_end+sig_size]
}

func (lease_set LeaseSet) Verify() error {
	data_end := 387 +
		256 +
		lease_set.signingKeySize() +
		1 +
		(LEASE_SIZE * lease_set.LeaseCount())
	data := lease_set[:data_end]
	verifier, err := lease_set.
		Destination().
		SigningPublicKey().
		NewVerifier()
	if err != nil {
		return err
	}
	return verifier.Verify(data, lease_set.Signature())
}

func (lease_set LeaseSet) signingKeySize() int {
	return lease_set.
		Destination().
		SigningPublicKey().
		Len()
}
