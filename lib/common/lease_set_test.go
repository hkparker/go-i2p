package common

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func buildDestination() RouterIdentity {
	router_ident_data := make([]byte, 128+256)
	router_ident_data = append(router_ident_data, []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}...)
	return RouterIdentity(router_ident_data)
}

func buildPublicKey() []byte {
	pk := make([]byte, 256)
	for i := range pk {
		pk[i] = 0x01
	}
	return pk
}

func buildSigningKey() []byte {
	sk := make([]byte, 128)
	for i := range sk {
		sk[i] = 0x02
	}
	return sk
}

func buildLease(n int) []byte {
	data := make([]byte, 0)
	for i := 0; i < n; i++ {
		lease := make([]byte, LEASE_SIZE)
		for p := range lease {
			lease[p] = byte(i)
		}
		for q := LEASE_SIZE - 9; q < LEASE_SIZE-1; q++ {
			lease[q] = 0x00
		}
		lease[LEASE_SIZE-1] = byte(i + 10)
		data = append(data, lease...)
	}
	return data
}

func buildSignature(size int) []byte {
	sig := make([]byte, size)
	for i := range sig {
		sig[i] = 0x08
	}
	return sig
}

func buildFullLeaseSet(n int) LeaseSet {
	lease_set_data := make([]byte, 0)
	lease_set_data = append(lease_set_data, buildDestination()...)
	lease_set_data = append(lease_set_data, buildPublicKey()...)
	lease_set_data = append(lease_set_data, buildSigningKey()...)
	lease_set_data = append(lease_set_data, byte(n))
	lease_set_data = append(lease_set_data, buildLease(n)...)
	lease_set_data = append(lease_set_data, buildSignature(64)...)
	return LeaseSet(lease_set_data)
}

func TestDestinationIsCorrect(t *testing.T) {
	assert := assert.New(t)

	lease_set := buildFullLeaseSet(1)
	dest, err := lease_set.Destination()
	assert.Nil(err)
	dest_cert, err := dest.Certificate()
	assert.Nil(err)
	cert_type, err := dest_cert.Type()
	assert.Nil(err)
	assert.Equal(CERT_KEY, cert_type)
}

func TestPublicKeyIsCorrect(t *testing.T) {
	assert := assert.New(t)

	lease_set := buildFullLeaseSet(1)
	pk, err := lease_set.PublicKey()
	if assert.Nil(err) {
		assert.Equal(
			0,
			bytes.Compare(
				[]byte(buildPublicKey()),
				pk[:],
			),
		)
	}
}

func TestSigningKeyIsCorrect(t *testing.T) {
	assert := assert.New(t)

	lease_set := buildFullLeaseSet(1)
	sk, err := lease_set.SigningKey()
	if assert.Nil(err) {
		assert.Equal(128, sk.Len())
	}
}

func TestLeaseCountCorrect(t *testing.T) {
	assert := assert.New(t)

	lease_set := buildFullLeaseSet(1)
	count, err := lease_set.LeaseCount()
	if assert.Nil(err) {
		assert.Equal(1, count)
	}
}

func TestLeaseCountCorrectWithMultiple(t *testing.T) {
	assert := assert.New(t)

	lease_set := buildFullLeaseSet(3)
	count, err := lease_set.LeaseCount()
	if assert.Nil(err) {
		assert.Equal(3, count)
	}
}

func TestLeaseCountErrorWithTooMany(t *testing.T) {
	assert := assert.New(t)

	lease_set := buildFullLeaseSet(17)
	count, err := lease_set.LeaseCount()
	if assert.NotNil(err) {
		assert.Equal("invalid lease set: more than 16 leases", err.Error())
	}
	assert.Equal(17, count)
}

func TestLeasesHaveCorrectData(t *testing.T) {
	assert := assert.New(t)

	lease_set := buildFullLeaseSet(3)
	count, err := lease_set.LeaseCount()
	if assert.Nil(err) && assert.Equal(3, count) {
		leases, err := lease_set.Leases()
		if assert.Nil(err) {
			for i := 0; i < count; i++ {
				lease := make([]byte, LEASE_SIZE)
				for p := range lease {
					lease[p] = byte(i)
				}
				for q := LEASE_SIZE - 9; q < LEASE_SIZE-1; q++ {
					lease[q] = 0x00
				}
				lease[LEASE_SIZE-1] = byte(i + 10)
				assert.Equal(
					0,
					bytes.Compare(
						lease,
						leases[i][:],
					),
				)
			}
		}
	}
}

func TestSignatureIsCorrect(t *testing.T) {
	assert := assert.New(t)

	lease_set := buildFullLeaseSet(1)
	sig, err := lease_set.Signature()
	if assert.Nil(err) {
		assert.Equal(
			0,
			bytes.Compare(
				buildSignature(64),
				sig,
			),
		)
	}
}

func TestNewestExpirationIsCorrect(t *testing.T) {
	assert := assert.New(t)

	lease_set := buildFullLeaseSet(5)
	latest, err := lease_set.NewestExpiration()
	assert.Nil(err)
	assert.Equal(
		Date{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, byte(4 + 10)},
		latest,
	)
}

func TestOldestExpirationIsCorrect(t *testing.T) {
	assert := assert.New(t)

	lease_set := buildFullLeaseSet(5)
	latest, err := lease_set.OldestExpiration()
	assert.Nil(err)
	assert.Equal(
		Date{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a},
		latest,
	)
}
