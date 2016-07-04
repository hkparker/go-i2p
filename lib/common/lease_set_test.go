package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func buildDestination() RouterIdentity {
	router_ident_data := make([]byte, 128+256)
	router_ident_data = append(router_ident_data, []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}...)
	return RouterIdentity(router_ident_data)
}

func buildPublicKey() []byte {
	return make([]byte, 256)
}

func buildSigningKey() []byte {
	return make([]byte, 128)
}

func buildLease(n int) []byte {
	return make([]byte, LEASE_SIZE*n)
}

func buildSignature() []byte {
	return make([]byte, 40)
}

func buildFullLeaseSet(n int) LeaseSet {
	lease_set_data := make([]byte, 0)
	lease_set_data = append(lease_set_data, buildDestination()...)
	lease_set_data = append(lease_set_data, buildPublicKey()...)
	lease_set_data = append(lease_set_data, buildSigningKey()...)
	lease_set_data = append(lease_set_data, byte(n))
	lease_set_data = append(lease_set_data, buildLease(n)...)
	lease_set_data = append(lease_set_data, buildSignature()...)
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

// TestPublicKey

// TestSigningKey

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

// TestLeases

// TestSignature

//TestOldestExpiration
