package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIntegerBigEndian(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	integer := Integer(bytes)

	assert.Equal(integer, 1, "Integer() did not parse bytes big endian")
}

func TestWorksWithOneByte(t *testing.T) {
	assert := assert.New(t)

	integer := Integer([]byte{0x01})

	assert.Equal(integer, 1, "Integer() did not correctly parse single byte slice")
}

func TestIsZeroWithNoData(t *testing.T) {
	assert := assert.New(t)

	integer := Integer([]byte{})

	assert.Equal(integer, 0, "Integer() did not correctly parse zero length byte slice")
}
