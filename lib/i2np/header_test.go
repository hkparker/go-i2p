package i2np

import (
	"github.com/hkparker/go-i2p/lib/common"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestReadI2NPTypeWithNoData(t *testing.T) {
	assert := assert.New(t)

	mtype, err := ReadI2NPType([]byte{})
	assert.Equal(0, mtype)
	assert.Equal(ERR_I2NP_NOT_ENOUGH_DATA, err)
}

func TestReadI2NPTypeWithValidData(t *testing.T) {
	assert := assert.New(t)

	mtype, err := ReadI2NPType([]byte{0x01})
	assert.Equal(1, mtype)
	assert.Nil(err)
}

func TestReadI2NPNTCPMessageIDWithMissingData(t *testing.T) {
	assert := assert.New(t)

	mid, err := ReadI2NPNTCPMessageID([]byte{0x00, 0x00, 0x00, 0x00})
	assert.Equal(0, mid)
	assert.Equal(ERR_I2NP_NOT_ENOUGH_DATA, err)
}

func TestReadI2NPNTCPMessageIDWithValidData(t *testing.T) {
	assert := assert.New(t)

	mid, err := ReadI2NPNTCPMessageID([]byte{0x01, 0x00, 0x00, 0x00, 0x01})
	assert.Equal(1, mid)
	assert.Nil(err)
}

func TestReadI2NPNTCPMessageExpirationWithMissingData(t *testing.T) {
	assert := assert.New(t)

	date, err := ReadI2NPNTCPMessageExpiration([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	assert.Equal(common.Date{}, date)
	assert.Equal(ERR_I2NP_NOT_ENOUGH_DATA, err)
}

func TestReadI2NPNTCPMessageExpirationWithValidData(t *testing.T) {
	assert := assert.New(t)

	date, err := ReadI2NPNTCPMessageExpiration([]byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5c, 0x00})
	assert.Equal(int64(86400), date.Time().Unix())
	assert.Nil(err)
}

func TestReadI2NPSSUMessageExpirationWithMissingData(t *testing.T) {
	assert := assert.New(t)

	date, err := ReadI2NPSSUMessageExpiration([]byte{0x00, 0x00, 0x00, 0x00})
	assert.Equal(common.Date{}, date)
	assert.Equal(ERR_I2NP_NOT_ENOUGH_DATA, err)
}

func TestReadI2NPSSUMessageExpirationWithValidData(t *testing.T) {
	assert := assert.New(t)

	date, err := ReadI2NPSSUMessageExpiration([]byte{0x01, 0x05, 0x26, 0x5c, 0x00})
	assert.Equal(int64(86400), date.Time().Unix())
	assert.Nil(err)
}

func TestReadI2NPNTCPMessageSizeWithMissingData(t *testing.T) {
	assert := assert.New(t)

	size, err := ReadI2NPNTCPMessageSize([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	assert.Equal(0, size)
	assert.Equal(ERR_I2NP_NOT_ENOUGH_DATA, err)
}

func TestReadI2NPNTCPMessageSizeWithValidData(t *testing.T) {
	assert := assert.New(t)

	size, err := ReadI2NPNTCPMessageSize([]byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5c, 0x00, 0x00, 0x01})
	assert.Equal(1, size)
	assert.Nil(err)
}

func TestReadI2NPNTCPMessageChecksumWithMissingData(t *testing.T) {
	assert := assert.New(t)

	checksum, err := ReadI2NPNTCPMessageChecksum([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	assert.Equal(0, checksum)
	assert.Equal(ERR_I2NP_NOT_ENOUGH_DATA, err)
}

func TestReadI2NPNTCPMessageChecksumWithValidData(t *testing.T) {
	assert := assert.New(t)

	checksum, err := ReadI2NPNTCPMessageChecksum([]byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5c, 0x00, 0x00, 0x01, 0x01})
	assert.Equal(1, checksum)
	assert.Nil(err)
}

func TestReadI2NPNTCPDataWithNoData(t *testing.T) {
	assert := assert.New(t)

	data, err := ReadI2NPNTCPData([]byte{}, 3)
	assert.Equal([]byte{}, data)
	assert.Equal(ERR_I2NP_NOT_ENOUGH_DATA, err)
}

func TestReadI2NPNTCPDataWithMissingData(t *testing.T) {
	assert := assert.New(t)

	data, err := ReadI2NPNTCPData([]byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5c, 0x00, 0x00, 0x03, 0x01, 0x01, 0x02}, 3)
	assert.Equal([]byte{}, data)
	assert.Equal(ERR_I2NP_NOT_ENOUGH_DATA, err)
}

func TestReadI2NPNTCPDataWithExtraData(t *testing.T) {
	assert := assert.New(t)

	data, err := ReadI2NPNTCPData([]byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5c, 0x00, 0x00, 0x03, 0x01, 0x01, 0x02, 0x03, 0x04}, 3)
	assert.Equal([]byte{0x01, 0x02, 0x03}, data)
	assert.Nil(err)
}

func TestReadI2NPNTCPDataWithValidData(t *testing.T) {
	assert := assert.New(t)

	data, err := ReadI2NPNTCPData([]byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5c, 0x00, 0x00, 0x03, 0x01, 0x01, 0x02, 0x03}, 3)
	assert.Equal([]byte{0x01, 0x02, 0x03}, data)
	assert.Nil(err)
}

func TestCrasherRegression123781(t *testing.T) {
	ReadI2NPNTCPHeader([]byte{0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x30})
}
