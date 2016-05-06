package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStringReportsCorrectLength(t *testing.T) {
	assert := assert.New(t)

	str_len, err := String([]byte{0x02, 0x00, 0x00}).Length()

	assert.Equal(str_len, 2, "Length() did not report correct length")
	assert.Nil(err, "Length() reported an error on valid string")
}

func TestStringReportsLengthZeroError(t *testing.T) {
	assert := assert.New(t)

	str_len, err := String(make([]byte, 0)).Length()

	assert.Equal(str_len, 0, "Length() reported non-zero length on empty slice")
	if assert.NotNil(err) {
		assert.Equal(err.Error(), "error parsing string: zero length", "correct error message should be returned")
	}
}

func TestStringReportsExtraDataError(t *testing.T) {
	assert := assert.New(t)

	str_len, err := String([]byte{0x01, 0x00, 0x00}).Length()

	assert.Equal(str_len, 1, "Length() reported wrong size when extra data present")
	if assert.NotNil(err) {
		assert.Equal(err.Error(), "string parsing warning: string contains data beyond length", "correct error message should be returned")
	}
}

func TestStringDataReportsLengthZeroError(t *testing.T) {
	assert := assert.New(t)

	str_len, err := String([]byte{0x01}).Length()

	assert.Equal(str_len, 1, "Length() reported wrong size with missing data")
	if assert.NotNil(err) {
		assert.Equal(err.Error(), "string parsing warning: string data is shorter than specified by length", "correct error message should be returned")
	}
}

func TestStringDataReportsExtraDataError(t *testing.T) {
	assert := assert.New(t)

	data, err := String([]byte{0x01, 0x00, 0x01}).Data()
	data_len := len(data)

	assert.Equal(data_len, 1, "Data() reported wrong size on string with extra data")
	if assert.NotNil(err) {
		assert.Equal(err.Error(), "string parsing warning: string contains data beyond length", "correct error message should be returned")
	}
}

func TestStringDataEmptyWhenZeroLength(t *testing.T) {
	assert := assert.New(t)

	data, err := String(make([]byte, 0)).Data()

	assert.Equal(len(data), 0, "Data() returned data when none was present:")
	if assert.NotNil(err) {
		assert.Equal(err.Error(), "error parsing string: zero length", "correct error message should be returned")
	}
}

func TestStringDataErrorWhenNonZeroLengthOnly(t *testing.T) {
	assert := assert.New(t)

	data, err := String([]byte{0x01}).Data()

	assert.Equal(len(data), 0, "Data() returned data when only length was present")
	if assert.NotNil(err) {
		assert.Equal(err.Error(), "string parsing warning: string data is shorter than specified by length", "correct error message should be returned")
	}
}

func TestToI2PStringFormatsCorrectly(t *testing.T) {
	assert := assert.New(t)

	i2p_string, err := ToI2PString(string([]byte{0x08, 0x09}))

	assert.Nil(err, "ToI2PString() returned error on valid data")
	assert.Equal(2, int(i2p_string[0]), "ToI2PString() did not prepend the correct length")
	assert.Equal(8, int(i2p_string[1]), "ToI2PString() did not include string")
	assert.Equal(9, int(i2p_string[2]), "ToI2PString() did not include string")
}

func TestToI2PStringReportsOverflows(t *testing.T) {
	assert := assert.New(t)

	i2p_string, err := ToI2PString(string(make([]byte, 256)))

	assert.Equal(len(i2p_string), 0, "ToI2PString() returned data when overflowed")
	if assert.NotNil(err) {
		assert.Equal(err.Error(), "cannot store that much data in I2P string", "correct error message should be returned")
	}

	_, err = ToI2PString(string(make([]byte, 255)))

	assert.Nil(err, "ToI2PString() reported error with acceptable size")
}

func TestReadStringReadsLength(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x01, 0x04, 0x06}
	str, remainder, err := ReadString(bytes)

	assert.Nil(err, "ReadString() returned error reading string with extra data")
	assert.Equal(len(str), 2, "ReadString() did not return correct string length")
	assert.Equal(1, int(str[0]), "ReadString() did not return correct string")
	assert.Equal(4, int(str[1]), "ReadString() did not return correct string")
	assert.Equal(len(remainder), 1, "ReadString() did not return correct remainder length")
	assert.Equal(6, int(remainder[0]), "ReadString() did not return correct remainder")
}

func TestReadStringErrWhenEmptySlice(t *testing.T) {
	assert := assert.New(t)

	bytes := make([]byte, 0)
	_, _, err := ReadString(bytes)

	if assert.NotNil(err) {
		assert.Equal(err.Error(), "error parsing string: zero length", "correct error message should be returned")
	}
}

func TestReadStringErrWhenDataTooShort(t *testing.T) {
	assert := assert.New(t)

	short_str := []byte{0x03, 0x01}
	str, remainder, err := ReadString(short_str)

	if assert.NotNil(err) {
		assert.Equal(err.Error(), "string parsing warning: string data is shorter than specified by length", "correct error message should be returned")
	}
	assert.Equal(len(str), 2, "ReadString() did not return the slice as string when too long")
	assert.Equal(3, int(str[0]), "ReadString() did not return the correct partial string")
	assert.Equal(1, int(str[1]), "ReadString() did not return the correct partial string")
	assert.Equal(len(remainder), 0, "ReadString() returned a remainder when the string data was too short")
}
