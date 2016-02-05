package common

import "testing"

func TestStringReportsCorrectLength(t *testing.T) {
	str_len, err := String([]byte{0x02, 0x00, 0x00}).Length()
	if str_len != 2 {
		t.Fatal("string.Length() did not report correct length")
	}
	if err != nil {
		t.Fatal("string.Length() reported an error on valid string:", err)
	}
}

func TestStringReportsLengthZeroError(t *testing.T) {
	str_len, err := String(make([]byte, 0)).Length()
	if str_len != 0 {
		t.Fatal("string.Length() reported non-zero length on empty slice")
	}
	if err == nil || err.Error() != "error parsing string: zero length" {
		t.Fatal("string.Length() reported incorrect error on zero length slice:", err)
	}
}

func TestStringReportsExtraDataError(t *testing.T) {
	str_len, err := String([]byte{0x01, 0x00, 0x00}).Length()
	if str_len != 1 {
		t.Fatal("string.Length() reported wrong size when extra data present")
	}
	if err == nil || err.Error() != "string parsing warning: string contains data beyond length" {
		t.Fatal("string.Length() reported incorrect error on extra data:", err)
	}
}

func TestStringDataReportsLengthZeroError(t *testing.T) {
	str_len, err := String([]byte{0x01}).Length()
	if str_len != 1 {
		t.Fatal("string.Length() reported wring length with missing data", str_len)
	}
	if err == nil || err.Error() != "string parsing warning: string data is shorter than specified by length" {
		t.Fatal("string.Length() reported wrong error when data was missing", err)
	}
}

func TestStringDataReportsExtraDataError(t *testing.T) {
	data, err := String([]byte{0x01, 0x00, 0x01}).Data()
	data_len := len(data)
	if data_len != 1 {
		t.Fatal("string.Data() returned wrong size data for length with extra data:", data_len)
	}
	if err == nil || err.Error() != "string parsing warning: string contains data beyond length" {
		t.Fatal("string.Length() reported wrong error with extra data", err)
	}
}

func TestStringDataEmptyWhenZeroLength(t *testing.T) {
	data, err := String(make([]byte, 0)).Data()
	data_len := len(data)
	if data_len != 0 {
		t.Fatal("string.Data() returned data when none was present:", data_len)
	}
	if err == nil || err.Error() != "error parsing string: zero length" {
		t.Fatal("string.Length() reported wrong error with no data", err)
	}
}

func TestStringDataErrorWhenNonZeroLengthOnly(t *testing.T) {
	data, err := String([]byte{0x01}).Data()
	data_len := len(data)
	if data_len != 0 {
		t.Fatal("string.Data() returned data when only length was present:", data_len)
	}
	if err == nil || err.Error() != "string parsing warning: string data is shorter than specified by length" {
		t.Fatal("string.Length() reported wrong error with length but no data", err)
	}
}

func TestToI2PStringFormatsCorrectly(t *testing.T) {
	i2p_string, err := ToI2PString([]byte{0x22, 0x33})
	if err != nil {
		t.Fatal("ToI2PString() returned error on valid data:", err)
	}
	if i2p_string[0] != 0x02 {
		t.Fatal("ToI2PString() did not prepend the correct length")
	}
	if i2p_string[1] != 0x22 && i2p_string[2] != 0x33 {
		t.Fatal("ToI2PString() did not preserve string")
	}
}

func TestToI2PStringReportsOverflows(t *testing.T) {
	i2p_string, err := ToI2PString(make([]byte, 256))
	if len(i2p_string) != 0 {
		t.Fatal("ToI2PString() returned data when overflowed")
	}
	if err == nil || err.Error() != "cannot store that much data in I2P string" {
		t.Fatal("ToI2pString() did not report overflow")
	}
	_, err = ToI2PString(make([]byte, 255))
	if err != nil {
		t.Fatal("ToI2PString() reported error with acceptable size:", err)
	}
}

func TestReadStringReadsLength(t *testing.T) {
	bytes := []byte{0x01, 0x04, 0x06}
	str, remainder, err := ReadString(bytes)
	if err == nil || err.Error() != "string parsing warning: string contains data beyond length" {
		t.Fatal("ReadString(t *testing.T) returned incorrect error,", err)
	}
	if len(str) != 2 {
		t.Fatal("ReadString(t *testing.T) did not return correct string length:", len(str))
	}
	if str[0] != 0x01 && str[1] != 0x04 {
		t.Fatal("ReadString(t *testing.T) did not return correct string")
	}
	if len(remainder) != 1 {
		t.Fatal("ReadString(t *testing.T) did not return correct remainder length")
	}
	if remainder[0] != 0x06 {
		t.Fatal("ReadString(t *testing.T) did not return correct remainder")
	}
}

func TestReadStringErrWhenEmptySlice(t *testing.T) {
	bytes := make([]byte, 0)
	_, _, err := ReadString(bytes)
	if err != nil && err.Error() != "error parsing string: zero length" {
		t.Fatal("ReadString(t *testing.T) did not report empty slice error", err)
	}
}

func TestReadStringErrWhenDataTooShort(t *testing.T) {
	bytes := []byte{0x03, 0x01}
	str, remainder, err := ReadString(bytes)
	if err != nil && err.Error() != "string parsing warning: string data is shorter than specified by length" {
		t.Fatal("ReadString(t *testing.T) did not report string too long", err)
	}
	if len(str) != 2 {
		t.Fatal("ReadString(t *testing.T) did not return the slice as string when too long")
	}
	if str[0] != 0x03 && str[1] != 0x01 {
		t.Fatal("ReadString(t *testing.T) did not return the correct partial string")
	}
	if len(remainder) != 0 {
		t.Fatal("ReadString(t *testing.T) returned a remainder when the string data was too short")
	}
}
