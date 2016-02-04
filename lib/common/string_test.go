package common

import "testing"

func TestReadStringReadsLength(t *testing.T) {
	bytes := []byte{0x01, 0x04, 0x06}
	str, remainder, err := ReadString(bytes)
	if err != nil {
		t.Fatal("ReadString() returner error,", err)
	}
	if len(str) != 1 {
		t.Fatal("ReadString() did not return correct string length:", len(str))
	}
	if str[0] != 0x04 {
		t.Fatal("ReadString() did not return correct string")
	}
	if len(remainder) != 1 {
		t.Fatal("ReadString() did not return correct remainder length")
	}
	if remainder[0] != 0x06 {
		t.Fatal("ReadString() did not return correct remainder")
	}
}

func TestReadStringErrWhenEmptySlice(t *testing.T) {
	bytes := make([]byte, 0)
	_, _, err := ReadString(bytes)
	if err != nil && err.Error() != "no string in empty byte slice" {
		t.Fatal("ReadString() did not report empty slice error", err)
	}
}

func TestReadStringErrWhenStringTooLong(t *testing.T) {
	bytes := []byte{0x03, 0x01}
	str, remainder, err := ReadString(bytes)
	if err != nil && err.Error() != "string longer than provided slice" {
		t.Fatal("ReadString() did not report string too long", err)
	}
	if len(str) != 1 {
		t.Fatal("ReadString() did not return the slice as string when too long")
	}
	if str[0] != 0x01 {
		t.Fatal("ReadString() did not return the correct partial string")
	}
	if len(remainder) != 0 {
		t.Fatal("ReadString() returned a remainder when the string was too long")
	}
}
