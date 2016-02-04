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

}

func TestReadStringErrWhenStringTooLong(t *testing.T) {

}
