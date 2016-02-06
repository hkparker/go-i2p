package common

import (
	"testing"
)

func TestIntegerBigEndian(t *testing.T) {
	bytes := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	i := Integer(bytes)
	if i != 1 {
		t.Fatal("Integer() not big endian")
	}
}

func TestWorksWith1Byte(t *testing.T) {
	i := Integer([]byte{0x01})
	if i != 1 {
		t.Fatal("Integer() does not work with 1 byte")
	}
}
