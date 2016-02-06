//
// base32 encoding using I2P's alphabet
//
package base32

import (
	b32 "encoding/base32"
)

var I2PEncoding *b32.Encoding = b32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567")

//
// Return a go string of the I2P base32
// encoding of the provided byte slice
//
func EncodeToString(data []byte) string {
	return I2PEncoding.EncodeToString(data)
}
