//
// base64 encoding using I2P's alphabet
//
package base64

import (
	b64 "encoding/base64"
)

// i2p base64 alphabet
const Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~"

// i2p base64 encoding
var I2PEncoding *b64.Encoding = b64.NewEncoding(Alphabet)

//
// Return a go string of the I2P base64
// encoding of the provided byte slice
//
func EncodeToString(data []byte) string {
	return I2PEncoding.EncodeToString(data)
}

//
// decode string using i2p base64 encoding
// returns error if data is malfromed
//
func DecodeFromString(str string) (d []byte, err error) {
	return I2PEncoding.DecodeString(str)
}
