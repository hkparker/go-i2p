//
// base64 encoding using I2P's alphabet
//
package base64

import (
	b64 "encoding/base64"
)

var I2PEncoding *b64.Encoding = b64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~")

//
// Return a go string of the I2P base64
// encoding of the provided byte slice
//
func EncodeToString(data []byte) string {
	return I2PEncoding.EncodeToString(data)
}
