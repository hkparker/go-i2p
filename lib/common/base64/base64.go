//
// base64 encoding with i2p's alphabet
//
package base64

import (
  b64 "encoding/base64"
)

// i2p base64 encoding
var I2PEncoding *b64.Encoding = b64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~")

// wrapper arround encoding for encoding to string
func EncodeToString(data []byte) (str string) {
  str = I2PEncoding.EncodeToString(data)
  return
}
