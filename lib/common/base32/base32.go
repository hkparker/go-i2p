//
// base32 encoding using i2p's alphabet
//
package base32

import (
  b32 "encoding/base32"
)

// i2p base32 encoding
var I2PEncoding *b32.Encoding = b32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567")
