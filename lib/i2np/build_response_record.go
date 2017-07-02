package i2np

import (
	"github.com/hkparker/go-i2p/lib/common"
)

/*
I2P I2NP BuildResponseRecord
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

Encrypted:

bytes 0-527 :: AES-encrypted record (note: same size as BuildRequestRecord)

Unencrypted:

+----+----+----+----+----+----+----+----+
|                                       |
+                                       +
|                                       |
+   SHA-256 Hash of following bytes     +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
| random data...                        |
~                                       ~
|                                       |
+                                  +----+
|                                  | ret|
+----+----+----+----+----+----+----+----+

bytes 0-31   :: SHA-256 Hash of bytes 32-527
bytes 32-526 :: random data
byte  527    :: reply

total length: 528
*/

type BuildResponseRecordELGamalAES [528]byte
type BuildResponseRecordELGamal [528]byte

type BuildResponseRecord struct {
	Hash    common.Hash
	Padding [495]byte
	Reply   byte
}
