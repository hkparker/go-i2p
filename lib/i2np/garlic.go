package i2np

import (
	"github.com/hkparker/go-i2p/lib/common"
	"time"
)

/*
I2P I2NP Garlic
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

Encrypted:

+----+----+----+----+----+----+----+----+
|      length       | data              |
+----+----+----+----+                   +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+

length ::
       4 byte Integer
       number of bytes that follow 0 - 64 KB

data ::
     $length bytes
     ElGamal encrypted data

Unencrypted data:

+----+----+----+----+----+----+----+----+
| num|  clove 1                         |
+----+                                  +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|         clove 2 ...                   |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| Certificate  |   Message_ID      |
+----+----+----+----+----+----+----+----+
          Expiration               |
+----+----+----+----+----+----+----+

num ::
     1 byte Integer number of GarlicCloves to follow

clove ::  a GarlicClove

Certificate :: always NULL in the current implementation (3 bytes total, all zeroes)

Message_ID :: 4 byte Integer

Expiration :: Date (8 bytes)
*/

type GarlicElGamal []byte

type Garlic struct {
	Count       int
	Cloves      []GarlicClove
	Certificate common.Certificate
	MessageID   int
	Expiration  time.Time
}
