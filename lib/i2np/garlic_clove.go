package i2np

import (
	"github.com/hkparker/go-i2p/lib/common"
	"time"
)

/*
I2P I2NP GarlicClove
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

Unencrypted:

+----+----+----+----+----+----+----+----+
| Delivery Instructions                 |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| I2NP Message                          |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|    Clove ID       |     Expiration
+----+----+----+----+----+----+----+----+
                    | Certificate  |
+----+----+----+----+----+----+----+

Delivery Instructions :: as defined below
       Length varies but is typically 1, 33, or 37 bytes

I2NP Message :: Any I2NP Message

Clove ID :: 4 byte Integer

Expiration :: Date (8 bytes)

Certificate :: Always NULL in the current implementation (3 bytes total, all zeroes)
*/

type GarlicClove struct {
	DeliveryInstructions GarlicCloveDeliveryInstructions
	I2NPMessage          I2NPMessage
	CloveID              int
	Expiration           time.Time
	Certificate          common.Certificate
}
