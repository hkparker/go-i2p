package i2np

import (
	"github.com/hkparker/go-i2p/lib/common"
)

/*
I2P I2NP DatabaseStore
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

with reply token:
+----+----+----+----+----+----+----+----+
| SHA256 Hash as key                    |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
|type| reply token       | reply_tunnelId
+----+----+----+----+----+----+----+----+
     | SHA256 of the gateway RouterInfo |
+----+                                  +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+    +----+----+----+----+----+----+----+
|    | data ...
+----+-//

with reply token == 0:
+----+----+----+----+----+----+----+----+
| SHA256 Hash as key                    |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
|type|         0         | data ...
+----+----+----+----+----+-//

key ::
    32 bytes
    SHA256 hash

type ::
     1 byte
     type identifier
     bit 0:
             0    RouterInfo
             1    LeaseSet
     bits 7-1:
            Through release 0.9.17, must be 0
            As of release 0.9.18, ignored, reserved for future options, set to 0 for compatibility

reply token ::
            4 bytes
            If greater than zero, a DeliveryStatusMessage
            is requested with the Message ID set to the value of the Reply Token.
            A floodfill router is also expected to flood the data to the closest floodfill peers
            if the token is greater than zero.

reply_tunnelId ::
               4 byte TunnelId
               Only included if reply token > 0
               This is the TunnelId of the inbound gateway of the tunnel the response should be sent to
               If $reply_tunnelId is zero, the reply is sent directy to the reply gateway router.

reply gateway ::
              32 bytes
              Hash of the RouterInfo entry to reach the gateway
              Only included if reply token > 0
              If $reply_tunnelId is nonzero, this is the router hash of the inbound gateway
              of the tunnel the response should be sent to.
              If $reply_tunnelId is zero, this is the router hash the response should be sent to.

data ::
     If type == 0, data is a 2-byte Integer specifying the number of bytes that follow,
                   followed by a gzip-compressed RouterInfo.
     If type == 1, data is an uncompressed LeaseSet.
*/

type DatabaseStore struct {
	Key           common.Hash
	Type          byte
	ReplyToken    [4]byte
	ReplyTunnelID [4]byte
	ReplyGateway  common.Hash
	Data          []byte
}
