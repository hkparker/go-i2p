package i2np

import (
	"github.com/hkparker/go-i2p/lib/common"
	"github.com/hkparker/go-i2p/lib/tunnel"
)

/*
I2P I2NP GarlicCloveDeliveryInstructions
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

+----+----+----+----+----+----+----+----+
|flag|                                  |
+----+                                  +
|                                       |
+       Session Key (optional)          +
|                                       |
+                                       +
|                                       |
+    +----+----+----+----+--------------+
|    |                                  |
+----+                                  +
|                                       |
+         To Hash (optional)            +
|                                       |
+                                       +
|                                       |
+    +----+----+----+----+--------------+
|    |  Tunnel ID (opt)  |  Delay (opt)
+----+----+----+----+----+----+----+----+
     |
+----+

flag ::
       1 byte
       Bit order: 76543210
       bit 7: encrypted? Unimplemented, always 0
                If 1, a 32-byte encryption session key is included
       bits 6-5: delivery type
                0x0 = LOCAL, 0x01 = DESTINATION, 0x02 = ROUTER, 0x03 = TUNNEL
       bit 4: delay included?  Not fully implemented, always 0
                If 1, four delay bytes are included
       bits 3-0: reserved, set to 0 for compatibility with future uses

Session Key ::
       32 bytes
       Optional, present if encrypt flag bit is set.
       Unimplemented, never set, never present.

To Hash ::
       32 bytes
       Optional, present if delivery type is DESTINATION, ROUTER, or TUNNEL
          If DESTINATION, the SHA256 Hash of the destination
          If ROUTER, the SHA256 Hash of the router
          If TUNNEL, the SHA256 Hash of the gateway router

Tunnel ID :: TunnelId
       4 bytes
       Optional, present if delivery type is TUNNEL
       The destination tunnel ID

Delay :: Integer
       4 bytes
       Optional, present if delay included flag is set
       Not fully implemented. Specifies the delay in seconds.

Total length: Typical length is:
       1 byte for LOCAL delivery;
       33 bytes for ROUTER / DESTINATION delivery;
       37 bytes for TUNNEL delivery
*/

type GarlicCloveDeliveryInstructions struct {
	Flag       byte
	SessionKey common.SessionKey
	Hash       common.Hash
	TunnelID   tunnel.TunnelID
	Delay      int
}
