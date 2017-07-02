package i2np

import (
	"github.com/hkparker/go-i2p/lib/tunnel"
)

/*
I2P I2NP TunnelGateway
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

+----+----+----+----+----+----+----+-//
| tunnelId          | length  | data...
+----+----+----+----+----+----+----+-//

tunnelId ::
         4 byte TunnelId
         identifies the tunnel this message is directed at

length ::
       2 byte Integer
       length of the payload

data ::
     $length bytes
     actual payload of this message
*/

type TunnelGatway struct {
	TunnelID tunnel.TunnelID
	Length   int
	Data     []byte
}
