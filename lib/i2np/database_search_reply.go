package i2np

import (
	"github.com/hkparker/go-i2p/lib/common"
)

/*
I2P I2NP DatabaseSearchReply
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

+----+----+----+----+----+----+----+----+
| SHA256 hash as query key              |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
| num| peer_hashes                      |
+----+                                  +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+    +----+----+----+----+----+----+----+
|    | from                             |
+----+                                  +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+    +----+----+----+----+----+----+----+
|    |
+----+

key ::
    32 bytes
    SHA256 of the object being searched

num ::
    1 byte Integer
    number of peer hashes that follow, 0-255

peer_hashes ::
          $num SHA256 hashes of 32 bytes each (total $num*32 bytes)
          SHA256 of the RouterIdentity that the other router thinks is close
          to the key

from ::
     32 bytes
     SHA256 of the RouterInfo of the router this reply was sent from
*/

type DatabaseSearchReply struct {
	Key        common.Hash
	Count      int
	PeerHashes []common.Hash
	From       common.Hash
}
