package i2np

import (
	"github.com/hkparker/go-i2p/lib/common"
	"github.com/hkparker/go-i2p/lib/tunnel"
)

/*
I2P I2NP BuildRequestRecord
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

ElGamal and AES encrypted:

+----+----+----+----+----+----+----+----+
| encrypted data...                     |
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+

encrypted_data :: ElGamal and AES encrypted data
                  length -> 528

total length: 528

ElGamal encrypted:

+----+----+----+----+----+----+----+----+
| toPeer                                |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
| encrypted data...                     |
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+

toPeer :: First 16 bytes of the SHA-256 Hash of the peer's RouterIdentity
          length -> 16 bytes

encrypted_data :: ElGamal-2048 encrypted data (see notes)
                  length -> 512

total length: 528

Cleartext:

+----+----+----+----+----+----+----+----+
| receive_tunnel    | our_ident         |
+----+----+----+----+                   +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+                   +----+----+----+----+
|                   | next_tunnel       |
+----+----+----+----+----+----+----+----+
| next_ident                            |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
| layer_key                             |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
| iv_key                                |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
| reply_key                             |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
| reply_iv                              |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
|flag| request_time      | send_msg_id
+----+----+----+----+----+----+----+----+
     |                                  |
+----+                                  +
|         29 bytes padding              |
+                                       +
|                                       |
+                             +----+----+
|                             |
+----+----+----+----+----+----+

receive_tunnel :: TunnelId
                  length -> 4 bytes

our_ident :: Hash
             length -> 32 bytes

next_tunnel :: TunnelId
               length -> 4 bytes

next_ident :: Hash
              length -> 32 bytes

layer_key :: SessionKey
             length -> 32 bytes

iv_key :: SessionKey
          length -> 32 bytes

reply_key :: SessionKey
             length -> 32 bytes

reply_iv :: data
            length -> 16 bytes

flag :: Integer
        length -> 1 byte

request_time :: Integer
                length -> 4 bytes
                Hours since the epoch, i.e. current time / 3600

send_message_id :: Integer
                   length -> 4 bytes

padding :: Data
           length -> 29 bytes
           source -> random

total length: 222
*/

type BuildRequestRecordELGamalAES [528]byte
type BuildRequestRecordELGamal [528]byte

type BuildRequestRecord struct {
	ReceiveTunnel tunnel.TunnelID
	OurIdent      common.Hash
	NextTunnel    tunnel.TunnelID
	NextIdent     common.Hash
	LayerKey      common.SessionKey
	IVKey         common.SessionKey
	ReplyKey      common.SessionKey
	ReplyIV       [16]byte
	flag          int
	RequestTime   int
	SendMessageID int
	Padding       [29]byte
}
