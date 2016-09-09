package tunnel

import (
	"encoding/binary"
	log "github.com/Sirupsen/logrus"
	"github.com/hkparker/go-i2p/lib/crypto"
)

/*
I2P Encrypted Tunnel Message
https://geti2p.net/spec/tunnel-message
Accurate for version 0.9.11
+----+----+----+----+----+----+----+----+
|    Tunnel ID      |       IV          |
+----+----+----+----+                   +
|                                       |
+                   +----+----+----+----+
|                   |                   |
+----+----+----+----+                   +
|                                       |
+           Encrypted Data              +
~                                       ~
|                                       |
+                   +-------------------+
|                   |
+----+----+----+----+

Tunnel ID :: TunnelId
       4 bytes
       the ID of the next hop

IV ::
       16 bytes
       the initialization vector

Encrypted Data ::
       1008 bytes
       the encrypted tunnel message

total size: 1028 Bytes



I2P Decrypted Tunnel Message
https://geti2p.net/spec/tunnel-message
Accurate for version 0.9.11

+----+----+----+----+----+----+----+----+
|    Tunnel ID      |       IV          |
+----+----+----+----+                   +
|                                       |
+                   +----+----+----+----+
|                   |     Checksum      |
+----+----+----+----+----+----+----+----+
|          nonzero padding...           |
~                                       ~
|                                       |
+                                  +----+
|                                  |zero|
+----+----+----+----+----+----+----+----+
|                                       |
|       Delivery Instructions  1        |
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|                                       |
+       I2NP Message Fragment 1         +
|                                       |
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|                                       |
|       Delivery Instructions 2...      |
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|                                       |
+       I2NP Message Fragment 2...      +
|                                       |
~                                       ~
|                                       |
+                   +-------------------+
|                   |
+----+----+----+----+

Tunnel ID :: TunnelId
       4 bytes
       the ID of the next hop

IV ::
       16 bytes
       the initialization vector

Checksum ::
       4 bytes
       the first 4 bytes of the SHA256 hash of (the contents of the message
       (after the zero byte) + IV)

Nonzero padding ::
       0 or more bytes
       random nonzero data for padding

Zero ::
       1 byte
       the value 0x00

Delivery Instructions :: TunnelMessageDeliveryInstructions
       length varies but is typically 7, 39, 43, or 47 bytes
       Indicates the fragment and the routing for the fragment

Message Fragment ::
       1 to 996 bytes, actual maximum depends on delivery instruction size
       A partial or full I2NP Message

total size: 1028 Bytes
*/

type TunnelID uint32

type EncryptedTunnelMessage crypto.TunnelData

type DeliveryInstructionsWithFragment struct {
	DeliveryInstructions DeliveryInstructions
	MessageFragment      []byte
}

func (tm EncryptedTunnelMessage) ID() (tid TunnelID) {
	tid = TunnelID(binary.BigEndian.Uint32(tm[:4]))
	return
}

func (tm EncryptedTunnelMessage) IV() crypto.TunnelIV {
	return tm[4:20]
}

func (tm EncryptedTunnelMessage) Data() crypto.TunnelIV {
	return tm[24:]
}

type DecryptedTunnelMessage [1028]byte

func (decrypted_tunnel_message DecryptedTunnelMessage) ID() TunnelID {
	return TunnelID(binary.BigEndian.Uint32(
		decrypted_tunnel_message[:4],
	))
}

func (decrypted_tunnel_message DecryptedTunnelMessage) IV() crypto.TunnelIV {
	return decrypted_tunnel_message[4 : 4+16]
}

func (decrypted_tunnel_message DecryptedTunnelMessage) Checksum() crypto.TunnelIV {
	return decrypted_tunnel_message[4+16 : 4+4+16]
}

//
// Returns the contents of a decrypted tunnel message that contain the data for the
// DeliveryInstructions.
//
func (decrypted_tunnel_message DecryptedTunnelMessage) deliveryInstructionData() []byte {
	data_area := decrypted_tunnel_message[4+4+16:]
	for i := 0; i < len(data_area); i++ {
		if data_area[i] == 0x00 {
			return data_area[i+1:]
		}
	}
	return []byte{}
}

//
// Returns a slice of DeliveryInstructionWithFragment structures, which all of the Delivery Instructions
// in the tunnel message and their corresponding MessageFragment structures.
//
//
func (decrypted_tunnel_message DecryptedTunnelMessage) DeliveryInstructionsWithFragments() []DeliveryInstructionsWithFragment {
	set := make([]DeliveryInstructionsWithFragment, 0)
	data := decrypted_tunnel_message.deliveryInstructionData()
	for {
		instructions, remainder, err := readDeliveryInstructions(data)
		if err != nil {
			log.WithFields(log.Fields{
				"at":  "(DecryptedTunnelMessage) DeliveryInstructionsWithFragments",
				"err": err.Error(),
			}).Error("error reading delivery instructions")
			break
		}

		fragment_data := remainder[:instructions.FragmentSize()]
		pair := DeliveryInstructionsWithFragment{
			DeliveryInstructions: instructions,
			MessageFragment:      fragment_data,
		}

		data = remainder[instructions.FragmentSize():]
		set = append(set, pair)
	}
	return set
}
