package tunnel

import (
	"encoding/binary"
)

/*
I2P First Fragment Delivery Instructions
https://geti2p.net/spec/tunnel-message#struct-tunnelmessagedeliveryinstructions
Accurate for version 0.9.11

+----+----+----+----+----+----+----+----+
|flag|  Tunnel ID (opt)  |              |
+----+----+----+----+----+              +
|                                       |
+                                       +
|         To Hash (optional)            |
+                                       +
|                                       |
+                        +--------------+
|                        |dly | Message
+----+----+----+----+----+----+----+----+
 ID (opt) |extended opts (opt)|  size   |
+----+----+----+----+----+----+----+----+

flag ::
       1 byte
       Bit order: 76543210
       bit 7: 0 to specify an initial fragment or an unfragmented message
       bits 6-5: delivery type
                 0x0 = LOCAL
                 0x01 = TUNNEL
                 0x02 = ROUTER
                 0x03 = unused, invalid
                 Note: LOCAL is used for inbound tunnels only, unimplemented
                 for outbound tunnels
       bit 4: delay included?  Unimplemented, always 0
                               If 1, a delay byte is included
       bit 3: fragmented?  If 0, the message is not fragmented, what follows
                           is the entire message
                           If 1, the message is fragmented, and the
                           instructions contain a Message ID
       bit 2: extended options?  Unimplemented, always 0
                                 If 1, extended options are included
       bits 1-0: reserved, set to 0 for compatibility with future uses

Tunnel ID :: TunnelId
       4 bytes
       Optional, present if delivery type is TUNNEL
       The destination tunnel ID

To Hash ::
       32 bytes
       Optional, present if delivery type is DESTINATION, ROUTER, or TUNNEL
          If DESTINATION, the SHA256 Hash of the destination
          If ROUTER, the SHA256 Hash of the router
          If TUNNEL, the SHA256 Hash of the gateway router

Delay ::
       1 byte
       Optional, present if delay included flag is set
       In tunnel messages: Unimplemented, never present; original
       specification:
          bit 7: type (0 = strict, 1 = randomized)
          bits 6-0: delay exponent (2^value minutes)

Message ID ::
       4 bytes
       Optional, present if this message is the first of 2 or more fragments
          (i.e. if the fragmented bit is 1)
       An ID that uniquely identifies all fragments as belonging to a single
       message (the current implementation uses I2NPMessageHeader.msg_id)

Extended Options ::
       2 or more bytes
       Optional, present if extend options flag is set
       Unimplemented, never present; original specification:
       One byte length and then that many bytes

size ::
       2 bytes
       The length of the fragment that follows
       Valid values: 1 to approx. 960 in a tunnel message

Total length: Typical length is:
       3 bytes for LOCAL delivery (tunnel message);
       35 bytes for ROUTER / DESTINATION delivery or 39 bytes for TUNNEL
       delivery (unfragmented tunnel message);
       39 bytes for ROUTER delivery or 43 bytes for TUNNEL delivery (first
       fragment)



I2P Follow-on Fragment Delivery Instructions
https://geti2p.net/spec/tunnel-message#struct-tunnelmessagedeliveryinstructions
Accurate for version 0.9.11

----+----+----+----+----+----+----+
|frag|     Message ID    |  size   |
+----+----+----+----+----+----+----+

frag ::
       1 byte
       Bit order: 76543210
       binary 1nnnnnnd
              bit 7: 1 to indicate this is a follow-on fragment
              bits 6-1: nnnnnn is the 6 bit fragment number from 1 to 63
              bit 0: d is 1 to indicate the last fragment, 0 otherwise

Message ID ::
       4 bytes
       Identifies the fragment sequence that this fragment belongs to.
       This will match the message ID of an initial fragment (a fragment
       with flag bit 7 set to 0 and flag bit 3 set to 1).

size ::
       2 bytes
       the length of the fragment that follows
       valid values: 1 to 996

total length: 7 bytes
*/

const (
	DT_LOCAL = iota
	DT_TUNNEL
	DT_ROUTER
	DT_UNUSED
)

const (
	FIRST_FRAGMENT = iota
	FOLLOW_ON_FRAGMENT
)

type DelayFactor byte

type DeliveryInstructions []byte

// Return if the DeliveryInstructions are of type FIRST_FRAGMENT or FOLLOW_ON_FRAGMENT.
func (delivery_instructions DeliveryInstructions) Type() int {
	/*
	 Check if the 7 bit of the Delivery Instructions
	 is set using binary AND operator to determine
	 the Delivery Instructions type
	
	      1xxxxxxx	      0xxxxxxx
	     &10000000	     &10000000
	     ---------	     ---------
	      10000000	      00000000
	
	  bit is set,		bit is not set,
	  message is a		message is an
	  follow-on fragment	initial I2NP message
				fragment or a complete fragment
	*/
	if (delivery_instructions[0] & 0x08) == 0x08 {
		return FOLLOW_ON_FRAGMENT
	}
	return FIRST_FRAGMENT
}

// Return the delivery type for these DeliveryInstructions, can be of type
// DT_LOCAL, DT_TUNNEL, DT_ROUTER, or DT_UNUSED.
func (delivery_instructions DeliveryInstructions) DeliveryType() byte {
	/*
	 Check if the 6-5 bits of the Delivery Instructions
	 are set using binary AND operator to determine
	 the delivery type

	      xx0?xxxx
	     &00110000    bit shift
	     ---------	
	      000?0000       >> 4   =>   n	(DT_* consts)
	*/
	return (delivery_instructions[0] & 0x30) >> 4
}

// do we have a delay factor?
func (di DeliveryInstructions) HasDelay() bool {
	return (di[0] & 0x10) == 0x10
}


// get the tunnel id in this devilevery instrcutions or 0 if not applicable
func (di DeliveryInstructions) TunnelID() (tid uint32) {
	if di.DeliveryType() == DT_TUNNEL {
		// TODO(psi):  what if this is 0?
		tid = binary.BigEndian.Uint32(di[1:5])
	}
	return
}

// get the delay factor if it exists
func (di DeliveryInstructions) Delay() (d DelayFactor) {
	if di.HasDelay() {
		t := di.DeliveryType()
		if t == DT_TUNNEL {
			d = DelayFactor(di[37])
		} else if t == DT_ROUTER {
			d = DelayFactor(di[36])
		}
	}
	return
}

func (di DeliveryInstructions) HasExtendedOptions() bool {
	return (di[0] & 0x04) == 0x04
}

// get the to hash for these delivery instructions or nil if not applicable
func (di DeliveryInstructions) ToHash() (h []byte) {
	t := di.DeliveryType()
	if t == DT_TUNNEL {
		h = di[5:37]
	} else if t == DT_ROUTER || t == DT_LOCAL {
		h = di[4:36]
	}
	return
}

// get the i2np message id or 0 if not applicable
func (di DeliveryInstructions) MessageID() (msgid uint32) {
	if di.Type() == FOLLOW_ON_FRAGMENT {
		idx := 1
		t := di.DeliveryType()
		if t == DT_TUNNEL {
			idx += 36
		} else if t == DT_ROUTER {
			idx += 32
		}
		if di.HasDelay() {
			idx++
		}
		msgid = binary.BigEndian.Uint32(di[idx:])
	}
	return
}

// get the size of the associated i2np fragment
func (di DeliveryInstructions) FragmentSize() uint16 {
	idx := 5
	t := di.DeliveryType()
	if t == DT_TUNNEL {
		idx += 36
	} else if t == DT_ROUTER {
		idx += 32
	}
	if di.HasDelay() {
		idx++
	}
	if di.HasExtendedOptions() {
		// add extended options length to idx
	}
	return binary.BigEndian.Uint16(di[idx:])
}

func readDeliveryInstructions(data []byte) (instructions DeliveryInstructions, remainder []byte, err error) {
	return
}
