package tunnel

import (
	"encoding/binary"
	"errors"
	log "github.com/Sirupsen/logrus"
	"github.com/hkparker/go-i2p/lib/common"
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
       Optional, present if delivery type is ROUTER, or TUNNEL
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

// Check if the delay bit is set.  This feature in unimplemented in the Java router.
func (delivery_instructions DeliveryInstructions) HasDelay() bool {
	/*
		 Check if the 4 bit of the Delivery Instructions
		 is set using binary AND operator to determine
		 if the Delivery Instructions has a delay

		      xxx1xxxx	      xxx0xxxx
		     &00010000	     &00010000
		     ---------	     ---------
		      00010000	      00000000

		  bit is set,		bit is not set,
		  delay is included     no delay included

		Delay is unimplemented in the Java router, a warning
		is logged as this is interesting behavior.
	*/
	delay := (delivery_instructions[0] & 0x10) == 0x10
	if delay {
		log.WithFields(log.Fields{
			"at":   "(DeliveryInstructions) HasDelay",
			"info": "this feature is unimplemented in the Java router",
		}).Warn("DeliveryInstructions found with delay bit set")
	}
	return delay
}

// Returns true if the Delivery Instructions are fragmented or false
// if the following data contains the entire message
func (delivery_instructions DeliveryInstructions) Fragmented() bool {
	/*
	 Check if the 3 bit of the Delivery Instructions
	 is set using binary AND operator to determine
	 if the Delivery Instructions is fragmented or if
	 the entire message is contained in the following data

	      xxxx1xxx	      xxxx0xxx
	     &00001000	     &00001000
	     ---------	     ---------
	      00001000	      00000000

	  bit is set,		bit is not set,
	  message is		message is not
	  fragmented		fragmented
	*/
	return (delivery_instructions[0] & 0x08) == 0x08
}

// Check if the extended options bit is set.  This feature in unimplemented in the Java router.
func (delivery_instructions DeliveryInstructions) HasExtendedOptions() bool {
	/*
		 Check if the 2 bit of the Delivery Instructions
		 is set using binary AND operator to determine
		 if the Delivery Instructions has a extended options

		      xxxxx1xx	      xxxxx0xx
		     &00000100	     &00000100
		     ---------	     ---------
		      00000100	      00000000

		  bit is set,		bit is not set,
		  extended options      extended options
		  included		not included

		Extended options is unimplemented in the Java router, a warning
		is logged as this is interesting behavior.
	*/
	extended_options := (delivery_instructions[0] & 0x04) == 0x04
	if extended_options {
		log.WithFields(log.Fields{
			"at":   "(DeliveryInstructions) ExtendedOptions",
			"info": "this feature is unimplemented in the Java router",
		}).Warn("DeliveryInstructions found with extended_options bit set")
	}
	return extended_options
}

// Return the tunnel ID in this DeliveryInstructions or 0 and an error if the
// DeliveryInstructions are not of type DT_TUNNEL.
func (delivery_instructions DeliveryInstructions) TunnelID() (tunnel_id uint32, err error) {
	if delivery_instructions.DeliveryType() == DT_TUNNEL {
		tunnel_id = binary.BigEndian.Uint32(delivery_instructions[1:5])
	} else {
		err = errors.New("DeliveryInstructions are not of type DT_TUNNEL")
	}
	return
}

// Return the hash for these DeliveryInstructions, which varies by hash type.
//  If the type is DT_TUNNEL, hash is the SHA256 of the gateway router, if
//  the type is DT_ROUTER it is the SHA256 of the router.
func (delivery_instructions DeliveryInstructions) ToHash() (hash common.Hash, err error) {
	// TODO(hayden): check length of delivery instructions
	delivery_type := delivery_instructions.DeliveryType()
	if delivery_type == DT_TUNNEL {
		copy(hash[:], delivery_instructions[1+4:33+4]) // 4 bytes for DT_TUNNEL's TunnelID
	} else if delivery_type == DT_ROUTER {
		copy(hash[:], delivery_instructions[1:33])
	} else {
		err = errors.New("No Hash on DeliveryInstructions not of type DT_TUNNEL or DT_ROUTER")
	}
	return
}

// get the delay factor if it exists
func (delivery_instructions DeliveryInstructions) Delay() (d DelayFactor) {
	if delivery_instructions.HasDelay() {
		t := delivery_instructions.DeliveryType()
		if t == DT_TUNNEL {
			d = DelayFactor(delivery_instructions[37])
		} else if t == DT_ROUTER {
			d = DelayFactor(delivery_instructions[36])
		}
	}
	return
}

// get the i2np message id or 0 if not applicable
func (delivery_instructions DeliveryInstructions) MessageID() (msgid uint32) {
	if delivery_instructions.Type() == FOLLOW_ON_FRAGMENT {
		idx := 1
		t := delivery_instructions.DeliveryType()
		if t == DT_TUNNEL {
			idx += 36
		} else if t == DT_ROUTER {
			idx += 32
		}
		if delivery_instructions.HasDelay() {
			idx++
		}
		msgid = binary.BigEndian.Uint32(delivery_instructions[idx:])
	}
	return
}

// get the size of the associated i2np fragment
func (delivery_instructions DeliveryInstructions) FragmentSize() uint16 {
	idx := 5
	t := delivery_instructions.DeliveryType()
	if t == DT_TUNNEL {
		idx += 36
	} else if t == DT_ROUTER {
		idx += 32
	}
	if delivery_instructions.HasDelay() {
		idx++
	}
	if delivery_instructions.HasExtendedOptions() {
		// add extended options length to idx
	}
	return binary.BigEndian.Uint16(delivery_instructions[idx:])
}

func readDeliveryInstructions(data []byte) (instructions DeliveryInstructions, remainder []byte, err error) {
	return
}
