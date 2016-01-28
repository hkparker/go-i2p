package tunnel

import(
  "encoding/binary"
)

const (
  DT_LOCAL = iota
  DT_TUNNEL
  DT_ROUTER
  DT_UNUSED
)

type DelayFactor byte

type DeliveryInstructions []byte


func (di DeliveryInstructions) DeliveryType() byte {
  return (di[0] & 0x30) >> 4
}


func (di DeliveryInstructions) IsFragmented() bool {
  return (di[0] & 0x08) == 0x08
}

// get the tunnel id in this devilevery instrcutions or 0 if not applicable
func (di DeliveryInstructions) TunnelID() (tid uint32) {
  if di.DeliveryType() == DT_TUNNEL {
    // TODO(psi):  what if this is 0?
    tid = binary.BigEndian.Uint32(di[1:5])
  }
  return
}

// do we have a delay factor?
func (di DeliveryInstructions) HasDelay() bool {
  return (di[0] & 0x10) == 0x10 
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
