package bootstrap

import (
  "github.com/bounce-chat/go-i2p/lib/stdi2p"
)

type Reseed interface {
  // do reseed, return nil on success otherwise error
  // sends down all retrieved SU3 files down chan
  Reseed(chnl chan *stdi2p.SU3) error
}
