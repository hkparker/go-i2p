package bootstrap

import (
  "github.com/bounce-chat/go-i2p/lib/stdi2p"
)


type HTTPSReseed string

func (r HTTPSReseed) Reseed(chnl chan *stdi2p.SU3) (err error) {
  return
}
