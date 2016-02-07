package transport

import (
	"github.com/bounce-chat/go-i2p/lib/common"
)

// muxes multiple transports into 1 Transport
// implements transport.Transport
type TransportMuxer struct {
	// the underlying transports we are using in order of most prominant to least
	trans []Transport
}

// mux a bunch of transports together
func Mux(t ...Transport) (tmux *TransportMuxer) {
	tmux = new(TransportMuxer)
	tmux.trans = append(tmux.trans, t...)
	return
}

// set the identity for every transport
func (tmux *TransportMuxer) SetIdentity(ident common.RouterIdentity) (err error) {
	for _, t := range tmux.trans {
		err = t.SetIdentity(ident)
		if err != nil {
			// an error happened let's return and complain
			return
		}
	}
	return
}

// close every transport that this transport muxer has
func (tmux *TransportMuxer) Close() (err error) {
	for _, t := range tmux.trans {
		err = t.Close()
		if t != nil {
			// TODO: handle error (?)
		}
	}
	return
}

// the name of this transport with the names of all the ones that we mux
func (tmux *TransportMuxer) Name() string {
	name := "Muxed Transport: "
	for _, t := range tmux.trans {
		name += t.Name() + ", "
	}
	return name[len(name)-3:]
}

// get a transport session given a router info
// return session and nil if successful
// return nil and ErrNoTransportAvailable if we failed to get a session
func (tmux *TransportMuxer) GetSession(routerInfo common.RouterInfo) (s TransportSession, err error) {
	for _, t := range tmux.trans {
		// pick the first one that is compatable
		if t.Compatable(routerInfo) {
			// try to get a session
			s, err = t.GetSession(routerInfo)
			if err != nil {
				// we could not get a session
				// try the next transport
				continue
			}
			// we got a session
			return
		}
	}
	// we failed to get a session for this routerInfo
	err = ErrNoTransportAvailable
	return
}

// is there a transport that we mux that is compatable with this router info?
func (tmux *TransportMuxer) Compatable(routerInfo common.RouterInfo) (compat bool) {
	for _, t := range tmux.trans {
		if t.Compatable(routerInfo) {
			compat = true
			return
		}
	}
	return
}
