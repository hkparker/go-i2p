package transport

import (
	"github.com/bounce-chat/go-i2p/lib/common"
	"github.com/bounce-chat/go-i2p/lib/i2np"
)

// a session between 2 routers for tranmitting i2np messages securly
type TransportSession interface {
	// queue an i2np message to be sent over the session
	// will block as long as the send queue is full
	// does not block if the queue is not full
	QueueSendI2NP(msg i2np.I2NPMessage)
	// return how many i2np messages are not completely sent yet
	SendQueueSize() int
	// blocking read the next fully recv'd i2np message from this session
	ReadNextI2NP() (i2np.I2NPMessage, error)
	// close the session cleanly
	// returns any errors that happen while closing the session
	Close() error
}

type Transport interface {

	// Set the router identity for this transport.
	// will bind if the underlying socket is not already
	// if the underlying socket is already bound update the RouterIdentity
	// returns any errors that happen if they do
	SetIdentity(ident common.RouterIdentity) error

	// Obtain a transport session with a router given its RouterInfo.
	// If a session with this router is NOT already made attempt to create one and block until made or until an error happens
	// returns an established TransportSession and nil on success
	// returns nil and an error on error
	GetSession(routerInfo common.RouterInfo) (TransportSession, error)

	// return true if a routerInfo is compatable with this transport
	Compatable(routerInfo common.RouterInfo) bool

	// close the transport cleanly
	// blocks until done
	// returns an error if one happens
	Close() error

	// get the name of this tranport as a string
	Name() string
}
