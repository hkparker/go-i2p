package transport

import (
	"errors"
)

// error for when we have no transports available to use
var ErrNoTransportAvailable = errors.New("no transports available")
