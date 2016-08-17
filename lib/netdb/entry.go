package netdb

import (
	"github.com/hkparker/go-i2p/lib/common"
	"io"
)

// netdb entry
// wraps a router info and provides serialization
type Entry struct {
	ri common.RouterInfo
}

func (e *Entry) WriteTo(w io.Writer) (err error) {
	return
}

func (e *Entry) ReadFrom(r io.Reader) (err error) {
	return
}
