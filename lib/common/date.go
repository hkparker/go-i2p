package common

import (
	"time"
)

type Date [8]byte

//
// Time takes the value stored in date as an 8
// byte big-endian integer representing the
// number of milliseconds since the beginning
// of unix time and converts it to a go time.Time
// struct.
//
func (date Date) Time() time.Time {
	seconds := Integer(date[:])
	return time.Unix(0, int64(seconds*1000000))
}
