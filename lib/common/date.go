package common

import (
	"time"
)

type Date [8]byte

//
// Time takes the value stored in date as an 8 byte big-endian integer representing the
// number of milliseconds since the beginning of unix time and converts it to a Go time.Time
// struct.
//
func (date Date) Time() (date_time time.Time) {
	seconds := Integer(date[:])
	date_time = time.Unix(0, int64(seconds*1000000))
	return
}
