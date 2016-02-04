package common

import (
	"time"
)

type Date [8]byte

func (date Date) Time() time.Time {
	seconds := Integer(date[:])
	return time.Unix(0, int64(seconds*1000000))
}
