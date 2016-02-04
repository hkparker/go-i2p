package common

import (
	"time"
)

type Date [8]byte

func GoDate(date Date) time.Time {
	seconds := Integer(date[:]...)
	return time.Unix(0, int64(seconds*1000000))
}
