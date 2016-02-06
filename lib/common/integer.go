package common

import (
	"encoding/binary"
)

//
// Interpret a slice of bytes from length 1
// to length 8 as a big-endian integer and
// return an int representation.
//
func Integer(number []byte) int {
	num_len := len(number)
	if num_len < 8 {
		number = append(
			make([]byte, 8-num_len),
			number...,
		)
	}
	return int(
		binary.BigEndian.Uint64(number),
	)
}
