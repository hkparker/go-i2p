package common

/*
I2P Integer
https://geti2p.net/spec/common-structures#integer
Accurate for version 0.9.24
*/

import (
	"encoding/binary"
)

const (
	INTEGER_SIZE = 8
)

//
// Interpret a slice of bytes from length 0 to length 8 as a big-endian
// integer and return an int representation.
//
func Integer(number []byte) (value int) {
	num_len := len(number)
	if num_len < INTEGER_SIZE {
		number = append(
			make([]byte, INTEGER_SIZE-num_len),
			number...,
		)
	}
	value = int(binary.BigEndian.Uint64(number))
	return
}
