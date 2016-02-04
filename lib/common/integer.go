package common

import (
	"encoding/binary"
)

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
