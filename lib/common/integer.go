package common

import (
	"encoding/binary"
)

func Integer(number ...byte) int {
	return int(
		binary.BigEndian.Uint64(number),
	)
}
