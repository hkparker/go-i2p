package common

import (
	"errors"
)

type String []byte

func ReadString(data []byte) (str String, remainder []byte, err error) {
	if len(data) == 0 {
		err = errors.New("no string in empty byte slice")
		return
	}
	length := Integer([]byte{data[0]})
	data = data[1:]

	if len(data) < length {
		str = data
		err = errors.New("string longer than provided slice")
		return
	}
	str = data[:length]
	remainder = data[length:]
	return
}
