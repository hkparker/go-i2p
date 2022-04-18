package common

/*
I2P String
https://geti2p.net/spec/common-structures#string
Accurate for version 0.9.24
*/

import (
	"errors"
	log "github.com/sirupsen/logrus"
)

// Maximum number of bytes that can be stored in an I2P string
const (
	STRING_MAX_SIZE = 255
)

type String []byte

//
// Look up the length of the string, reporting errors if the string is
// invalid or the specified length does not match the provided data.
//
func (str String) Length() (length int, err error) {
	if len(str) == 0 {
		log.WithFields(log.Fields{
			"at":     "(String) Length",
			"reason": "no data",
		}).Error("error parsing string")
		err = errors.New("error parsing string: zero length")
		return
	}
	length = Integer([]byte{byte(str[0])})
	inferred_len := length + 1
	str_len := len(str)
	if inferred_len > str_len {
		log.WithFields(log.Fields{
			"at": "(String) Length",
			"string_bytes_length":   str_len,
			"string_length_field":   length,
			"expected_bytes_length": inferred_len,
			"reason":                "data shorter than specified",
		}).Warn("string format warning")
		err = errors.New("string parsing warning: string data is shorter than specified by length")
	} else if str_len > inferred_len {
		log.WithFields(log.Fields{
			"at": "(String) Length",
			"string_bytes_length":   str_len,
			"string_length_field":   length,
			"expected_bytes_length": inferred_len,
			"reason":                "data longer than specified",
		}).Warn("string format warning")
		err = errors.New("string parsing warning: string contains data beyond length")
	}
	return
}

//
// Return the string data and any errors encountered by Length.
//
func (str String) Data() (data string, err error) {
	length, err := str.Length()
	if err != nil {
		switch err.Error() {
		case "error parsing string: zero length":
			return
		case "string parsing warning: string data is shorter than specified by length":
			data = string(str[1:])
			return
		case "string parsing warning: string contains data beyond length":
			data = string(str[1 : length+1])
			return
		}
	}
	data = string(str[1:])
	return
}

//
// This function takes an unformatted Go string and returns a String
// and any errors encountered during the encoding.
//
func ToI2PString(data string) (str String, err error) {
	data_len := len(data)
	if data_len > STRING_MAX_SIZE {
		log.WithFields(log.Fields{
			"at":         "ToI2PString",
			"string_len": data_len,
			"max_len":    STRING_MAX_SIZE,
			"reason":     "too much data",
		}).Error("cannot create I2P string")
		err = errors.New("cannot store that much data in I2P string")
		return
	}
	i2p_string := []byte{byte(data_len)}
	i2p_string = append(i2p_string, []byte(data)...)
	str = String(i2p_string)
	return
}

//
// Read a string from a slice of bytes, returning any extra data on the end
// of the slice and any errors encountered parsing the String.
//
func ReadString(data []byte) (str String, remainder []byte, err error) {
	str = String(data)
	length, err := String(data).Length()
	if err != nil && err.Error() == "string parsing warning: string contains data beyond length" {
		str = String(data[:length+1])
		remainder = data[length+1:]
		err = nil
	}
	return
}
