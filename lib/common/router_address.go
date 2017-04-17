package common

/*
I2P RouterAddress
https://geti2p.net/spec/common-structures#routeraddress
Accurate for version 0.9.24

+----+----+----+----+----+----+----+----+
|cost|           expiration
+----+----+----+----+----+----+----+----+
     |        transport_style           |
+----+----+----+----+-//-+----+----+----+
|                                       |
+                                       +
|               options                 |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+

cost :: Integer
        length -> 1 byte

        case 0 -> free
        case 255 -> expensive

expiration :: Date (must be all zeros, see notes below)
              length -> 8 bytes

              case null -> never expires

transport_style :: String
                   length -> 1-256 bytes

options :: Mapping
*/

import (
	"errors"
	log "github.com/Sirupsen/logrus"
)

// Minimum number of bytes in a valid RouterAddress
const (
	ROUTER_ADDRESS_MIN_SIZE = 9
)

type RouterAddress []byte

//
// Return the cost integer for this RouterAddress and any errors encountered
// parsing the RouterAddress.
//
func (router_address RouterAddress) Cost() (cost int, err error) {
	err, exit := router_address.checkValid()
	if exit {
		return
	}
	cost = Integer([]byte{router_address[0]})
	return
}

//
// Return the Date this RouterAddress expires and any errors encountered
// parsing the RouterAddress.
//
func (router_address RouterAddress) Expiration() (date Date, err error) {
	err, exit := router_address.checkValid()
	if exit {
		return
	}
	copy(date[:], router_address[1:ROUTER_ADDRESS_MIN_SIZE])
	return
}

//
// Return the Transport type for this RouterAddress and any errors encountered
// parsing the RouterAddress.
//
func (router_address RouterAddress) TransportStyle() (str String, err error) {
	err, exit := router_address.checkValid()
	if exit {
		return
	}
	str, _, err = ReadString(router_address[ROUTER_ADDRESS_MIN_SIZE:])
	return
}

//
// Return the Mapping containing the options for this RouterAddress and any
// errors encountered parsing the RouterAddress.
//
func (router_address RouterAddress) Options() (mapping Mapping, err error) {
	err, exit := router_address.checkValid()
	if exit {
		return
	}
	_, remainder, err := ReadString(router_address[ROUTER_ADDRESS_MIN_SIZE:])
	if len(remainder) == 0 {
		return
	}
	mapping = Mapping(remainder)
	return
}

//
// Check if the RouterAddress is empty or if it is too small to contain valid data.
//
func (router_address RouterAddress) checkValid() (err error, exit bool) {
	addr_len := len(router_address)
	exit = false
	if addr_len == 0 {
		log.WithFields(log.Fields{
			"at":     "(RouterAddress) checkValid",
			"reason": "no data",
		}).Error("invalid router address")
		err = errors.New("error parsing RouterAddress: no data")
		exit = true
	} else if addr_len < ROUTER_ADDRESS_MIN_SIZE {
		log.WithFields(log.Fields{
			"at":     "(RouterAddress) checkValid",
			"reason": "data too small (len < ROUTER_ADDRESS_MIN_SIZE)",
		}).Warn("router address format warning")
		err = errors.New("warning parsing RouterAddress: data too small")
	}
	return
}

//
// Given a slice of bytes, read a RouterAddress, returning the remaining bytes and any
// errors encountered parsing the RouterAddress.
//
func ReadRouterAddress(data []byte) (router_address RouterAddress, remainder []byte, err error) {
	test_address := RouterAddress(data)
	err, _ = test_address.checkValid()
	if err != nil {
		return
	}
	router_address = append(router_address, data[:ROUTER_ADDRESS_MIN_SIZE]...)
	str, remainder, err := ReadString(data[ROUTER_ADDRESS_MIN_SIZE:])
	if err != nil {
		return
	}
	router_address = append(router_address, str...)
	map_size := 0
	mapping := make([]byte, 0)
	if len(remainder) >= 2 {
		map_size = Integer(remainder[:2])
		if len(remainder) < map_size+2 {
			err = errors.New("not enough data for map inside router address")
			router_address = RouterAddress([]byte{})
			remainder = []byte{}
			return
		}
		mapping = remainder[:map_size+2]
		router_address = append(router_address, mapping...)
	}

	remainder = data[ROUTER_ADDRESS_MIN_SIZE+len(str)+len(mapping):]
	return
}
