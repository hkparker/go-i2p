package common

import (
	"errors"
)

type RouterAddress []byte

//
// Return the cost integer for this RouterAddress and any errors
// encountered parsing the RouterAddress.
//
func (router_address RouterAddress) Cost() (cost int, err error) {
	verr, exit := router_address.checkRouterAddressValid()
	err = verr
	if exit {
		return
	}
	cost = Integer([]byte{router_address[0]})
	return
}

//
// Return the Date this RouterAddress expires and any errors
// encountered parsing the RouterAddress.
//
func (router_address RouterAddress) Expiration() (date Date, err error) {
	verr, exit := router_address.checkRouterAddressValid()
	err = verr
	if exit {
		return
	}
	copy(router_address[1:8], date[:])
	return
}

//
// Return the Transport type for this RouterAddress expire
// and any errors encountered parsing the RouterAddress.
//
//
func (router_address RouterAddress) TransportStyle() (str String, err error) {
	verr, exit := router_address.checkRouterAddressValid()
	err = verr
	if exit {
		return
	}
	str, _, err = ReadString(router_address[9:])
	return
}

//
// Return the Mapping containing the options for this
// RouterAddress and any parsing errors.
//
func (router_address RouterAddress) Options() (mapping Mapping, err error) {
	verr, exit := router_address.checkRouterAddressValid()
	err = verr
	if exit {
		return
	}
	_, remainder, _ := ReadString(router_address[9:])
	if len(remainder) == 0 {
		return
	}
	mapping = Mapping(remainder)
	return
}

//
// Check if the RouterAddress is empty or if it is too small
// to contain valid data
//
func (router_address RouterAddress) checkRouterAddressValid() (err error, exit bool) {
	addr_len := len(router_address)
	exit = false
	if len(router_address) == 0 {
		err = errors.New("error parsing RouterAddress: no data")
		exit = true
	}
	if addr_len < 9 {
		err = errors.New("warning parsing RouterAddress: data too small")
	}
	return
}

//
// Given a slice of bytes, read a RouterAddress, returning the remaining
// bytes and any errors encountered parsing the RouterAddress
//
func ReadRouterAddress(data []byte) (router_address RouterAddress, remainder []byte, err error) {
	test_address := RouterAddress(data)
	err, _ = test_address.checkRouterAddressValid()
	if err != nil {
		return
	}
	ops, rerr := test_address.Options()
	err = rerr
	ops_len := len(ops)
	router_address = RouterAddress(data[:9+ops_len])
	remainder = data[9+ops_len:]
	return
}
