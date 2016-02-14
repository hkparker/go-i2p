package common

import (
	"errors"
)

type RouterInfo []byte

//
// Read a RouterIdentity from the RouterInfo, returning the
// RouterIdentity and any parsing errors.
//
func (router_info RouterInfo) RouterIdentity() (router_identity RouterIdentity, err error) {
	router_identity, _, err = ReadRouterIdentity(router_info)
	return
}

//
// Return the Date the RouterInfo was published and any errors
// encountered parsing the RouterInfo.
//
func (router_info RouterInfo) Published() (date Date, err error) {
	_, remainder, _ := ReadRouterIdentity(router_info)
	if len(remainder) < 8 {
		err = errors.New("error parsing date: not enough data")
		return
	}
	copy(remainder[:8], date[:])
	return
}

//
// Return the Integer representing the number of RouterAddresses
// are contained in this RouterInfo.
//
func (router_info RouterInfo) RouterAddressCount() (count int, err error) {
	_, remainder, _ := ReadRouterIdentity(router_info)
	if len(remainder) < 9 {
		err = errors.New("error parsing router addresses: not enough data")
		return
	}
	count = Integer([]byte{remainder[8]})
	return
}

//
// Read the RouterAddresses inside this RouterInfo and return
// them in a slice.
//
func (router_info RouterInfo) RouterAddresses() (router_addresses []RouterAddress, err error) {
	_, remainder, _ := ReadRouterIdentity(router_info)
	if len(remainder) < 9 {
		err = errors.New("error parsing router addresses: not enough data")
		return
	}
	remaining := router_info[9:]
	var router_address RouterAddress
	addr_count, cerr := router_info.RouterAddressCount()
	if cerr != nil {
		err = cerr
		return
	}
	for i := 0; i < addr_count; i++ {
		router_address, remaining, err = ReadRouterAddress(remaining)
		if err == nil {
			router_addresses = append(router_addresses, router_address)
		}
	}
	return
}

//
// Return the PeerSize value, currently unused and always zero.
//
func (router_info RouterInfo) PeerSize() int {
	// Peer size is unused:
	// https://geti2p.net/en/docs/spec/common-structures#struct_RouterAddress
	return 0
}

//
// Return the Options Mapping inside this RouterInfo.
//
func (router_info RouterInfo) Options() Mapping {
	head := router_info.optionsLocation()
	size := head + router_info.optionsSize()
	return Mapping(router_info[head:size])
}

//
// Return the 40 bytes that follow the Mapping in the RouterInfo.
//
func (router_info RouterInfo) Signature() []byte {
	head := router_info.optionsLocation()
	size := head + router_info.optionsSize()
	return router_info[head+size : head+size+40]
}

//
// Used to determine where in the RouterInfo the Mapping
// data begins for parsing.
//
func (router_info RouterInfo) optionsLocation() int {
	offset := 9
	var router_address RouterAddress
	remaining := router_info[9:]
	addr_count, _ := router_info.RouterAddressCount()
	for i := 0; i < addr_count; i++ {
		router_address, remaining, _ = ReadRouterAddress(remaining)
		offset += len(router_address)
	}
	return offset
}

//
// Used to determine the size of the options in the RouterInfo
// for parsing.
//
func (router_info RouterInfo) optionsSize() int {
	head := router_info.optionsLocation()
	return Integer(router_info[head:head+1]) + 1
}
