package common

/*
I2P RouterInfo
https://geti2p.net/spec/common-structures#routerinfo
Accurate for version 0.9.24

+----+----+----+----+----+----+----+----+
| router_ident                          |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| published                             |
+----+----+----+----+----+----+----+----+
|size| RouterAddress 0                  |
+----+                                  +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| RouterAddress 1                       |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| RouterAddress ($size-1)               |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+-//-+----+----+----+
|psiz| options                          |
+----+----+----+----+-//-+----+----+----+
| signature                             |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+

router_ident :: RouterIdentity
                length -> >= 387 bytes

published :: Date
             length -> 8 bytes

size :: Integer
        length -> 1 byte
        The number of RouterAddresses to follow, 0-255

addresses :: [RouterAddress]
             length -> varies

peer_size :: Integer
             length -> 1 byte
             The number of peer Hashes to follow, 0-255, unused, always zero
             value -> 0

options :: Mapping

signature :: Signature
             length -> 40 bytes
*/

import (
	"errors"
	log "github.com/sirupsen/logrus"
)

type RouterInfo []byte

//
// Read a RouterIdentity from the RouterInfo, returning the RouterIdentity and any errors
// encountered parsing the RouterIdentity.
//
func (router_info RouterInfo) RouterIdentity() (router_identity RouterIdentity, err error) {
	router_identity, _, err = ReadRouterIdentity(router_info)
	return
}

//
// Calculate this RouterInfo's Identity Hash (the sha256 of the RouterIdentity)
// returns error if the RouterIdentity is malformed
//
func (router_info RouterInfo) IdentHash() (h Hash, err error) {
	var ri RouterIdentity
	ri, err = router_info.RouterIdentity()
	if err == nil {
		h = HashData(ri)
	}
	return
}

//
// Return the Date the RouterInfo was published and any errors encountered parsing the RouterInfo.
//
func (router_info RouterInfo) Published() (date Date, err error) {
	_, remainder, err := ReadRouterIdentity(router_info)
	if err != nil {
		return
	}
	remainder_len := len(remainder)
	if remainder_len < 8 {
		log.WithFields(log.Fields{
			"at":           "(RouterInfo) Published",
			"data_len":     remainder_len,
			"required_len": 8,
			"reason":       "not enough data",
		}).Error("error parsing router info")
		err = errors.New("error parsing date: not enough data")
		return
	}
	copy(date[:], remainder[:8])
	return
}

//
// Return the Integer representing the number of RouterAddresses that are contained in this RouterInfo.
//
func (router_info RouterInfo) RouterAddressCount() (count int, err error) {
	_, remainder, err := ReadRouterIdentity(router_info)
	if err != nil {
		return
	}
	remainder_len := len(remainder)
	if remainder_len < 9 {
		log.WithFields(log.Fields{
			"at":           "(RouterInfo) RouterAddressCount",
			"data_len":     remainder_len,
			"required_len": 9,
			"reason":       "not enough data",
		}).Error("error parsing router info")
		err = errors.New("error parsing router addresses: not enough data")
		return
	}
	count = Integer([]byte{remainder[8]})
	return
}

//
// Read the RouterAddresses inside this RouterInfo and return them in a slice, returning
// a partial list if data is missing.
//
func (router_info RouterInfo) RouterAddresses() (router_addresses []RouterAddress, err error) {
	_, remainder, err := ReadRouterIdentity(router_info)
	if err != nil {
		return
	}
	remainder_len := len(remainder)
	if remainder_len < 9 {
		log.WithFields(log.Fields{
			"at":           "(RouterInfo) RouterAddresses",
			"data_len":     remainder_len,
			"required_len": 9,
			"reason":       "not enough data",
		}).Error("error parsing router info")
		err = errors.New("error parsing router addresses: not enough data")
		return
	}
	remaining := remainder[9:]
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
	// https://geti2p.net/spec/common-structures#routeraddress
	return 0
}

//
// Return the Options Mapping inside this RouterInfo.
//
func (router_info RouterInfo) Options() (mapping Mapping) {
	head := router_info.optionsLocation()
	size := head + router_info.optionsSize()
	mapping = Mapping(router_info[head:size])
	return
}

//
// Return the 40 bytes that follow the Mapping in the RouterInfo.
//
func (router_info RouterInfo) Signature() (signature Signature) {
	head := router_info.optionsLocation()
	size := head + router_info.optionsSize()
	// TODO: signature is not always 40 bytes, is 40 bytes for DSA only
	signature = Signature(router_info[size : size+40])
	return
}

//
// Used during parsing to determine where in the RouterInfo the Mapping data begins.
//
func (router_info RouterInfo) optionsLocation() (location int) {
	data, remainder, err := ReadRouterIdentity(router_info)
	if err != nil {
		return
	}
	location += len(data)

	remainder_len := len(remainder)
	if remainder_len < 9 {
		log.WithFields(log.Fields{
			"at":           "(RouterInfo) optionsLocation",
			"data_len":     remainder_len,
			"required_len": 9,
			"reason":       "not enough data",
		}).Error("error parsing router info")
		err = errors.New("error parsing router addresses: not enough data")
		return
	}
	location += 9

	remaining := remainder[9:]
	var router_address RouterAddress
	var router_addresses []RouterAddress
	addr_count, cerr := router_info.RouterAddressCount()
	if cerr != nil {
		err = cerr
		return
	}
	for i := 0; i < addr_count; i++ {
		router_address, remaining, err = ReadRouterAddress(remaining)
		if err == nil {
			location += len(router_address)
			router_addresses = append(router_addresses, router_address)
		}
	}
	location += 1
	return
}

//
// Used during parsing to determine the size of the options in the RouterInfo.
//
func (router_info RouterInfo) optionsSize() (size int) {
	head := router_info.optionsLocation()
	size = Integer(router_info[head:head+2]) + 2
	return
}
