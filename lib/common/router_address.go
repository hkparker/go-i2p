package common

import (
	"bytes"
	"encoding/binary"
)

type RouterAddress []byte

func (router_address RouterAddress) Cost() int {
	var cost int
	buf := bytes.NewReader(
		[]byte{router_address[0]},
	)
	binary.Read(buf, binary.BigEndian, &cost)
	return cost
}

func (router_address RouterAddress) Expiration() (d Date) {
	copy(router_address[1:8], d[:])
	return
}

func (router_address RouterAddress) TransportStyle() string {
	return string(
		router_address[10:router_address.stringLength()],
	)
}

func (router_address RouterAddress) Options() Mapping {
	var mapping Mapping
	copy(router_address[9+router_address.stringLength():], mapping[:])
	return mapping
}

func (router_address RouterAddress) stringLength() int {
	var string_len int
	buf := bytes.NewReader(
		[]byte{router_address[9]},
	)
	binary.Read(buf, binary.BigEndian, &string_len)
	return string_len

}

func readRouterAddress(data []byte) (RouterAddress, []byte, error) {
	var router_address RouterAddress
	copy(data[:10], router_address)

	string_len := router_address.stringLength()
	router_address = append(router_address, data[10:10+string_len]...)

	options_len := int(binary.BigEndian.Uint16(data[string_len+10 : string_len+11]))
	router_address = append(router_address, data[string_len+10:11+string_len+options_len]...)

	return router_address, data[:], nil
}
