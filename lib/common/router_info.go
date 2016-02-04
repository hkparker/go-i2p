package common

type RouterInfo []byte

func (router_info RouterInfo) RouterIdentity() RouterIdentity {
	router_identity, _, _ := readRouterIdentity(router_info)
	return router_identity
}

func (router_info RouterInfo) Published() (d Date) {
	_, remainder, _ := readRouterIdentity(router_info)
	copy(remainder[:8], d[:])
	return
}

func (router_info RouterInfo) RouterAddressCount() int {
	_, remainder, _ := readRouterIdentity(router_info)
	return Integer(remainder[8])
}

func (router_info RouterInfo) RouterAddresses() []RouterAddress {
	var router_address RouterAddress
	remaining := router_info[9:]
	var err error
	addresses := make([]RouterAddress, 0)
	for i := 0; i < router_info.RouterAddressCount(); i++ {
		router_address, remaining, err = readRouterAddress(remaining)
		if err == nil {
			addresses = append(addresses, router_address)
		}
	}
	return addresses
}

func (router_info RouterInfo) PeerSize() int {
	return 0
}

func (router_info RouterInfo) Options() Mapping {
	head := router_info.optionsLocation()
	size := head + router_info.optionsSize()
	return Mapping(router_info[head:size])
}

func (router_info RouterInfo) Signature() []byte {
	offset := router_info.optionsLocation() + router_info.optionsSize()
	sig_size := router_info.
		RouterIdentity().
		Certificate().
		signatureSize()
	return router_info[offset:sig_size]
}

func (router_info RouterInfo) optionsLocation() int {
	offset := 9
	var router_address RouterAddress
	remaining := router_info[9:]
	for i := 0; i < router_info.RouterAddressCount(); i++ {
		router_address, remaining, _ = readRouterAddress(remaining)
		offset = len(router_address)
	}
	return offset
}

func (router_info RouterInfo) optionsSize() int {
	head := router_info.optionsLocation()
	return Integer(router_info[head : head+1]...)
}
