package common

import (
	//"github.com/stretchr/testify/assert"
	"testing"
)

func buildFullRouterInfo() RouterInfo {
	// starts with a keys_and_cert
	router_address_bytes := []byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	str, _ := ToI2PString("foo")
	mapping, _ := GoMapToMapping(map[string]string{"host": "127.0.0.1", "port": "4567"})
	router_address_bytes = append(router_address_bytes, []byte(str)...)
	router_address_bytes = append(router_address_bytes, mapping...)
	//RouterAddress(router_address_bytes)
	return nil
}

func TestPublishedReturnsCorrectDate(t *testing.T) {
}

func TestRouterAddressCountReturnsCorrectCount(t *testing.T) {
}

func TestRouterAdrressesReturnsAddresses(t *testing.T) {

}

func TestRouterAdrressesReturnsPartialListWithMissing(t *testing.T) {

}

func TestPeerSizeIsZero(t *testing.T) {

}

func TestSignatureIsCorrectSize(t *testing.T) {

}
