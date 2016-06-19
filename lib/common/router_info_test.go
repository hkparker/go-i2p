package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func buildFullRouterInfo() RouterInfo {
	router_info_data := make([]byte, 0)

	router_ident_data := make([]byte, 128+256)
	router_ident_data = append(router_ident_data, []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}...)
	router_info_data = append(router_info_data, router_ident_data...)

	date_data := []byte{0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5c, 0x00}
	router_info_data = append(router_info_data, date_data...)

	router_info_data = append(router_info_data, 0x01)

	router_address_bytes := []byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	str, _ := ToI2PString("foo")
	mapping, _ := GoMapToMapping(map[string]string{"host": "127.0.0.1", "port": "4567"})
	router_address_bytes = append(router_address_bytes, []byte(str)...)
	router_address_bytes = append(router_address_bytes, mapping...)
	router_info_data = append(router_info_data, router_address_bytes...)

	return RouterInfo(router_info_data)
}

func TestPublishedReturnsCorrectDate(t *testing.T) {
	assert := assert.New(t)

	router_info := buildFullRouterInfo()
	date, err := router_info.Published()
	assert.Nil(err)
	assert.Equal(int64(86400), date.Time().Unix(), "RouterInfo.Published() did not return correct date")
}

func TestRouterAddressCountReturnsCorrectCount(t *testing.T) {
	assert := assert.New(t)

	router_info := buildFullRouterInfo()
	count, err := router_info.RouterAddressCount()
	assert.Nil(err)
	assert.Equal(1, count, "RouterInfo.RouterAddressCount() did not return correct count")
}

func TestRouterAdrressesReturnsAddresses(t *testing.T) {

}

func TestRouterAdrressesReturnsPartialListWithMissing(t *testing.T) {

}

func TestPeerSizeIsZero(t *testing.T) {
	assert := assert.New(t)

	router_info := buildFullRouterInfo()
	size := router_info.PeerSize()
	assert.Equal(0, size, "RouterInfo.PeerSize() did not return 0")
}

func TestSignatureIsCorrectSize(t *testing.T) {

}
