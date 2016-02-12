package common

import (
	"bytes"
	"testing"
)

func TestCheckValidReportsEmptySlice(t *testing.T) {
	router_address := RouterAddress([]byte{})
	err, exit := router_address.checkValid()
	if err == nil || err.Error() != "error parsing RouterAddress: no data" {
		t.Fatal("incorrect error returned by checkValid:", err)
	}
	if exit != true {
		t.Fatal("checkValid did not indicate to stop parsing on empty slice")
	}
}

func TestCheckRouterAddressValidReportsDataMissing(t *testing.T) {
	router_address := RouterAddress([]byte{0x01})
	err, exit := router_address.checkValid()
	if err == nil || err.Error() != "warning parsing RouterAddress: data too small" {
		t.Fatal("incorrect error returned by checkValid:", err)
	}
	if exit != false {
		t.Fatal("checkValid indicated to stop parsing when some fields may be present")
	}
}

func TestCheckRouterAddressValidNoErrWithValidData(t *testing.T) {
	router_address := RouterAddress([]byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00})
	mapping, _ := GoMapToMapping(map[string]string{"host": "127.0.0.1", "port": "4567"})
	router_address = append(router_address, mapping...)
	err, exit := router_address.checkValid()
	if err != nil {
		t.Fatal("checkValid reported error with valid data:", err)
	}
	if exit != false {
		t.Fatal("checkValid indicated to stop parsing valid data")
	}
}

func TestRouterAddressCostReturnsFirstByte(t *testing.T) {
	router_address := RouterAddress([]byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00})
	cost, err := router_address.Cost()
	if err != nil {
		t.Fatal("err when calling Cost on valid data:", err)
	}
	if cost != 6 {
		t.Fatal("Cost returned wrong cost:", cost)
	}
}

func TestRouterAddressExpirationReturnsCorrectData(t *testing.T) {
	router_address := RouterAddress([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00})
	expiration, err := router_address.Expiration()
	if err != nil {
		t.Fatal("err when calling Expiration on valid data:", err)
	}
	if bytes.Compare(expiration[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}) != 0 {
		t.Fatal("Expiration did not return correct data:", expiration)
	}
}

func TestReadRouterAddressReturnsCorrectRemainderWithoutError(t *testing.T) {
	router_address_bytes := []byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	str, _ := ToI2PString("foo")
	mapping, _ := GoMapToMapping(map[string]string{"host": "127.0.0.1", "port": "4567"})
	router_address_bytes = append(router_address_bytes, []byte(str)...)
	router_address_bytes = append(router_address_bytes, mapping...)
	router_address_bytes = append(router_address_bytes, []byte{0x01, 0x02, 0x03}...)
	router_address, remainder, err := ReadRouterAddress(router_address_bytes)
	if err != nil {
		t.Fatal("ReadRouterAddress reported error with valid data:", err)
	}
	if bytes.Compare(remainder, []byte{0x01, 0x02, 0x03}) != 0 {
		t.Fatal("incorrect remainder returned on ReadRouterAddress:", remainder)
	}
	err, exit := router_address.checkValid()
	if err != nil {
		t.Fatal("checkValid on address from ReadRouterAddress reported error with valid data:", err)
	}
	if exit != false {
		t.Fatal("checkValid on address from ReadRouterAddress indicated to stop parsing valid data")
	}
}
