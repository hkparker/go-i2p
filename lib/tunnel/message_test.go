package tunnel

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDeliveryInstructionDataWithNoPadding(t *testing.T) {
	assert := assert.New(t)

	data := make([]byte, 0)
	data = append(data, make([]byte, 4+4+16)...)
	data = append(data, 0)
	data = append(data, make([]byte, 1028-4-4-16-1)...)
	var decrypted_tunnel_message DecryptedTunnelMessage
	copy(decrypted_tunnel_message[:], data)
	di := decrypted_tunnel_message.deliveryInstructionData()
	assert.Equal(1028-4-4-16-1, len(di))
}

func TestDeliveryInstructionDataWithSomePadding(t *testing.T) {
	assert := assert.New(t)

	data := make([]byte, 0)
	data = append(data, make([]byte, 4+4+16)...)
	padding_size := 200
	for i := 0; i < padding_size; i++ {
		data = append(data, 0x01)
	}
	data = append(data, 0)
	data = append(data, make([]byte, 1028-4-4-16-1-padding_size)...)
	var decrypted_tunnel_message DecryptedTunnelMessage
	copy(decrypted_tunnel_message[:], data)
	di := decrypted_tunnel_message.deliveryInstructionData()
	assert.Equal(1028-4-4-16-1-padding_size, len(di))

}

func TestDeliveryInstructionDataWithOnlyPadding(t *testing.T) {
	assert := assert.New(t)

	data := make([]byte, 0)
	data = append(data, make([]byte, 4+4+16)...)
	padding_size := 1028 - 4 - 4 - 16 - 1
	for i := 0; i < padding_size; i++ {
		data = append(data, 0x01)
	}
	data = append(data, 0)
	var decrypted_tunnel_message DecryptedTunnelMessage
	copy(decrypted_tunnel_message[:], data)
	di := decrypted_tunnel_message.deliveryInstructionData()
	assert.Equal(0, len(di))
}

func TestDeliveryInstructionsWithFragmentsWithAllPadding(t *testing.T) {

}

// Test invalid delivery instructions and message fragments

func TestDeliveryInstructionsWithFragmentsWithValidData(t *testing.T) {

}
