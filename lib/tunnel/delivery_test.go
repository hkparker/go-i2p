package tunnel

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

type DeliveryInstructionsFlags struct {
	FirstFragment bool
	Type          byte
	Delay         bool
}

func (dif DeliveryInstructionsFlags) FlagByte() byte {
	flag := byte(0x00)
	if !dif.FirstFragment {
		flag |= 0x01
	}
	flag |= dif.Type
	if dif.Delay {
		flag |= 0x10
	}
	return byte(flag)
}

func validFirstFragmentDeliveryInstructions() []byte {
	data := []byte{}

	flag := DeliveryInstructionsFlags{
		FirstFragment: true,
		Type:          0x02,
		Delay:         false,
	}.FlagByte()
	data = append(data, flag)

	tunnel_id := []byte{0x00, 0x00, 0x00, 0x01}
	data = append(data, tunnel_id...)

	hash := make([]byte, 32)
	data = append(data, hash...)

	// Add 0 delay
	data = append(data, 0)

	message_id := []byte{0x00, 0x00, 0x00, 0x02}
	data = append(data, message_id...)

	return data
}

func TestReadDeliveryInstructions(t *testing.T) {
	assert := assert.New(t)

	_, _, err := readDeliveryInstructions(validFirstFragmentDeliveryInstructions())
	assert.Nil(err)
}
