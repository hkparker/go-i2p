package tunnel

import (
	"github.com/hkparker/go-i2p/lib/common"
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

func validFirstFragmentDeliveryInstructions(mapping common.Mapping) []byte {
	data := []byte{}

	flag := DeliveryInstructionsFlags{
		FirstFragment: true,
		Type:          0x02,
		Delay:         false,
	}
	data = append(data, flag.FlagByte())

	tunnel_id := []byte{0x00, 0x00, 0x00, 0x01}
	data = append(data, tunnel_id...)

	hash := make([]byte, HASH_SIZE)
	data = append(data, hash...)

	if flag.Delay {
		data = append(data, 1)
	} else {
		data = append(data, 0)
	}

	message_id := []byte{0x00, 0x00, 0x00, 0x02}
	data = append(data, message_id...)

	data = append(data, mapping...)

	return data
}

func TestReadDeliveryInstructions(t *testing.T) {
	assert := assert.New(t)

	mapping, _ := common.GoMapToMapping(map[string]string{})
	_, _, err := readDeliveryInstructions(
		validFirstFragmentDeliveryInstructions(
			mapping,
		),
	)
	assert.Nil(err)
}
