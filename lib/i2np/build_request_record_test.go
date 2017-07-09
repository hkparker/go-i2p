package i2np

import (
	"github.com/hkparker/go-i2p/lib/common"
	"github.com/hkparker/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestReadBuildRequestRecordReceiveTunnelTooLittleData(t *testing.T) {
	assert := assert.New(t)

	receive_tunnel, err := readBuildRequestRecordReceiveTunnel([]byte{0x01})
	assert.Equal(tunnel.TunnelID(0), receive_tunnel)
	assert.Equal(ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA, err)

}

func TestReadBuildRequestRecordReceiveTunnelValidData(t *testing.T) {
	assert := assert.New(t)

	receive_tunnel, err := readBuildRequestRecordReceiveTunnel([]byte{0x00, 0x00, 0x00, 0x01})
	assert.Equal(tunnel.TunnelID(1), receive_tunnel)
	assert.Equal(nil, err)
}

func TestReadBuildRequestRecordOurIdentTooLittleValidData(t *testing.T) {
	assert := assert.New(t)

	receive_tunnel := []byte{0x00, 0x00, 0x00, 0x01}
	our_ident := make([]byte, 31)
	our_ident[30] = 0x01
	build_request_record := append(receive_tunnel, our_ident...)
	read_ident, err := readBuildRequestRecordOurIdent(build_request_record)
	hash := common.Hash{}
	assert.Equal(hash, read_ident)
	assert.Equal(ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA, err)
}

func TestReadBuildRequestRecordOurIdentValidData(t *testing.T) {
	assert := assert.New(t)

	receive_tunnel := []byte{0x00, 0x00, 0x00, 0x01}
	our_ident := make([]byte, 32)
	our_ident[31] = 0x01
	build_request_record := append(receive_tunnel, our_ident...)
	read_ident, err := readBuildRequestRecordOurIdent(build_request_record)
	hash := common.Hash{}
	copy(hash[:], our_ident)
	assert.Equal(hash, read_ident)
	assert.Equal(nil, err)
}

func TestReadBuildRequestRecordNextTunnel(t *testing.T) {}

func TestReadBuildRequestRecordNextIdent(t *testing.T) {}

func TestReadBuildRequestRecordLayerKey(t *testing.T) {}

func TestReadBuildRequestRecordIVKey(t *testing.T) {}

func TestReadBuildRequestRecordReplyKey(t *testing.T) {}

func TestReadBuildRequestRecordReplyIV(t *testing.T) {}

func TestReadBuildRequestRecordFlag(t *testing.T) {}

func TestReadBuildRequestRecordRequestTime(t *testing.T) {}

func TestReadBuildRequestRecordSendMessageID(t *testing.T) {}

func TestReadBuildRequestRecordPadding(t *testing.T) {}
