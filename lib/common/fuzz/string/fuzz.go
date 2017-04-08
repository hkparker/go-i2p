package exportable

import "github.com/hkparker/go-i2p/lib/common"

func Fuzz(data []byte) int {
	str, _, _ := common.ReadString(data)
	str.Data()
	str.Length()
	str, _ = common.ToI2PString(string(data))
	str.Data()
	str.Length()
	return 0
}
