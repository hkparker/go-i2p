package exportable

import "github.com/hkparker/go-i2p/lib/common"

func Fuzz(data []byte) int {
	keys_and_cert, _, _ := common.ReadKeysAndCert(data)
	keys_and_cert.Certificate()
	keys_and_cert.PublicKey()
	keys_and_cert.SigningPublicKey()
	return 0
}
