package crypto

import (
	"crypto/md5"
)

const IPAD = byte(0x36)
const OPAD = byte(0x5C)

type HMACKey [32]byte
type HMACDigest [16]byte

func (hk HMACKey) xor(p byte) (i []byte) {
	i = make([]byte, 64)
	for idx, b := range hk {
		i[idx] = b ^ p
	}
	c := 32
	for c > 0 {
		c--
		i[c+32] = p
	}
	return
}

//
// do i2p hmac
//
func I2PHMAC(data []byte, k HMACKey) (d HMACDigest) {

	buff := make([]byte, 64+len(data))
	ip := k.xor(IPAD)
	copy(buff, ip)
	copy(buff[64:], data)
	h := md5.Sum(buff)

	buff = make([]byte, 96)
	copy(buff, k.xor(OPAD))
	copy(buff[64:], h[:])
	// go zeros slices so we do not have to zero
	d = md5.Sum(buff)
	return
}
