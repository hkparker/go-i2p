package common

import (
	"crypto/sha256"
	"io"
)

// sha256 hash of some data
type Hash [32]byte

// calculate sha256 of a byte slice
func HashData(data []byte) (h Hash) {
	h = sha256.Sum256(data)
	return
}

// calulate sha256 of all data being read from an io.Reader
// return error if one occurs while reading from reader
func HashReader(r io.Reader) (h Hash, err error) {
	sha := sha256.New()
	_, err = io.Copy(sha, r)
	if err == nil {
		d := sha.Sum(nil)
		copy(h[:], d)
	}
	return
}
