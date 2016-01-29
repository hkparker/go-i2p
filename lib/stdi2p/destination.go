package stdi2p

import (
	"github.com/bounce-chat/go-i2p/lib/common/base32"
	"github.com/bounce-chat/go-i2p/lib/common/base64"
	"github.com/bounce-chat/go-i2p/lib/crypto"
	"strings"
)

// a network endpoint inside i2p
// effectively a public key blob
type Destination []byte

// obtain public elgamal key
func (dest Destination) PublicKey() (k crypto.PublicEncryptionKey) {
	cert := dest.Certificate()
	if cert.Type() == CERT_KEY {
		// TODO(psi): check for key cert and included encryption key
	} else {
		var ek crypto.ElgPublicKey
		copy(ek[:], dest[:256])
		k = ek
	}
	return
}

// obtain destination certificate
func (dest Destination) Certificate() Certificate {
	return Certificate(dest[128+256:])
}

// gets this destination's signing key
// if there is a keycert in this destination the signing key in there is used
func (dest Destination) SigningPublicKey() (k crypto.SigningPublicKey) {
	cert := dest.Certificate()
	if cert.Type() == CERT_KEY {
		// we have a key certificate
		// extract the signing key from the key cert
		k = KeyCert(cert).SigningPublicKey()
	} else {
		var pk crypto.DSAPublicKey
		copy(pk[:], dest[256:256+128])
		k = pk
	}
	return
}

// return the .b32.i2p address
func (dest Destination) Base32Address() (str string) {
	h := crypto.SHA256(dest)
	str = strings.Trim(base32.EncodeToString(h[:]), "=")
	str += ".b32.i2p"
	return
}

func (dest Destination) Base64() (str string) {
	str = base64.EncodeToString(dest)
	return
}
