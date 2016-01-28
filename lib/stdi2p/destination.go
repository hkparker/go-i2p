package stdi2p

// a network endpoint inside i2p
// effectively a public key blob
type Destination []byte

// obtain public elgamal key
func (dest Destination) PublicKey() (k PublicEncryptionKey) {
  cert := dest.Certificate()
  if cert.Type() == CERT_KEY {
  } else {
    var ek ElgPublicKey
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
func (dest Destination) SigningPublicKey() (k SigningPublicKey) {
  cert := dest.Certificate()
  if cert.Type() == CERT_KEY {
    // we have a key certificate
    k = KeyCert(cert).SigningPublicKey()
  } else {
    var pk DSAPublicKey
    copy(pk[:], dest[256:256+128])
    k = pk
  }
  return
}
