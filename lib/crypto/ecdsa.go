package crypto

import (
  "crypto"
  "crypto/ecdsa"
  "crypto/elliptic"
)

type ECDSAVerifier struct {
  k *ecdsa.PublicKey
  c elliptic.Curve
  h crypto.Hash
}

// verify a signature given the hash
func (v *ECDSAVerifier) VerifyHash(h, sig []byte) (err error) {
  r, s := elliptic.Unmarshal(v.c, sig)
  if r == nil || s == nil || ! ecdsa.Verify(v.k, h, r, s) {
    err = ErrInvalidSignature
  }
  return
}

// verify a block of data by hashing it and comparing the hash against the signature
func (v *ECDSAVerifier) Verify(data, sig []byte) (err error) {
  // sum the data and get the hash
  h := v.h.New().Sum(data)[len(data):]
  // verify 
  err = v.VerifyHash(h, sig)
  return
}

func createECVerifier(c elliptic.Curve, h crypto.Hash, k []byte) (ev *ECDSAVerifier, err error) {
  x, y := elliptic.Unmarshal(c, k[:])
  if x == nil {
    err = ErrInvalidKeyFormat
  } else {
    ev = &ECDSAVerifier{
      c: c,
      h: h,
    }
    ev.k = &ecdsa.PublicKey{c, x, y}
  }
  return
}

type ECP256PublicKey [64]byte
type ECP256PrivateKey [32]byte

func (k ECP256PublicKey) Len() int {
  return len(k)
}

func (k ECP256PublicKey) NewVerifier() (Verifier, error) {
  return createECVerifier(elliptic.P256(), crypto.SHA256, k[:])
}

type ECP384PublicKey [96]byte
type ECP384PrivateKey [48]byte

func (k ECP384PublicKey) Len() int {
  return len(k)
}

func (k ECP384PublicKey) NewVerifier() (Verifier, error) {
  return createECVerifier(elliptic.P384(), crypto.SHA384, k[:])
}

type ECP521PublicKey [132]byte
type ECP521PrivateKey [66]byte

func (k ECP521PublicKey) Len() int {
  return len(k)
}

func (k ECP521PublicKey) NewVerifier() (Verifier, error) {
  return createECVerifier(elliptic.P521(), crypto.SHA512, k[:])
}
