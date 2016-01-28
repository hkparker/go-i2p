package stdi2p

import (
  "crypto/dsa"
  "crypto/ecdsa"
  "crypto/elliptic"
  "errors"
  "github.com/bounce-chat/go-i2p/lib/crypto"
  "math/big"
)

var ErrBadSignatureSize = errors.New("bad signature size")
var ErrInvalidKeyFormat = errors.New("invalid key format")
var ErrInvalidSignature = errors.New("invalid signature")

// key for verifying data
type SigningPublicKey interface {
  // verify hashed data with this signing key
  // return nil on valid signature otherwise error
  Verify(data, sig []byte) error
  // get the size of this public key
  Len() int
}


// key for signing data
type SigningPrivateKey interface {
  // sign data with our private key
  // return signature or nil signature and error if an error happened
  Sign(data []byte) (sig []byte, err error)
}

type DSAPublicKey [128]byte
type DSAPrivateKey [20]byte

// verify data with a dsa public key
func (dpk DSAPublicKey) Verify(data, sig []byte) (err error) {
  if len(sig) == 40 {
    k := crypto.DSAPublicKey(new(big.Int).SetBytes(dpk[:]))
    r := new(big.Int).SetBytes(sig[:20])
    s := new(big.Int).SetBytes(sig[20:])
    if dsa.Verify(k, data, r, s) {
      // valid signature
    } else {
      // invalid signature
      err = ErrInvalidSignature
    }
  } else {
    err = ErrBadSignatureSize
  }
  return
}

func (k DSAPublicKey) Len() int {
  return len(k)
}


func ecVerify(c elliptic.Curve, k, data, sig []byte) (err error) {
  x, y := elliptic.Unmarshal(c, k[:])
  if x == nil {
    err = ErrInvalidKeyFormat
  } else {
    pk := &ecdsa.PublicKey{c, x, y}
    r, s := elliptic.Unmarshal(c, sig)
    if r == nil || s == nil || ! ecdsa.Verify(pk, data, r, s) {
      err = ErrInvalidSignature
    }
  }
  return
}

type ECP256PublicKey [64]byte
type ECP256PrivateKey [32]byte

func (k ECP256PublicKey) Len() int {
  return len(k)
}

func (k ECP256PublicKey) Verify(data, sig []byte) (err error) {
  err = ecVerify(elliptic.P256(), k[:], data, sig)
  return
}

type ECP384PublicKey [96]byte
type ECP384PrivateKey [48]byte

func (k ECP384PublicKey) Len() int {
  return len(k)
}

func (k ECP384PublicKey) Verify(data, sig []byte) (err error) {
  err = ecVerify(elliptic.P384(), k[:], data, sig)
  return
}

type ECP521PublicKey [132]byte
type ECP521PrivateKey [66]byte

func (k ECP521PublicKey) Len() int {
  return len(k)
}

func (k ECP521PublicKey) Verify(data, sig []byte) (err error) {
  err = ecVerify(elliptic.P521(), k[:], data, sig)
  return
}
type RSA2048PublicKey [256]byte
type RSA2048PrivateKey [512]byte

type RSA3072PublicKey [384]byte
type RSA3072PrivateKey [786]byte

type RSA4096PublicKey [512]byte
type RSA4096PrivateKey [1024]byte

type Ed25519PublicKey [32]byte
type Ed25519PrivateKey [32]byte
