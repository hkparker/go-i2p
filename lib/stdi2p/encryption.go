package stdi2p

import (
  "crypto/rand"
  "github.com/bounce-chat/go-i2p/lib/crypto"
)

// AES session key
type SessionKey [32]byte 

// key used for encrypting via public key cryptography
type PublicEncryptionKey interface {
  // encrypt data to this public key
  // return encrypted data or nil and error
  Encrypt(data []byte) ([]byte, error)
}

// public encryption key
type ElgPublicKey [256]byte

// generate a new encrypter session
func (k ElgPublicKey) NewEncrypter() (enc PublicEncryptionKey, err error) {
  enc, err = crypto.NewElgamalEncryption(crypto.ElgamalPublicKey(k[:]), rand.Reader)
  return
}

func (k ElgPublicKey) Encrypt(data []byte) (enc []byte, err error) {
  var ek PublicEncryptionKey
  // TODO(psi): do we really want to generate a new encryption session every time?
  ek, err = k.NewEncrypter()
  if err == nil {
    enc, err = ek.Encrypt(data)
  }
  ek = nil
  return
}

// private encryption key
type ElgPrivateKey [256]byte
