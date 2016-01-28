package crypto

import (
  "errors"
)

var ErrBadSignatureSize = errors.New("bad signature size")
var ErrInvalidKeyFormat = errors.New("invalid key format")
var ErrInvalidSignature = errors.New("invalid signature")

// type for verifying signatures
type Verifier interface {
  // verify hashed data with this signing key
  // return nil on valid signature otherwise error
  VerifyHash(data, sig []byte) error
  // verify an unhashed piece of data by hashing it and calling VerifyHash
  Verify(data, sig []byte) error
}

// key for verifying data
type SigningPublicKey interface {
  // create new Verifier to verify the validity of signatures
  // return verifier or nil and error if key format is invalid
  NewVerifier() (Verifier, error)
  // get the size of this public key
  Len() int
}


// type for signing data
type Signer interface {
  // sign data with our private key by calling SignHash after hashing the data we are given
  // return signature or nil signature and error if an error happened
  Sign(data []byte) (sig []byte, err error)
  
  // sign hash of data with our private key
  // return signature or nil signature and error if an error happened
  SignHash(h []byte) (sig []byte, err error)
}


// key for signing data
type SigningPrivateKey interface {
  // create a new signer to sign data
  // return signer or nil and error if key format is invalid
  NewSigner() (Signer, error)

  Len() int
}
