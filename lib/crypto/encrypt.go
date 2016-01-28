package crypto

type Encrypter interface {
  // encrypt a block of data
  // return encrypted block or nil and error if an error happened
  Encrypt(data []byte) (enc []byte, err error)
}

type PublicEncryptionKey interface {

  // create a new encrypter to encrypt data to this public key
  NewEncrypter() (Encrypter, error)
  
  // length of this public key in bytes
  Len() int
}
