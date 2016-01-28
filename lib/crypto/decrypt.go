package crypto

// decrypts data
type Decrypter interface {
  // decrypt a block of data
  // return decrypted block or nil and error if error happens
  Decrypt(data []byte) ([]byte, error)
}

type PrivateEncryptionKey interface {

  // create a new decryption object for this private key to decrypt data encrypted to our public key
  // returns decrypter or nil and error if the private key is in a bad format
  NewDecrypter() (Decrypter, error)
}
