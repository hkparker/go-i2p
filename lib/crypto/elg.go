package crypto

import (
  "crypto/rand"
  "crypto/sha256"
  "crypto/subtle"
  "errors"
  "golang.org/x/crypto/openpgp/elgamal"
  "io"
  "math/big"
)

var elgp = new(big.Int).SetBytes([]byte{
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
  0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
  0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
  0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
  0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
  0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
  0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
  0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
  0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
  0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
  0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
  0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
  0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
  0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
  0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
  0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
})

var one = big.NewInt(1)
var elgg = big.NewInt(2)

var ElgDecryptFail = errors.New("failed to decrypt elgamal encrypted data")
var ElgEncryptTooBig = errors.New("failed to encrypt data, too big for elgamal")

// generate an elgamal key pair
func ElgamalGenerate(priv *elgamal.PrivateKey, rand io.Reader) (err error) {
  priv.P = elgp
  priv.G = elgg
  xBytes := make([]byte, priv.P.BitLen()/8)
  _, err = io.ReadFull(rand, xBytes)
  if err == nil {
    // set private key
    priv.X = new(big.Int).SetBytes(xBytes)
    // compute public key
    priv.Y = new(big.Int).Exp(priv.G, priv.X, priv.P)
  }
  return
}

type elgDecrypter struct {
  k *elgamal.PrivateKey
}

func (elg elgDecrypter) Decrypt(data []byte) (dec []byte, err error) {
  dec, err = elgamalDecrypt(elg.k , data, true) // TODO(psi): should this be true or false?
  return
}

// decrypt an elgamal encrypted message, i2p style
func elgamalDecrypt(priv *elgamal.PrivateKey, data []byte, zeroPadding bool) (decrypted []byte, err error) {
  a := new(big.Int)
  b := new(big.Int)
  idx := 0
  if zeroPadding {
    idx ++
  }
  a.SetBytes(data[idx : idx + 256])
  if zeroPadding {
    idx ++
  }
  b.SetBytes(data[idx + 256:])

  // decrypt
  m := new(big.Int).Mod(new(big.Int).Mul(b, new(big.Int).Exp(a,new(big.Int).Sub(new(big.Int).Sub(priv.P, priv.X), one), priv.P)), priv.P).Bytes()

  // check digest
  d := sha256.Sum256(m[33:255])
  good := 0
  if subtle.ConstantTimeCompare(d[:], m[1:33]) == 1 {
    // decryption successful
    good = 1
  } else {
    // decrypt failed
    err = ElgDecryptFail
  }
  // copy result 
  decrypted = make([]byte, 222)
  subtle.ConstantTimeCopy(good, decrypted, m[33:255])
  
  if good == 0 {
    // if decrypt failed nil out decrypted slice
    decrypted = nil
  }
  return
}


type ElgamalEncryption struct {
  p, a, b1 *big.Int
}

func (elg *ElgamalEncryption) Encrypt(data []byte) (enc []byte, err error) {
  return elg.EncryptPadding(data, true)
}

func (elg *ElgamalEncryption) EncryptPadding(data []byte, zeroPadding bool) (encrypted []byte, err error) {
  if len(data) > 222 {
    err = ElgEncryptTooBig
    return
  }
  mbytes := make([]byte, 255)
  mbytes[0] = 0xFF
  copy(mbytes[33:], data)
  // do sha256 of payload
  d := sha256.Sum256(mbytes[33:len(data)+33])
  copy(mbytes[1:], d[:])
  m := new(big.Int).SetBytes(mbytes)
  // do encryption
  b := new(big.Int).Mod(new(big.Int).Mul(elg.b1, m), elg.p).Bytes()

  if zeroPadding {
    encrypted = make([]byte, 514)
    copy(encrypted[1:], elg.a.Bytes())
    copy(encrypted[258:], b)
  } else {
    encrypted = make([]byte, 512)
    copy(encrypted, elg.a.Bytes())
    copy(encrypted[256:], b)
  }
  return
}

// create an elgamal public key from byte slice
func createElgamalPublicKey(data []byte) (k *elgamal.PublicKey) {
  if len(data) == 256 {
    k = &elgamal.PublicKey{
      G: elgg,
      P: elgp,
      Y: new(big.Int).SetBytes(data),
    }
  }
  return
}

// create an elgamal private key from byte slice
func createElgamalPrivateKey(data []byte) (k *elgamal.PrivateKey) {
  if len(data) == 256 {
    x := new(big.Int).SetBytes(data)
    y := new(big.Int).Exp(elgg, x, elgp)
    k = &elgamal.PrivateKey{
      PublicKey: elgamal.PublicKey{
        Y: y,
        G: elgg,
        P: elgp,
      },
      X: x,
    }
  }
  return
}

// create a new elgamal encryption session
func createElgamalEncryption(pub *elgamal.PublicKey, rand io.Reader) (enc *ElgamalEncryption, err error) {
  kbytes := make([]byte, 256)
  k := new(big.Int)
  for err == nil {
    _, err = io.ReadFull(rand, kbytes)
    k = new(big.Int).SetBytes(kbytes)
    k = k.Mod(k, pub.P)
    if k.Sign() != 0 {
      break
    }
  }
  if err == nil {
    enc = &ElgamalEncryption{
      p: pub.P,
      a: new(big.Int).Exp(pub.G, k, pub.P),
      b1: new(big.Int).Exp(pub.Y, k, pub.P),
    }
  }
  return
}


type ElgPublicKey [256]byte
type ElgPrivateKey [256]byte

func (elg ElgPublicKey) Len() int {
  return len(elg)
}

func (elg ElgPublicKey) NewEncrypter() (enc Encrypter, err error) {
  k := createElgamalPublicKey(elg[:])
  enc, err = createElgamalEncryption(k, rand.Reader)
  return
}


func (elg ElgPrivateKey) Len() int {
  return len(elg)
}

func (elg ElgPrivateKey) NewDecrypter() (dec Decrypter, err error) {
  dec = elgDecrypter{
    k: createElgamalPrivateKey(elg[:]),
  }
  return
}
