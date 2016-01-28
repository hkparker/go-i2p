package crypto

import (
  "bytes"
  "crypto/rand"
  "golang.org/x/crypto/openpgp/elgamal"
  "io"
  "testing"
)


func TestElg(t *testing.T) {
  k := new(elgamal.PrivateKey)
  err := ElgamalGenerate(k, rand.Reader)
  if err == nil {
    msg := make([]byte, 222)
      _, err := io.ReadFull(rand.Reader, msg)
    if err == nil {
      pub := createElgamalPublicKey(k.Y.Bytes())
      enc, err := createElgamalEncryption(pub, rand.Reader)
      if err == nil {
        emsg, err := enc.Encrypt(msg)
        if err == nil {
          dec, err := ElgamelDecrypt(k, emsg, true)
          if err == nil {
            if ! bytes.Equal(dec, msg) {
              t.Logf("%q != %q", dec, msg)
              t.Fail()
            }
          } else {
            t.Logf("decrypt failed: %s", err.Error())
            t.Fail()
          }
        } else {
          t.Logf("failed to encrypt message: %s", err.Error())
          t.Fail()
        }
      } else {
        t.Logf("failed to create encryption: %s", err.Error())
        t.Fail()
      }
    } else {
      t.Logf("failed to generate random message: %s", err.Error())
      t.Fail()
    }
  } else {
    t.Logf("error while generating key: %s", err.Error())
    t.Fail()
  }
}
