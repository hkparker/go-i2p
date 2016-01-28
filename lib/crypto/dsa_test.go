package crypto

import (
  "crypto/dsa"
  "crypto/rand"
  "testing"
)


func TestDSA(t *testing.T) {
  rng := rand.Reader
  kp := new(dsa.PrivateKey)
  err := DSAGenerate(kp, rng)
  if err == nil {
    t.Logf("DSA Key Pair generated")
  } else {
    t.Logf("error while generating key: %s", err)
    t.Fail()
  }
  h := make([]byte, 20)
  _, _, err = dsa.Sign(rng, kp, h)
  if err == nil {
    t.Log("signed")
  } else {
    t.Logf("error signing: %s", err)
    t.Fail()
  }
}
