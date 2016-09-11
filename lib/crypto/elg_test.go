package crypto

import (
	"bytes"
	"crypto/rand"
	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/openpgp/elgamal"
	"io"
	"testing"
)

func BenchmarkElgGenerate(b *testing.B) {
	k := new(elgamal.PrivateKey)
	for n := 0; n < b.N; n++ {
		err := ElgamalGenerate(k, rand.Reader)
		if err != nil {
			panic(err.Error())
		}
	}
}

func BenchmarkElgDecrypt(b *testing.B) {
	prv := new(elgamal.PrivateKey)
	err := ElgamalGenerate(prv, rand.Reader)
	if err != nil {
		panic(err.Error())
	}
	pub := createElgamalPublicKey(prv.Y.Bytes())
	enc, err := createElgamalEncryption(pub, rand.Reader)
	if err != nil {
		panic(err.Error())
	}
	d := make([]byte, 222)
	_, _ = io.ReadFull(rand.Reader, d)
	c, err := enc.Encrypt(d)
	fails := 0
	dec := &elgDecrypter{
		k: prv,
	}
	for n := 0; n < b.N; n++ {
		p, err := dec.Decrypt(c)
		if err != nil {
			fails++
		} else if !bytes.Equal(p, d) {
			fails++
		}
	}
	log.Infof("%d fails %d rounds", fails, b.N)

}

func BenchmarkElgEncrypt(b *testing.B) {
	prv := new(elgamal.PrivateKey)
	err := ElgamalGenerate(prv, rand.Reader)
	if err != nil {
		panic(err.Error())
	}
	pub := createElgamalPublicKey(prv.Y.Bytes())
	enc, err := createElgamalEncryption(pub, rand.Reader)
	if err != nil {
		panic(err.Error())
	}
	d := make([]byte, 222)
	_, err = io.ReadFull(rand.Reader, d)
	fails := 0
	for n := 0; n < b.N; n++ {
		_, err := enc.Encrypt(d)
		if err != nil {
			fails++
		}
	}
	log.Infof("%d fails %d rounds", fails, b.N)
}

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
					dec, err := elgamalDecrypt(k, emsg, true)
					if err == nil {
						if bytes.Equal(dec, msg) {
							t.Logf("%q == %q", dec, msg)
						} else {
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
