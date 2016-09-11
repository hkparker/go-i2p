package crypto

import (
	"crypto/rand"
	log "github.com/Sirupsen/logrus"
	"io"
	"testing"
)

func TestDSA(t *testing.T) {
	var sk DSAPrivateKey
	var pk DSAPublicKey
	var err error
	sk, err = sk.Generate()
	if err == nil {
		zeros := 0
		for b, _ := range sk {
			if b == 0 {
				zeros++
			}
		}
		if zeros == len(sk) {
			t.Logf("key generation yielded all zeros")
			t.Fail()
		}
		pk, err = sk.Public()
		data := make([]byte, 512)
		io.ReadFull(rand.Reader, data)
		if err == nil {
			var sig []byte
			var signer Signer
			signer, err = sk.NewSigner()
			if err == nil {
				sig, err = signer.Sign(data)
				if err == nil {
					t.Logf("sig=%q", sig)
					var verify Verifier
					verify, err = pk.NewVerifier()
					if err == nil {
						err = verify.Verify(data, sig)
					}
				}
			}
		}
	}
	if err != nil {
		t.Logf("failed: %s", err.Error())
		t.Fail()
	}
}

func BenchmarkDSAGenerate(b *testing.B) {
	var sk DSAPrivateKey
	for n := 0; n < b.N; n++ {
		_, err := sk.Generate()
		if err != nil {
			panic(err.Error())
		}
	}
}

func BenchmarkDSASignVerify(b *testing.B) {
	var sk DSAPrivateKey
	var pk DSAPublicKey
	var err error
	sk, err = sk.Generate()
	if err != nil {
		panic(err.Error())
	}
	pk, err = sk.Public()
	if err != nil {
		panic(err.Error())
	}
	s, _ := sk.NewSigner()
	v, _ := pk.NewVerifier()
	data := make([]byte, 1024)
	fail := 0
	for n := 0; n < b.N; n++ {
		sig, err := s.Sign(data)
		if err != nil {
			panic(err.Error())
		}
		err = v.Verify(data, sig)
		if err != nil {
			fail++
		}
	}
	log.Infof("%d fails %d signs", fail, b.N)
}
