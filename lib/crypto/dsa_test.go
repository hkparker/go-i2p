package crypto

import (
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
				zeros ++
			}
		}
		if zeros == len(sk) {
			t.Logf("key generation yielded all zeros")
			t.Fail()
		}
		pk, err = sk.Public()
		if err == nil {
			data := make([]byte, 512)
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
