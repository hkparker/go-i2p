package crypto

/*
#cgo pkg-config: libsodium
#include <sodium.h>
#include <stdint.h>
*/
import "C"

import (
	"crypto/sha512"
	"errors"
	"fmt"
)

type Ed25519PublicKey [32]byte

type Ed25519Verifier struct {
	k [32]C.uchar
}

func (k Ed25519PublicKey) NewVerifier() (v Verifier, err error) {
	ev := new(Ed25519Verifier)
	for i, b := range k {
		ev.k[i] = C.uchar(b)
	}
	v = ev
	return
}

func (v *Ed25519Verifier) VerifyHash(h, sig []byte) (err error) {
	if len(sig) == C.crypto_sign_BYTES {
		// valid size of sig
		// copy signature and hash
		var csig, ch [32]C.uchar
		for i, b := range h {
			ch[i] = C.uchar(b)
		}
		for i, b := range sig {
			csig[i] = C.uchar(b)
		}
		// verify
		if C.crypto_sign_verify_detached(&csig[0], &ch[0], C.ulonglong(32), &v.k[0]) == 0 {
			// valid signature
		} else {
			// bad signature
			err = ErrInvalidSignature
		}
	} else {
		// bad size of sig
		err = ErrBadSignatureSize
	}
	return
}

func (v *Ed25519Verifier) Verify(data, sig []byte) (err error) {
	h := sha512.Sum512(data)
	err = v.VerifyHash(h[:], sig)
	return
}

type Ed25519PrivateKey [32]byte

type Ed25519Signer struct {
	k [32]C.uchar
}

func (s *Ed25519Signer) Sign(data []byte) (sig []byte, err error) {
	h := sha512.Sum512(data)
	sig, err = s.SignHash(h[:])
	return
}

func (s *Ed25519Signer) SignHash(h []byte) (sig []byte, err error) {
	var ch [32]C.uchar
	for i, b := range h {
		ch[i] = C.uchar(b)
	}
	var csig [32]C.uchar
	var smlen_p C.ulonglong
	res := C.crypto_sign_detached(&csig[0], &smlen_p, &ch[0], C.ulonglong(32), &s.k[0])
	if res == 0 {
		// success signing
		sig = make([]byte, 32)
		for i, b := range csig {
			sig[i] = byte(b)
		}
	} else {
		// failed signing
		err = errors.New(fmt.Sprintf("failed to sign: crypto_sign_detached exit code %d", int(res)))
	}
	return
}
