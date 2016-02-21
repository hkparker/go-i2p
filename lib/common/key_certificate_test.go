package common

import (
	"testing"
)

func TestSingingPublicKeyTypeReturnsCorrectInteger(t *testing.T) {
	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x03, 0x00, 0x00})
	pk_type, err := key_cert.SigningPublicKeyType()
	if err != nil {
		t.Fatal("err reading SigningPublicKey type on valid data:", err)
	}
	if pk_type != KEYCERT_SIGN_P521 {
		t.Fatal("SigningPublicKeyType did not return correct type:", pk_type)
	}
}

func TestSingingPublicKeyTypeReportsWhenDataTooSmall(t *testing.T) {
	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x01, 0x00})
	_, err := key_cert.SigningPublicKeyType()
	if err == nil || err.Error() != "error parsing key certificate: not enough data" {
		t.Fatal("incorrect error reported by SigningPublicKeyType:", err)
	}
}

func TestPublicKeyTypeReturnsCorrectInteger(t *testing.T) {
	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03})
	pk_type, err := key_cert.PublicKeyType()
	if err != nil {
		t.Fatal("err reading PublicKey type on valid data:", err)
	}
	if pk_type != KEYCERT_SIGN_P521 {
		t.Fatal("PublicKeyType did not return correct type:", pk_type)
	}
}

func TestPublicKeyTypeReportsWhenDataTooSmall(t *testing.T) {
	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x02, 0x00, 0x00})
	_, err := key_cert.PublicKeyType()
	if err == nil || err.Error() != "error parsing key certificate: not enough data" {
		t.Fatal("incorrect error reported by PublicKeyType:", err)
	}
}

func TestConstructPublicKeyReportsWhenDataTooSmall(t *testing.T) {
	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00})
	data := make([]byte, 255)
	_, err := key_cert.ConstructPublicKey(data)
	if err == nil || err.Error() != "error constructing public key: not enough data" {
		t.Fatal("ConstructPubliKey reported incorrect error with missing data:", err)
	}
}

func TestConstructPublicKeyReturnsCorrectDataWithElg(t *testing.T) {
	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00})
	data := make([]byte, 256)
	pk, err := key_cert.ConstructPublicKey(data)
	if err != nil {
		t.Fatal("ConstructPublicKey returned error with valid data:", err)
	}
	if pk.Len() != 256 {
		t.Fatal("ConstructPublicKey did not return public key with correct length")
	}
}

func TestConstructSigningPublicKeyReportsWhenDataTooSmall(t *testing.T) {
	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00})
	data := make([]byte, 127)
	_, err := key_cert.ConstructSigningPublicKey(data)
	if err == nil || err.Error() != "error constructing signing public key: not enough data" {
		t.Fatal("ConstructSigngingPubliKey reported incorrect error with missing data:", err)
	}
}

func TestConstructSigningPublicKeyWithDSASHA1(t *testing.T) {
	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00})
	data := make([]byte, 128)
	spk, err := key_cert.ConstructSigningPublicKey(data)
	if err != nil {
		t.Fatal("ConstructSigningPublicKey with DSA SHA1 returned err on valid data:", err)
	}
	spk_len := spk.Len()
	if spk_len != KEYCERT_SIGN_DSA_SHA1_SIZE {
		t.Fatal("ConstructSigningPublicKeyWithDSASHA1 returned incorrect SigningPublicKey length:", spk_len)
	}
}

func TestConstructSigningPublicKeyWithP256(t *testing.T) {
	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01})
	data := make([]byte, 128)
	spk, err := key_cert.ConstructSigningPublicKey(data)
	if err != nil {
		t.Fatal("ConstructSigningPublicKey with P256 returned err on valid data:", err)
	}
	spk_len := spk.Len()
	if spk_len != KEYCERT_SIGN_P256_SIZE {
		t.Fatal("ConstructSigningPublicKey with P256 returned incorrect SigningPublicKey length:", spk_len)
	}
}

func TestConstructSigningPublicKeyWithP384(t *testing.T) {
	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x04, 0x00, 0x02, 0x00, 0x02})
	data := make([]byte, 128)
	spk, err := key_cert.ConstructSigningPublicKey(data)
	if err != nil {
		t.Fatal("ConstructSigningPublicKey with P384 returned err on valid data:", err)
	}
	spk_len := spk.Len()
	if spk_len != KEYCERT_SIGN_P384_SIZE {
		t.Fatal("ConstructSigningPublicKey with P384 returned incorrect SigningPublicKey length:", spk_len)
	}
}

func TestConstructSigningPublicKeyWithP521(t *testing.T) {
	key_cert := KeyCertificate([]byte{0x05, 0x00, 0x08, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00})
	data := make([]byte, 128)
	spk, err := key_cert.ConstructSigningPublicKey(data)
	if err != nil {
		t.Fatal("ConstructSigningPublicKey with P521 returned err on valid data:", err)
	}
	spk_len := spk.Len()
	if spk_len != KEYCERT_SIGN_P521_SIZE {
		t.Fatal("ConstructSigningPublicKey with P521 returned incorrect SigningPublicKey length:", spk_len)
	}
}
