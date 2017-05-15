package config

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCheckMagicBytes(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(
		nil,
		checkMagicBytes([]byte("I2Psu3")),
	)

	assert.Equal(
		ERR_NOT_ENOUGH_SU3_DATA,
		checkMagicBytes([]byte("I2Psu")),
	)

	assert.Equal(
		ERR_SU3_MAGIC_BYTES_MISMATCH,
		checkMagicBytes([]byte("I2Psu4")),
	)
}

func TestCheckByte6Unused(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(
		nil,
		checkByte6Unused(append([]byte("I2Psu3"), 0x00)),
	)

	assert.Equal(
		ERR_NOT_ENOUGH_SU3_DATA,
		checkByte6Unused([]byte("I2Psu3")),
	)

	assert.Equal(
		ERR_SU3_UNUSED_BYTE_WITH_DATA,
		checkByte6Unused(append([]byte("I2Psu3"), 0x41)),
	)
}

func TestGetFileFormatVersion(t *testing.T) {
	assert := assert.New(t)
	su3_base := append([]byte("I2Psu3"), 0x00)

	file_format_version, err := getFileFormatVersion(append(su3_base, 0x00))
	assert.Equal(nil, err)
	assert.Equal(0, file_format_version)

	file_format_version, err = getFileFormatVersion(su3_base)
	assert.Equal(ERR_NOT_ENOUGH_SU3_DATA, err)
	assert.Equal(0, file_format_version)

	file_format_version, err = getFileFormatVersion(append(su3_base, 0x01))
	assert.Equal(ERR_SU3_FILE_FORMAT_VERSION_UNKNOWN, err)
	assert.Equal(1, file_format_version)
}

func TestGetSignatureType(t *testing.T) {
	assert := assert.New(t)
	su3_base := append([]byte("I2Psu3"), []byte{0x00, 0x00}...)

	sig_type, err := getSignatureType(append(su3_base, []byte{0x00, 0x00}...))
	assert.Equal(nil, err)
	assert.Equal(SU3_SIGNATURE_TYPE_DSA_SHA1, sig_type)

	sig_type, err = getSignatureType(append(su3_base, []byte{0x00, 0x01}...))
	assert.Equal(nil, err)
	assert.Equal(SU3_SIGNATURE_TYPE_ECDSA_SHA256_P256, sig_type)

	sig_type, err = getSignatureType(append(su3_base, []byte{0x00, 0x02}...))
	assert.Equal(nil, err)
	assert.Equal(SU3_SIGNATURE_TYPE_ECDSA_SHA384_P384, sig_type)

	sig_type, err = getSignatureType(append(su3_base, []byte{0x00, 0x03}...))
	assert.Equal(nil, err)
	assert.Equal(SU3_SIGNATURE_TYPE_ECDSA_SHA512_P521, sig_type)

	sig_type, err = getSignatureType(append(su3_base, []byte{0x00, 0x04}...))
	assert.Equal(nil, err)
	assert.Equal(SU3_SIGNATURE_TYPE_RSA_SHA256_2048, sig_type)

	sig_type, err = getSignatureType(append(su3_base, []byte{0x00, 0x05}...))
	assert.Equal(nil, err)
	assert.Equal(SU3_SIGNATURE_TYPE_RSA_SHA384_3072, sig_type)

	sig_type, err = getSignatureType(append(su3_base, []byte{0x00, 0x06}...))
	assert.Equal(nil, err)
	assert.Equal(SU3_SIGNATURE_TYPE_RSA_SHA512_4096, sig_type)

	sig_type, err = getSignatureType(append(su3_base, []byte{0x00, 0x08}...))
	assert.Equal(nil, err)
	assert.Equal(SU3_SIGNATURE_TYPE_EdDSA_SHA512_Ed25519ph, sig_type)

	sig_type, err = getSignatureType(append(su3_base, []byte{0x00, 0x07}...))
	assert.Equal(ERR_SU3_SIGNATURE_TYPE_UNKNOWN, err)
	assert.Equal("", sig_type)

	sig_type, err = getSignatureType(append(su3_base, 0x00))
	assert.Equal(ERR_NOT_ENOUGH_SU3_DATA, err)
	assert.Equal("", sig_type)
}

func TestGetSignatureLength(t *testing.T) {
	assert := assert.New(t)
	su3_base := append([]byte("I2Psu3"), []byte{0x00, 0x00}...)

	sig_len, err := getSignatureLength(append(su3_base, []byte{0x00, 0x00, 0x00, 0x28}...))
	assert.Equal(nil, err)
	assert.Equal(40, sig_len)

	sig_len, err = getSignatureLength(append(su3_base, []byte{0x00, 0x00, 0x00}...))
	assert.Equal(ERR_NOT_ENOUGH_SU3_DATA, err)
	assert.Equal(0, sig_len)
}

func TestCheckByte12Unused(t *testing.T) {
	assert := assert.New(t)
	su3_base := append([]byte("I2Psu3"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x28}...)

	assert.Equal(
		nil,
		checkByte12Unused(append(su3_base, 0x00)),
	)

	assert.Equal(
		ERR_NOT_ENOUGH_SU3_DATA,
		checkByte12Unused(su3_base),
	)

	assert.Equal(
		ERR_SU3_UNUSED_BYTE_WITH_DATA,
		checkByte12Unused(append(su3_base, 0x41)),
	)
}

func TestGetVersionLength(t *testing.T) {
	assert := assert.New(t)
	su3_base := append([]byte("I2Psu3"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00}...)

	version_length, err := getVersionLength(append(su3_base, 0x10))
	assert.Equal(nil, err)
	assert.Equal(16, version_length)

	version_length, err = getVersionLength(su3_base)
	assert.Equal(ERR_NOT_ENOUGH_SU3_DATA, err)
	assert.Equal(0, version_length)

	version_length, err = getVersionLength(append(su3_base, 0x01))
	assert.Equal(ERR_SU3_VERSION_LENGTH_TOO_SMALL, err)
	assert.Equal(1, version_length)
}

func TestCheckByte14Unused(t *testing.T) {
	assert := assert.New(t)
	su3_base := append([]byte("I2Psu3"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x10}...)

	assert.Equal(
		nil,
		checkByte14Unused(append(su3_base, 0x00)),
	)

	assert.Equal(
		ERR_NOT_ENOUGH_SU3_DATA,
		checkByte14Unused(su3_base),
	)

	assert.Equal(
		ERR_SU3_UNUSED_BYTE_WITH_DATA,
		checkByte14Unused(append(su3_base, 0x41)),
	)
}

func TestGetSignerIDLength(t *testing.T) {
	assert := assert.New(t)
	su3_base := append([]byte("I2Psu3"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x10, 0x00}...)

	signer_id_length, err := getSignerIDLength(append(su3_base, 0x10))
	assert.Equal(nil, err)
	assert.Equal(16, signer_id_length)

	signer_id_length, err = getSignerIDLength(su3_base)
	assert.Equal(ERR_NOT_ENOUGH_SU3_DATA, err)
	assert.Equal(0, signer_id_length)
}

func TestGetContentLength(t *testing.T) {
	assert := assert.New(t)
	su3_base := append([]byte("I2Psu3"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x10, 0x00, 0x10}...)

	content_length, err := getContentLength(append(su3_base, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}...))
	assert.Equal(nil, err)
	assert.Equal(1, content_length)

	content_length, err = getContentLength(append(su3_base, []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...))
	assert.Equal(ERR_NOT_ENOUGH_SU3_DATA, err)
	assert.Equal(0, content_length)
}

func TestCheckByte24Unused(t *testing.T) {
	assert := assert.New(t)
	su3_base := append([]byte("I2Psu3"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x10, 0x000, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}...)

	assert.Equal(
		nil,
		checkByte24Unused(append(su3_base, 0x00)),
	)

	assert.Equal(
		ERR_NOT_ENOUGH_SU3_DATA,
		checkByte24Unused(su3_base),
	)

	assert.Equal(
		ERR_SU3_UNUSED_BYTE_WITH_DATA,
		checkByte24Unused(append(su3_base, 0x41)),
	)
}

func TestGetFileType(t *testing.T) {
	assert := assert.New(t)
	su3_base := append([]byte("I2Psu3"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x10, 0x000, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}...)

	sig_type, err := getFileType(append(su3_base, 0x00))
	assert.Equal(nil, err)
	assert.Equal(SU3_FILE_TYPE_ZIP, sig_type)

	sig_type, err = getFileType(append(su3_base, 0x01))
	assert.Equal(nil, err)
	assert.Equal(SU3_FILE_TYPE_XML, sig_type)

	sig_type, err = getFileType(append(su3_base, 0x02))
	assert.Equal(nil, err)
	assert.Equal(SU3_FILE_TYPE_HTML, sig_type)

	sig_type, err = getFileType(append(su3_base, 0x03))
	assert.Equal(nil, err)
	assert.Equal(SU3_FILE_TYPE_XML_GZ, sig_type)

	sig_type, err = getFileType(append(su3_base, 0x04))
	assert.Equal(nil, err)
	assert.Equal(SU3_FILE_TYPE_TXT_GZ, sig_type)

	sig_type, err = getFileType(append(su3_base, 0x05))
	assert.Equal(ERR_SU3_FILE_TYPE_UNKNOWN, err)
	assert.Equal("", sig_type)

	sig_type, err = getFileType(su3_base)
	assert.Equal(ERR_NOT_ENOUGH_SU3_DATA, err)
	assert.Equal("", sig_type)
}

func TestCheckByte26Unused(t *testing.T) {
	assert := assert.New(t)
	su3_base := append([]byte("I2Psu3"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x10, 0x000, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}...)

	assert.Equal(
		nil,
		checkByte26Unused(append(su3_base, 0x00)),
	)

	assert.Equal(
		ERR_NOT_ENOUGH_SU3_DATA,
		checkByte26Unused(su3_base),
	)

	assert.Equal(
		ERR_SU3_UNUSED_BYTE_WITH_DATA,
		checkByte26Unused(append(su3_base, 0x41)),
	)
}

func TestGetContextType(t *testing.T) {
	assert := assert.New(t)
	su3_base := append([]byte("I2Psu3"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x10, 0x000, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}...)

	content_type, err := getContentType(append(su3_base, 0x00))
	assert.Equal(nil, err)
	assert.Equal(SU3_CONTENT_TYPE_UNKNOWN, content_type)

	content_type, err = getContentType(append(su3_base, 0x01))
	assert.Equal(nil, err)
	assert.Equal(SU3_CONTENT_TYPE_ROUTER_UPDATE, content_type)

	content_type, err = getContentType(append(su3_base, 0x02))
	assert.Equal(nil, err)
	assert.Equal(SU3_CONTENT_TYPE_PLUGIN_UPDATE, content_type)

	content_type, err = getContentType(append(su3_base, 0x03))
	assert.Equal(nil, err)
	assert.Equal(SU3_CONTENT_TYPE_RESEED_DATA, content_type)

	content_type, err = getContentType(append(su3_base, 0x04))
	assert.Equal(nil, err)
	assert.Equal(SU3_CONTENT_TYPE_NEWS_FEED, content_type)

	content_type, err = getContentType(append(su3_base, 0x05))
	assert.Equal(nil, err)
	assert.Equal(SU3_CONTENT_TYPE_BLOCKLIST_FEED, content_type)

	content_type, err = getContentType(append(su3_base, 0x06))
	assert.Equal(ERR_SU3_CONTENT_TYPE_UNKNOWN, err)
	assert.Equal("", content_type)

	content_type, err = getContentType(su3_base)
	assert.Equal(ERR_NOT_ENOUGH_SU3_DATA, err)
	assert.Equal("", content_type)
}

func TestCheckBytes28To39Unused(t *testing.T) {
	assert := assert.New(t)
	su3_base := append([]byte("I2Psu3"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x10, 0x000, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}...)

	assert.Equal(
		nil,
		checkBytes28To39Unused(append(su3_base, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)),
	)

	assert.Equal(
		ERR_NOT_ENOUGH_SU3_DATA,
		checkBytes28To39Unused(append(su3_base, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)),
	)

	assert.Equal(
		ERR_SU3_UNUSED_BYTE_WITH_DATA,
		checkBytes28To39Unused(append(su3_base, []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)),
	)

	assert.Equal(
		ERR_SU3_UNUSED_BYTE_WITH_DATA,
		checkBytes28To39Unused(append(su3_base, []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)),
	)

	assert.Equal(
		ERR_SU3_UNUSED_BYTE_WITH_DATA,
		checkBytes28To39Unused(append(su3_base, []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)),
	)

	assert.Equal(
		ERR_SU3_UNUSED_BYTE_WITH_DATA,
		checkBytes28To39Unused(append(su3_base, []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)),
	)

	assert.Equal(
		ERR_SU3_UNUSED_BYTE_WITH_DATA,
		checkBytes28To39Unused(append(su3_base, []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)),
	)

	assert.Equal(
		ERR_SU3_UNUSED_BYTE_WITH_DATA,
		checkBytes28To39Unused(append(su3_base, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)),
	)

	assert.Equal(
		ERR_SU3_UNUSED_BYTE_WITH_DATA,
		checkBytes28To39Unused(append(su3_base, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}...)),
	)

	assert.Equal(
		ERR_SU3_UNUSED_BYTE_WITH_DATA,
		checkBytes28To39Unused(append(su3_base, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}...)),
	)

	assert.Equal(
		ERR_SU3_UNUSED_BYTE_WITH_DATA,
		checkBytes28To39Unused(append(su3_base, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}...)),
	)

	assert.Equal(
		ERR_SU3_UNUSED_BYTE_WITH_DATA,
		checkBytes28To39Unused(append(su3_base, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}...)),
	)

	assert.Equal(
		ERR_SU3_UNUSED_BYTE_WITH_DATA,
		checkBytes28To39Unused(append(su3_base, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}...)),
	)

	assert.Equal(
		ERR_SU3_UNUSED_BYTE_WITH_DATA,
		checkBytes28To39Unused(append(su3_base, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}...)),
	)
}

func TestGetVersion(t *testing.T) {
	assert := assert.New(t)
	su3_base := append([]byte("I2Psu3"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x10, 0x000, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}...)
	su3_base = append(su3_base, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)

	version, err := getVersion(append(su3_base, []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...))
	assert.Equal(nil, err)
	assert.Equal("A", version)

	version, err = getVersion(append(su3_base, []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...))
	assert.Equal(ERR_NOT_ENOUGH_SU3_DATA, err)
	assert.Equal("", version)

	su3_base[13] = 0x11
	version, err = getVersion(append(su3_base, []byte{0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41}...))
	assert.Equal(nil, err)
	assert.Equal("AAAAAAAAAAAAAAAAA", version)
}

func TestGetSignerID(t *testing.T) {
	assert := assert.New(t)
	su3_base := append([]byte("I2Psu3"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x10, 0x000, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}...)
	su3_base = append(su3_base, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
	su3_base = append(su3_base, []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)

	signer_id, err := getSignerID(append(su3_base, 0x41))
	assert.Equal(nil, err)
	assert.Equal("A", signer_id)

	signer_id, err = getSignerID(su3_base)
	assert.Equal(ERR_NOT_ENOUGH_SU3_DATA, err)
	assert.Equal("", signer_id)
}

func TestGetContent(t *testing.T) {
	assert := assert.New(t)
	su3_base := append([]byte("I2Psu3"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x10, 0x000, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}...)
	su3_base = append(su3_base, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
	su3_base = append(su3_base, []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
	su3_base = append(su3_base, 0x41)

	content, err := getContent(append(su3_base, 0x42))
	assert.Equal(nil, err)
	assert.Equal("B", string(content))

	su3_base[23] = 0x02
	content, err = getContent(append(su3_base, []byte{0x42, 0x42}...))
	assert.Equal(nil, err)
	assert.Equal("BB", string(content))

	content, err = getContent(su3_base)
	assert.Equal(ERR_NOT_ENOUGH_SU3_DATA, err)
	assert.Equal([]byte{}, content)
}

func TestGetSignature(t *testing.T) {
	assert := assert.New(t)
	su3_base := append([]byte("I2Psu3"), []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x10, 0x000, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}...)
	su3_base = append(su3_base, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
	su3_base = append(su3_base, []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
	su3_base = append(su3_base, []byte{0x41, 0x42}...)

	signature, err := getSignature(append(su3_base, make([]byte, 40)...))
	assert.Equal(nil, err)
	assert.Equal(make([]byte, 40), signature)

	signature, err = getSignature(append(su3_base, make([]byte, 39)...))
	assert.Equal(ERR_NOT_ENOUGH_SU3_DATA, err)
	assert.Equal([]byte{}, signature)
}
