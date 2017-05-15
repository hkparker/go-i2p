package config

import (
	"errors"
	log "github.com/Sirupsen/logrus"
	"github.com/hkparker/go-i2p/lib/common"
	"strings"
	"unicode/utf8"
)

//
// https://geti2p.net/spec/updates
//

const SU3_MAGIC_BYTES = "I2Psu3"
const SU3_MAGIC_BYTE_LEN = 6
const SU3_SIGNATURE_TYPE_LEN = 2
const SU3_SIGNATURE_LENGTH_LEN = 2
const SU3_CONTENT_LENGTH_LEN = 8

var SU3_SIGNATURE_TYPE_DSA_SHA1 = "DSA-SHA1"
var SU3_SIGNATURE_TYPE_ECDSA_SHA256_P256 = "ECDSA-SHA256-P256"
var SU3_SIGNATURE_TYPE_ECDSA_SHA384_P384 = "ECDSA-SHA384-P384"
var SU3_SIGNATURE_TYPE_ECDSA_SHA512_P521 = "ECDSA-SHA512-P521"
var SU3_SIGNATURE_TYPE_RSA_SHA256_2048 = "RSA-SHA256-2048"
var SU3_SIGNATURE_TYPE_RSA_SHA384_3072 = "RSA-SHA384-3072"
var SU3_SIGNATURE_TYPE_RSA_SHA512_4096 = "RSA-SHA512-4096"
var SU3_SIGNATURE_TYPE_EdDSA_SHA512_Ed25519ph = "EdDSA-SHA512-Ed25519ph"

var SU3_FILE_TYPE_ZIP = "zip"
var SU3_FILE_TYPE_XML = "xml"
var SU3_FILE_TYPE_HTML = "html"
var SU3_FILE_TYPE_XML_GZ = "xml.gz"
var SU3_FILE_TYPE_TXT_GZ = "txt.gz"

var SU3_CONTENT_TYPE_UNKNOWN = "unknown"
var SU3_CONTENT_TYPE_ROUTER_UPDATE = "router_update"
var SU3_CONTENT_TYPE_PLUGIN_UPDATE = "plugin_update"
var SU3_CONTENT_TYPE_RESEED_DATA = "reseed_data"
var SU3_CONTENT_TYPE_NEWS_FEED = "news_feed"
var SU3_CONTENT_TYPE_BLOCKLIST_FEED = "blocklist_feed"

var SU3_SIGNATURE_TYPE_MAP = map[[SU3_SIGNATURE_TYPE_LEN]byte]string{
	[SU3_SIGNATURE_TYPE_LEN]byte{0x00, 0x00}: SU3_SIGNATURE_TYPE_DSA_SHA1,
	[SU3_SIGNATURE_TYPE_LEN]byte{0x00, 0x01}: SU3_SIGNATURE_TYPE_ECDSA_SHA256_P256,
	[SU3_SIGNATURE_TYPE_LEN]byte{0x00, 0x02}: SU3_SIGNATURE_TYPE_ECDSA_SHA384_P384,
	[SU3_SIGNATURE_TYPE_LEN]byte{0x00, 0x03}: SU3_SIGNATURE_TYPE_ECDSA_SHA512_P521,
	[SU3_SIGNATURE_TYPE_LEN]byte{0x00, 0x04}: SU3_SIGNATURE_TYPE_RSA_SHA256_2048,
	[SU3_SIGNATURE_TYPE_LEN]byte{0x00, 0x05}: SU3_SIGNATURE_TYPE_RSA_SHA384_3072,
	[SU3_SIGNATURE_TYPE_LEN]byte{0x00, 0x06}: SU3_SIGNATURE_TYPE_RSA_SHA512_4096,
	[SU3_SIGNATURE_TYPE_LEN]byte{0x00, 0x08}: SU3_SIGNATURE_TYPE_EdDSA_SHA512_Ed25519ph,
}

var SU3_FILE_TYPE_MAP = map[byte]string{
	0x00: SU3_FILE_TYPE_ZIP,
	0x01: SU3_FILE_TYPE_XML,
	0x02: SU3_FILE_TYPE_HTML,
	0x03: SU3_FILE_TYPE_XML_GZ,
	0x04: SU3_FILE_TYPE_TXT_GZ,
}

var SU3_CONTENT_TYPE_MAP = map[byte]string{
	0x00: SU3_CONTENT_TYPE_UNKNOWN,
	0x01: SU3_CONTENT_TYPE_ROUTER_UPDATE,
	0x02: SU3_CONTENT_TYPE_PLUGIN_UPDATE,
	0x03: SU3_CONTENT_TYPE_RESEED_DATA,
	0x04: SU3_CONTENT_TYPE_NEWS_FEED,
	0x05: SU3_CONTENT_TYPE_BLOCKLIST_FEED,
}

var ERR_NOT_ENOUGH_SU3_DATA = errors.New("not enough data for su3")
var ERR_SU3_MAGIC_BYTES_MISMATCH = errors.New("magic bytes do not match I2Psu3")
var ERR_SU3_UNUSED_BYTE_WITH_DATA = errors.New("unused byte in su3 specification contains data")
var ERR_SU3_SIGNATURE_TYPE_UNKNOWN = errors.New("unknown signature type")
var ERR_SU3_FILE_FORMAT_VERSION_UNKNOWN = errors.New("unknown file format version")
var ERR_SU3_VERSION_LENGTH_TOO_SMALL = errors.New("version length is too small")
var ERR_SU3_FILE_TYPE_UNKNOWN = errors.New("unknown file type")
var ERR_SU3_CONTENT_TYPE_UNKNOWN = errors.New("unknown content type")
var ERR_SU3_VERSION_NOT_UTF8 = errors.New("version not utf8")
var ERR_SU3_SIGNER_ID_NOT_UTF8 = errors.New("version not utf8")

type SU3 struct {
	Raw               []byte
	FileFormatVersion int
	SignatureType     string
	SignatureLength   int
	VersionLength     int
	SignerIDLength    int
	ContentLength     int
	FileType          string
	ContentType       string
	Version           string
	SignerID          string
	Content           []byte
	Signature         []byte
}

func OpenSU3() {}

func ReadSU3(data []byte) (SU3, error) {
	su3 := SU3{
		Raw: data,
	}

	if err := checkMagicBytes(data); err != nil {
		return su3, err
	}
	if err := checkByte6Unused(data); err != nil {
		return su3, err
	}

	file_format_version, err := getFileFormatVersion(data)
	su3.FileFormatVersion = file_format_version
	if err != nil {
		return su3, err
	}

	signature_type, err := getSignatureType(data)
	su3.SignatureType = signature_type
	if err != nil {
		return su3, err
	}

	signature_length, err := getSignatureLength(data)
	su3.SignatureLength = signature_length
	if err != nil {
		return su3, err
	}

	if err := checkByte12Unused(data); err != nil {
		return su3, err
	}

	version_length, err := getVersionLength(data)
	su3.VersionLength = version_length
	if err != nil {
		return su3, err
	}

	if err := checkByte14Unused(data); err != nil {
		return su3, err
	}

	signer_id_length, err := getSignerIDLength(data)
	su3.SignerIDLength = signer_id_length
	if err != nil {
		return su3, err
	}

	content_length, err := getContentLength(data)
	su3.ContentLength = content_length
	if err != nil {
		return su3, err
	}

	file_type, err := getFileType(data)
	su3.FileType = file_type
	if err != nil {
		return su3, err
	}

	if err := checkByte26Unused(data); err != nil {
		return su3, err
	}

	content_type, err := getContentType(data)
	su3.ContentType = content_type
	if err != nil {
		return su3, err
	}

	if err := checkBytes28To39Unused(data); err != nil {
		return su3, err
	}

	version, err := getVersion(data)
	su3.Version = version
	if err != nil {
		return su3, err
	}

	signer_id, err := getSignerID(data)
	su3.SignerID = signer_id
	if err != nil {
		return su3, err
	}

	content, err := getContent(data)
	su3.Content = content
	if err != nil {
		return su3, err
	}

	signature, err := getSignature(data)
	su3.Signature = signature
	if err != nil {
		return su3, err
	}

	return su3, nil
}

func checkMagicBytes(data []byte) error {
	if len(data) < SU3_MAGIC_BYTE_LEN {
		return ERR_NOT_ENOUGH_SU3_DATA
	}

	magic_str := string(data[:SU3_MAGIC_BYTE_LEN])
	if magic_str != SU3_MAGIC_BYTES {
		log.WithFields(log.Fields{
			"at":       "config.checkMagicBytes",
			"expected": []byte(SU3_MAGIC_BYTES),
			"got":      []byte(magic_str),
		}).Debug(ERR_SU3_MAGIC_BYTES_MISMATCH)
		return ERR_SU3_MAGIC_BYTES_MISMATCH
	}

	return nil
}

func checkByte6Unused(data []byte) error {
	if len(data) < SU3_MAGIC_BYTE_LEN+1 {
		return ERR_NOT_ENOUGH_SU3_DATA
	}

	unused_byte := data[SU3_MAGIC_BYTE_LEN]
	if unused_byte != 0x00 {
		log.WithFields(log.Fields{
			"at":        "config.checkByte6Unused",
			"byte_data": unused_byte,
		}).Debug(ERR_SU3_UNUSED_BYTE_WITH_DATA)
		return ERR_SU3_UNUSED_BYTE_WITH_DATA
	}

	return nil
}

func getFileFormatVersion(data []byte) (int, error) {
	if len(data) < SU3_MAGIC_BYTE_LEN+1+1 {
		return 0, ERR_NOT_ENOUGH_SU3_DATA
	}

	if file_format_version_byte := data[SU3_MAGIC_BYTE_LEN+1]; file_format_version_byte != 0x00 {
		log.WithFields(log.Fields{
			"at": "config.getSignatureType",
			"file_format_version_byte": file_format_version_byte,
		}).Debug(ERR_SU3_FILE_FORMAT_VERSION_UNKNOWN)
		return int(file_format_version_byte), ERR_SU3_FILE_FORMAT_VERSION_UNKNOWN
	}

	return 0, nil
}

func getSignatureType(data []byte) (string, error) {
	signature_type := ""

	if len(data) < SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN {
		return signature_type, ERR_NOT_ENOUGH_SU3_DATA
	}

	signature_type_bytes := [2]byte{}
	copy(
		signature_type_bytes[:],
		data[SU3_MAGIC_BYTE_LEN+1+1:SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN],
	)
	if str, ok := SU3_SIGNATURE_TYPE_MAP[signature_type_bytes]; !ok {
		log.WithFields(log.Fields{
			"at":   "config.getSignatureType",
			"type": signature_type_bytes,
		}).Debug(ERR_SU3_SIGNATURE_TYPE_UNKNOWN)
		return signature_type, ERR_SU3_SIGNATURE_TYPE_UNKNOWN

	} else {
		signature_type = str
	}

	return signature_type, nil
}

func getSignatureLength(data []byte) (int, error) {
	signature_length := 0

	if len(data) < SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN {
		return signature_length, ERR_NOT_ENOUGH_SU3_DATA
	}

	signature_length_bytes := [2]byte{}
	copy(
		signature_length_bytes[:],
		data[SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN:SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN],
	)
	signature_length = common.Integer(signature_length_bytes[:])

	return signature_length, nil
}

func checkByte12Unused(data []byte) error {
	if len(data) < SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN+1 {
		return ERR_NOT_ENOUGH_SU3_DATA
	}

	unused_byte := data[SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN]
	if unused_byte != 0x00 {
		log.WithFields(log.Fields{
			"at":        "config.checkByte12Unused",
			"byte_data": unused_byte,
		}).Debug(ERR_SU3_UNUSED_BYTE_WITH_DATA)
		return ERR_SU3_UNUSED_BYTE_WITH_DATA
	}

	return nil
}

func getVersionLength(data []byte) (int, error) {
	if len(data) < SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN+1+1 {
		return 0, ERR_NOT_ENOUGH_SU3_DATA
	}

	version_length := common.Integer([]byte{data[SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN+1]})

	if version_length < 16 {
		log.WithFields(log.Fields{
			"at":             "config.getSignatureType",
			"version_length": version_length,
		}).Debug(ERR_SU3_VERSION_LENGTH_TOO_SMALL)
		return version_length, ERR_SU3_VERSION_LENGTH_TOO_SMALL
	}

	return version_length, nil
}

func checkByte14Unused(data []byte) error {
	if len(data) < SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN+1+1+1 {
		return ERR_NOT_ENOUGH_SU3_DATA
	}

	unused_byte := data[SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN+1+1]
	if unused_byte != 0x00 {
		log.WithFields(log.Fields{
			"at":        "config.checkByte14Unused",
			"byte_data": unused_byte,
		}).Debug(ERR_SU3_UNUSED_BYTE_WITH_DATA)
		return ERR_SU3_UNUSED_BYTE_WITH_DATA
	}

	return nil
}

func getSignerIDLength(data []byte) (int, error) {
	if len(data) < SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN+1+1+1+1 {
		return 0, ERR_NOT_ENOUGH_SU3_DATA
	}

	signer_id_length := common.Integer([]byte{data[SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN+1+1+1]})

	return signer_id_length, nil
}

func getContentLength(data []byte) (int, error) {
	content_length := 0

	if len(data) < SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN+1+1+1+1+SU3_CONTENT_LENGTH_LEN {
		return content_length, ERR_NOT_ENOUGH_SU3_DATA
	}

	content_length_bytes := [8]byte{}
	copy(
		content_length_bytes[:],
		data[SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN+1+1+1+1:SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN+1+1+1+1+SU3_CONTENT_LENGTH_LEN],
	)
	content_length = common.Integer(content_length_bytes[:])

	return content_length, nil
}

func checkByte24Unused(data []byte) error {
	if len(data) < SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN+1+1+1+1+SU3_CONTENT_LENGTH_LEN+1 {
		return ERR_NOT_ENOUGH_SU3_DATA
	}

	unused_byte := data[SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN+1+1+1+1+SU3_CONTENT_LENGTH_LEN]
	if unused_byte != 0x00 {
		log.WithFields(log.Fields{
			"at":        "config.checkByte24Unused",
			"byte_data": unused_byte,
		}).Debug(ERR_SU3_UNUSED_BYTE_WITH_DATA)
		return ERR_SU3_UNUSED_BYTE_WITH_DATA
	}

	return nil
}

func getFileType(data []byte) (string, error) {
	file_type := ""

	if len(data) < SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN+1+1+1+1+SU3_CONTENT_LENGTH_LEN+1+1 {
		return file_type, ERR_NOT_ENOUGH_SU3_DATA
	}

	file_type_byte := data[SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN+1+1+1+1+SU3_CONTENT_LENGTH_LEN+1]
	if str, ok := SU3_FILE_TYPE_MAP[file_type_byte]; !ok {
		log.WithFields(log.Fields{
			"at":   "config.getFileType",
			"type": file_type_byte,
		}).Debug(ERR_SU3_FILE_TYPE_UNKNOWN)
		return file_type, ERR_SU3_FILE_TYPE_UNKNOWN
	} else {
		file_type = str
	}

	return file_type, nil
}

func checkByte26Unused(data []byte) error {
	if len(data) < SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN+1+1+1+1+SU3_CONTENT_LENGTH_LEN+1+1+1 {
		return ERR_NOT_ENOUGH_SU3_DATA
	}

	unused_byte := data[SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN+1+1+1+1+SU3_CONTENT_LENGTH_LEN+1+1]
	if unused_byte != 0x00 {
		log.WithFields(log.Fields{
			"at":        "config.checkByt26Unused",
			"byte_data": unused_byte,
		}).Debug(ERR_SU3_UNUSED_BYTE_WITH_DATA)
		return ERR_SU3_UNUSED_BYTE_WITH_DATA
	}

	return nil
}

func getContentType(data []byte) (string, error) {
	content_type := ""

	if len(data) < SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN+1+1+1+1+SU3_CONTENT_LENGTH_LEN+1+1+1+1 {
		return content_type, ERR_NOT_ENOUGH_SU3_DATA
	}

	content_type_byte := data[SU3_MAGIC_BYTE_LEN+1+1+SU3_SIGNATURE_TYPE_LEN+SU3_SIGNATURE_LENGTH_LEN+1+1+1+1+SU3_CONTENT_LENGTH_LEN+1+1+1]
	if str, ok := SU3_CONTENT_TYPE_MAP[content_type_byte]; !ok {
		log.WithFields(log.Fields{
			"at":   "config.getContentType",
			"type": content_type_byte,
		}).Debug(ERR_SU3_CONTENT_TYPE_UNKNOWN)
		return content_type, ERR_SU3_CONTENT_TYPE_UNKNOWN
	} else {
		content_type = str
	}

	return content_type, nil
}

func checkBytes28To39Unused(data []byte) error {
	end := SU3_MAGIC_BYTE_LEN + 1 + 1 + SU3_SIGNATURE_TYPE_LEN + SU3_SIGNATURE_LENGTH_LEN + 1 + 1 + 1 + 1 + SU3_CONTENT_LENGTH_LEN + 1 + 1 + 1 + 1 + 12

	if len(data) < end {
		return ERR_NOT_ENOUGH_SU3_DATA
	}

	unused_bytes := [12]byte{}
	copy(
		unused_bytes[:],
		data[end-12:end],
	)
	for i, value := range unused_bytes {
		if value != 0x00 {
			log.WithFields(log.Fields{
				"at":       "config.checkBytes28To39Unused",
				"iterator": i,
			}).Debug(ERR_SU3_UNUSED_BYTE_WITH_DATA)
			return ERR_SU3_UNUSED_BYTE_WITH_DATA
		}
	}

	return nil
}

func getVersion(data []byte) (string, error) {
	version := ""
	version_length, err := getVersionLength(data)
	if err != nil {
		return version, err
	}

	min := SU3_MAGIC_BYTE_LEN + 1 + 1 + SU3_SIGNATURE_TYPE_LEN + SU3_SIGNATURE_LENGTH_LEN + 1 + 1 + 1 + 1 + SU3_CONTENT_LENGTH_LEN + 1 + 1 + 1 + 1 + 12
	if len(data) < min+version_length {
		return version, ERR_NOT_ENOUGH_SU3_DATA
	}

	version_bytes := data[min : min+version_length]
	version_str := strings.TrimRight(string(version_bytes), "\x00")
	if !utf8.ValidString(version_str) {
		log.WithFields(log.Fields{
			"at": "config.getVersion",
		}).Debug(ERR_SU3_VERSION_NOT_UTF8)
		return version, ERR_SU3_VERSION_NOT_UTF8
	} else {
		version = version_str
	}

	return version, nil
}

func getSignerID(data []byte) (string, error) {
	signer_id := ""
	signer_id_length, err := getSignerIDLength(data)
	if err != nil {
		return signer_id, err
	}
	version_length, err := getVersionLength(data)
	if err != nil {
		return signer_id, err
	}

	min := SU3_MAGIC_BYTE_LEN + 1 + 1 + SU3_SIGNATURE_TYPE_LEN + SU3_SIGNATURE_LENGTH_LEN + 1 + 1 + 1 + 1 + SU3_CONTENT_LENGTH_LEN + 1 + 1 + 1 + 1 + 12 + version_length
	if len(data) < min+signer_id_length {
		return signer_id, ERR_NOT_ENOUGH_SU3_DATA
	}

	signer_id_bytes := data[min : min+signer_id_length]
	signer_id_str := string(signer_id_bytes)
	if !utf8.ValidString(signer_id_str) {
		log.WithFields(log.Fields{
			"at": "config.getSignerID",
		}).Debug(ERR_SU3_SIGNER_ID_NOT_UTF8)
		return signer_id, ERR_SU3_SIGNER_ID_NOT_UTF8
	} else {
		signer_id = signer_id_str
	}

	return signer_id, nil
}

func getContent(data []byte) ([]byte, error) {
	content := []byte{}
	content_length, err := getContentLength(data)
	if err != nil {
		return content, err
	}
	signer_id_length, err := getSignerIDLength(data)
	if err != nil {
		return content, err
	}
	version_length, err := getVersionLength(data)
	if err != nil {
		return content, err
	}

	min := SU3_MAGIC_BYTE_LEN + 1 + 1 + SU3_SIGNATURE_TYPE_LEN + SU3_SIGNATURE_LENGTH_LEN + 1 + 1 + 1 + 1 + SU3_CONTENT_LENGTH_LEN + 1 + 1 + 1 + 1 + 12 + version_length + signer_id_length
	if len(data) < min+content_length {
		return content, ERR_NOT_ENOUGH_SU3_DATA
	}

	content = data[min : min+content_length]
	return content, nil
}

func getSignature(data []byte) ([]byte, error) {
	signature := []byte{}
	signature_length, err := getSignatureLength(data)
	if err != nil {
		return signature, err
	}
	content_length, err := getContentLength(data)
	if err != nil {
		return signature, err
	}
	signer_id_length, err := getSignerIDLength(data)
	if err != nil {
		return signature, err
	}
	version_length, err := getVersionLength(data)
	if err != nil {
		return signature, err
	}

	min := SU3_MAGIC_BYTE_LEN + 1 + 1 + SU3_SIGNATURE_TYPE_LEN + SU3_SIGNATURE_LENGTH_LEN + 1 + 1 + 1 + 1 + SU3_CONTENT_LENGTH_LEN + 1 + 1 + 1 + 1 + 12 + version_length + signer_id_length + content_length
	if len(data) < min+signature_length {
		return signature, ERR_NOT_ENOUGH_SU3_DATA
	}

	signature = data[min : min+signature_length]
	return signature, nil
}
