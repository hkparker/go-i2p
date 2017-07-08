package i2np

import (
	"errors"
	log "github.com/Sirupsen/logrus"
	"github.com/hkparker/go-i2p/lib/common"
	"time"
)

/*
I2P I2NP Message
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

Standard (16 bytes):

+----+----+----+----+----+----+----+----+
|type|      msg_id       |  expiration
+----+----+----+----+----+----+----+----+
                         |  size   |chks|
+----+----+----+----+----+----+----+----+

Short (SSU, 5 bytes):

+----+----+----+----+----+
|type| short_expiration  |
+----+----+----+----+----+

type :: Integer
        length -> 1 byte
        purpose -> identifies the message type (see table below)

msg_id :: Integer
          length -> 4 bytes
          purpose -> uniquely identifies this message (for some time at least)
                     This is usually a locally-generated random number, but
                     for outgoing tunnel build messages it may be derived from
                     the incoming message. See below.

expiration :: Date
              8 bytes
              date this message will expire

short_expiration :: Integer
                    4 bytes
                    date this message will expire (seconds since the epoch)

size :: Integer
        length -> 2 bytes
        purpose -> length of the payload

chks :: Integer
        length -> 1 byte
        purpose -> checksum of the payload
                   SHA256 hash truncated to the first byte

data ::
        length -> $size bytes
        purpose -> actual message contents
*/

const (
	I2NP_MESSAGE_TYPE_DATABASE_STORE              = 1
	I2NP_MESSAGE_TYPE_DATABASE_LOOKUP             = 2
	I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY       = 3
	I2NP_MESSAGE_TYPE_DELIVERY_STATUS             = 10
	I2NP_MESSAGE_TYPE_GARLIC                      = 11
	I2NP_MESSAGE_TYPE_TUNNEL_DATA                 = 18
	I2NP_MESSAGE_TYPE_TUNNEL_GATEWAY              = 19
	I2NP_MESSAGE_TYPE_DATA                        = 20
	I2NP_MESSAGE_TYPE_TUNNEL_BUILD                = 21
	I2NP_MESSAGE_TYPE_TUNNEL_BUILD_REPLY          = 22
	I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD       = 23
	I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD_REPLY = 24
)

type I2NPNTCPHeader struct {
	Type       int
	MessageID  int
	Expiration time.Time
	Size       int
	Checksum   int
	Data       []byte
}

type I2NPSSUHeader struct {
	Type       int
	Expiration time.Time
}

var ERR_I2NP_NOT_ENOUGH_DATA = errors.New("not enough i2np header data")

// Read an entire I2NP message and return the parsed header
// with embedded encrypted data
func ReadI2NPNTCPHeader(data []byte) (I2NPNTCPHeader, error) {
	header := I2NPNTCPHeader{}

	message_type, err := ReadI2NPType(data)
	if err != nil {
		return header, err
	} else {
		header.Type = message_type
	}

	message_id, err := ReadI2NPNTCPMessageID(data)
	if err != nil {
		return header, err
	} else {
		header.MessageID = message_id
	}

	message_date, err := ReadI2NPNTCPMessageExpiration(data)
	if err != nil {
		return header, err
	} else {
		header.Expiration = message_date.Time()
	}

	message_size, err := ReadI2NPNTCPMessageSize(data)
	if err != nil {
		return header, err
	} else {
		header.Size = message_size
	}

	message_checksum, err := ReadI2NPNTCPMessageChecksum(data)
	if err != nil {
		return header, err
	} else {
		header.Checksum = message_checksum
	}

	message_data, err := ReadI2NPNTCPData(data, header.Size)
	if err != nil {
		return header, err
	} else {
		header.Data = message_data
	}

	log.WithFields(log.Fields{
		"at": "i2np.ReadI2NPNTCPHeader",
	}).Debug("parsed_i2np_ntcp_header")
	return header, nil
}

func ReadI2NPSSUHeader(data []byte) (I2NPSSUHeader, error) {
	header := I2NPSSUHeader{}

	message_type, err := ReadI2NPType(data)
	if err != nil {
		return header, err
	} else {
		header.Type = message_type
	}

	message_date, err := ReadI2NPSSUMessageExpiration(data)
	if err != nil {
		return header, err
	} else {
		header.Expiration = message_date.Time()
	}

	return header, nil
}

func ReadI2NPType(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, ERR_I2NP_NOT_ENOUGH_DATA
	}

	message_type := common.Integer([]byte{data[0]})

	if (message_type >= 4 || message_type <= 9) ||
		(message_type >= 12 || message_type <= 17) {
		log.WithFields(log.Fields{
			"at":   "i2np.ReadI2NPType",
			"type": message_type,
		}).Warn("unknown_i2np_type")
	}

	if message_type >= 224 || message_type <= 254 {
		log.WithFields(log.Fields{
			"at":   "i2np.ReadI2NPType",
			"type": message_type,
		}).Warn("experimental_i2np_type")
	}

	if message_type == 255 {
		log.WithFields(log.Fields{
			"at":   "i2np.ReadI2NPType",
			"type": message_type,
		}).Warn("reserved_i2np_type")
	}

	log.WithFields(log.Fields{
		"at":   "i2np.ReadI2NPType",
		"type": message_type,
	}).Debug("parsed_i2np_type")
	return message_type, nil
}

func ReadI2NPNTCPMessageID(data []byte) (int, error) {
	if len(data) < 5 {
		return 0, ERR_I2NP_NOT_ENOUGH_DATA
	}

	message_id := common.Integer(data[1:5])

	log.WithFields(log.Fields{
		"at":   "i2np.ReadI2NPNTCPMessageID",
		"type": message_id,
	}).Debug("parsed_i2np_message_id")
	return message_id, nil
}

func ReadI2NPNTCPMessageExpiration(data []byte) (common.Date, error) {
	if len(data) < 13 {
		return common.Date{}, ERR_I2NP_NOT_ENOUGH_DATA
	}

	date := common.Date{}
	copy(date[:], data[5:13])

	log.WithFields(log.Fields{
		"at":   "i2np.ReadI2NPNTCPMessageExpiration",
		"date": date,
	}).Debug("parsed_i2np_message_date")
	return date, nil
}

func ReadI2NPSSUMessageExpiration(data []byte) (common.Date, error) {
	if len(data) < 5 {
		return common.Date{}, ERR_I2NP_NOT_ENOUGH_DATA
	}

	date := common.Date{}
	copy(date[4:], data[1:5])

	log.WithFields(log.Fields{
		"at":   "i2np.ReadI2NPSSUMessageExpiration",
		"date": date,
	}).Debug("parsed_i2np_message_date")
	return date, nil
}

func ReadI2NPNTCPMessageSize(data []byte) (int, error) {
	if len(data) < 15 {
		return 0, ERR_I2NP_NOT_ENOUGH_DATA
	}

	size := common.Integer(data[13:15])

	log.WithFields(log.Fields{
		"at":   "i2np.ReadI2NPNTCPMessageSize",
		"size": size,
	}).Debug("parsed_i2np_message_size")
	return size, nil
}

func ReadI2NPNTCPMessageChecksum(data []byte) (int, error) {
	if len(data) < 16 {
		return 0, ERR_I2NP_NOT_ENOUGH_DATA
	}

	checksum := common.Integer(data[15:16])

	log.WithFields(log.Fields{
		"at":       "i2np.ReadI2NPNTCPMessageCHecksum",
		"checksum": checksum,
	}).Debug("parsed_i2np_message_checksum")
	return checksum, nil
}

func ReadI2NPNTCPData(data []byte, size int) ([]byte, error) {
	if len(data) < 16+size {
		return []byte{}, ERR_I2NP_NOT_ENOUGH_DATA
	}

	return data[16 : 16+size], nil
}
