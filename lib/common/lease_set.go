package common

/*
I2P LeaseSet
https://geti2p.net/spec/common-structures#leaseset
Accurate for version 0.9.24

+----+----+----+----+----+----+----+----+
| destination                           |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| encryption_key                        |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| signing_key                           |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|num | Lease 0                          |
+----+                                  +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| Lease 1                               |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| Lease ($num-1)                        |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| signature                             |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+

destination :: Destination
               length -> >= 387 bytes

encryption_key :: PublicKey
                  length -> 256 bytes

signing_key :: SigningPublicKey
               length -> 128 bytes or as specified in destination's key certificate

num :: Integer
       length -> 1 byte
       Number of leases to follow
       value: 0 <= num <= 16

leases :: [Lease]
          length -> $num*44 bytes

signature :: Signature
             length -> 40 bytes or as specified in destination's key certificate
*/

import (
	"errors"
	log "github.com/Sirupsen/logrus"
	"github.com/hkparker/go-i2p/lib/crypto"
)

// Sizes of various structures in an I2P LeaseSet
const (
	LEASE_SET_PUBKEY_SIZE = 256
	LEASE_SET_SPK_SIZE    = 128
	LEASE_SET_SIG_SIZE    = 40
)

type LeaseSet []byte

//
// Read a Destination from the LeaseSet.
//
func (lease_set LeaseSet) Destination() (destination Destination, err error) {
	keys_and_cert, _, err := ReadKeysAndCert(lease_set)
	destination = Destination(keys_and_cert)
	return
}

//
// Return the PublicKey in this LeaseSet and any errors ancountered parsing the LeaseSet.
//
func (lease_set LeaseSet) PublicKey() (public_key crypto.ElgPublicKey, err error) {
	_, remainder, err := ReadKeysAndCert(lease_set)
	remainder_len := len(remainder)
	if remainder_len < LEASE_SET_PUBKEY_SIZE {
		log.WithFields(log.Fields{
			"at":           "(LeaseSet) PublicKey",
			"data_len":     remainder_len,
			"required_len": LEASE_SET_PUBKEY_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing public key")
		err = errors.New("error parsing public key: not enough data")
		copy(public_key[:], remainder)
		return
	}
	copy(public_key[:], remainder[:LEASE_SET_PUBKEY_SIZE])
	return
}

//
// Return the SigningPublicKey, as specified in the LeaseSet's Destination's Key Certificate if
// present, or a legacy DSA key.
//
func (lease_set LeaseSet) SigningKey() (signing_public_key crypto.SigningPublicKey, err error) {
	destination, err := lease_set.Destination()
	if err != nil {
		return
	}
	offset := len(destination) + LEASE_SET_PUBKEY_SIZE
	cert, err := destination.Certificate()
	if err != nil {
		return
	}
	cert_len, err := cert.Length()
	if err != nil {
		return
	}
	lease_set_len := len(lease_set)
	if lease_set_len < offset+LEASE_SET_SPK_SIZE {
		log.WithFields(log.Fields{
			"at":           "(LeaseSet) SigningKey",
			"data_len":     lease_set_len,
			"required_len": offset + LEASE_SET_SPK_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing signing public key")
		err = errors.New("error parsing signing public key: not enough data")
		return
	}
	if cert_len == 0 {
		// No Certificate is present, return the LEASE_SET_SPK_SIZE byte
		// SigningPublicKey space as legacy DSA SHA1 SigningPublicKey.
		var dsa_pk crypto.DSAPublicKey
		copy(dsa_pk[:], lease_set[offset:offset+LEASE_SET_SPK_SIZE])
		signing_public_key = dsa_pk
	} else {
		// A Certificate is present in this LeaseSet's Destination
		cert_type, _ := cert.Type()
		if cert_type == CERT_KEY {
			// This LeaseSet's Destination's Certificate is a Key Certificate,
			// create the signing publickey key using any data that might be
			// contained in the key certificate.
			signing_public_key, err = KeyCertificate(cert).ConstructSigningPublicKey(
				lease_set[offset : offset+LEASE_SET_SPK_SIZE],
			)
		} else {
			// No Certificate is present, return the LEASE_SET_SPK_SIZE byte
			// SigningPublicKey space as legacy DSA SHA1 SigningPublicKey.
			var dsa_pk crypto.DSAPublicKey
			copy(dsa_pk[:], lease_set[offset:offset+LEASE_SET_SPK_SIZE])
			signing_public_key = dsa_pk
		}

	}
	return
}

//
// Return the number of Leases specified by the LeaseCount value in this LeaseSet.
//
func (lease_set LeaseSet) LeaseCount() (count int, err error) {
	_, remainder, err := ReadKeysAndCert(lease_set)
	if err != nil {
		return
	}
	remainder_len := len(remainder)
	if remainder_len < LEASE_SET_PUBKEY_SIZE+LEASE_SET_SPK_SIZE+1 {
		log.WithFields(log.Fields{
			"at":           "(LeaseSet) LeaseCount",
			"data_len":     remainder_len,
			"required_len": LEASE_SET_PUBKEY_SIZE + LEASE_SET_SPK_SIZE + 1,
			"reason":       "not enough data",
		}).Error("error parsing lease count")
		err = errors.New("error parsing lease count: not enough data")
		return
	}
	count = Integer([]byte{remainder[LEASE_SET_PUBKEY_SIZE+LEASE_SET_SPK_SIZE]})
	if count > 16 {
		log.WithFields(log.Fields{
			"at":          "(LeaseSet) LeaseCount",
			"lease_count": count,
			"reason":      "more than 16 leases",
		}).Warn("invalid lease set")
		err = errors.New("invalid lease set: more than 16 leases")
	}
	return
}

//
// Read the Leases in this LeaseSet, returning a partial set if there is insufficient data.
//
func (lease_set LeaseSet) Leases() (leases []Lease, err error) {
	destination, err := lease_set.Destination()
	if err != nil {
		return
	}
	offset := len(destination) + LEASE_SET_PUBKEY_SIZE + LEASE_SET_SPK_SIZE + 1
	count, err := lease_set.LeaseCount()
	if err != nil {
		return
	}
	for i := 0; i < count; i++ {
		start := offset + (i * LEASE_SIZE)
		end := start + LEASE_SIZE
		lease_set_len := len(lease_set)
		if lease_set_len < end {
			log.WithFields(log.Fields{
				"at":           "(LeaseSet) Leases",
				"data_len":     lease_set_len,
				"required_len": end,
				"reason":       "some leases missing",
			}).Error("error parsnig lease set")
			err = errors.New("error parsing lease set: some leases missing")
			return
		}
		var lease Lease
		copy(lease[:], lease_set[start:end])
		leases = append(leases, lease)
	}
	return
}

//
// Return the Signature data for the LeaseSet, as specified in the Destination's
// Key Certificate if present or the 40 bytes following the Leases.
//
func (lease_set LeaseSet) Signature() (signature Signature, err error) {
	destination, err := lease_set.Destination()
	if err != nil {
		return
	}
	lease_count, err := lease_set.LeaseCount()
	if err != nil {
		return
	}
	start := len(destination) +
		LEASE_SET_PUBKEY_SIZE +
		LEASE_SET_SPK_SIZE +
		1 +
		(LEASE_SIZE * lease_count)
	cert, err := destination.Certificate()
	if err != nil {
		return
	}
	cert_type, _ := cert.Type()
	var end int
	if cert_type == CERT_KEY {
		end = start + KeyCertificate(cert).SignatureSize()
	} else {
		end = start + LEASE_SET_SIG_SIZE
	}
	lease_set_len := len(lease_set)
	if lease_set_len < end {
		log.WithFields(log.Fields{
			"at":           "(LeaseSet) Signature",
			"data_len":     lease_set_len,
			"required_len": end,
			"reason":       "not enough data",
		}).Error("error parsing signatre")
		err = errors.New("error parsing signature: not enough data")
		return
	}
	signature = []byte(lease_set[start:end])
	return
}

//
//
//
func (lease_set LeaseSet) Verify() error {
	//data_end := len(destination) +
	//	LEASE_SET_PUBKEY_SIZE +
	//	LEASE_SET_SPK_SIZE +
	//	1 +
	//	(44 * lease_set.LeaseCount())
	//data := lease_set[:data_end]
	//spk, _ := lease_set.
	//	Destination().
	//	SigningPublicKey()
	//verifier, err := spk.NewVerifier()
	//if err != nil {
	//	return err
	//}
	return nil // verifier.Verify(data, lease_set.Signature())
}

//
// Return the oldest date from all the Leases in the LeaseSet.
//
func (lease_set LeaseSet) NewestExpiration() (oldest Date, err error) {
	leases, err := lease_set.Leases()
	if err != nil {
		return
	}
	oldest = Date{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, lease := range leases {
		date := lease.Date()
		if date.Time().After(oldest.Time()) {
			oldest = date
		}
	}
	return
}

//
// Return the oldest date from all the Leases in the LeaseSet.
//
func (lease_set LeaseSet) OldestExpiration() (earliest Date, err error) {
	leases, err := lease_set.Leases()
	if err != nil {
		return
	}
	earliest = Date{0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	for _, lease := range leases {
		date := lease.Date()
		if date.Time().Before(earliest.Time()) {
			earliest = date
		}
	}
	return
}
