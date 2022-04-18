package common

/*
I2P Mapping
https://geti2p.net/spec/common-structures#mapping
Accurate for version 0.9.24

+----+----+----+----+----+----+----+----+
|  size   |key_string (len + data) | =  |
+----+----+----+----+----+----+----+----+
| val_string (len + data)     | ;  | ...
+----+----+----+----+----+----+----+
size :: Integer
        length -> 2 bytes
        Total number of bytes that follow

key_string :: String
              A string (one byte length followed by UTF-8 encoded characters)

= :: A single byte containing '='

val_string :: String
              A string (one byte length followed by UTF-8 encoded characters)

; :: A single byte containing ';'
*/

import (
	"encoding/binary"
	"errors"
	log "github.com/sirupsen/logrus"
	"sort"
)

type Mapping []byte

// Parsed key-values pairs inside a Mapping.
type MappingValues [][2]String

//
// Returns the values contained in a Mapping in the form of a MappingValues.
//
func (mapping Mapping) Values() (map_values MappingValues, errs []error) {
	var str String
	var remainder = mapping
	var err error

	length := Integer(remainder[:2])
	inferred_length := length + 2
	remainder = remainder[2:]
	mapping_len := len(mapping)
	if mapping_len > inferred_length {
		log.WithFields(log.Fields{
			"at": "(Mapping) Values",
			"mappnig_bytes_length":  mapping_len,
			"mapping_length_field":  length,
			"expected_bytes_length": inferred_length,
			"reason":                "data longer than expected",
		}).Warn("mapping format warning")
		errs = append(errs, errors.New("warning parsing mapping: data exists beyond length of mapping"))
	} else if inferred_length > mapping_len {
		log.WithFields(log.Fields{
			"at": "(Mapping) Values",
			"mappnig_bytes_length":  mapping_len,
			"mapping_length_field":  length,
			"expected_bytes_length": inferred_length,
			"reason":                "data shorter than expected",
		}).Warn("mapping format warning")
		errs = append(errs, errors.New("warning parsing mapping: mapping length exceeds provided data"))
	}

	for {
		// Read a key, breaking on fatal errors
		// and appending warnings
		str, remainder, err = ReadString(remainder)
		key_str := str
		if err != nil {
			if stopValueRead(err) {
				errs = append(errs, err)
				return
			}
		}
		if !beginsWith(remainder, 0x3d) {
			log.WithFields(log.Fields{
				"at":     "(Mapping) Values",
				"reason": "expected =",
			}).Warn("mapping format violation")
			errs = append(errs, errors.New("mapping format violation, expected ="))
			return
		}
		remainder = remainder[1:]

		// Read a value, breaking on fatal errors
		// and appending warnings
		str, remainder, err = ReadString(remainder)
		val_str := str
		if err != nil {
			if stopValueRead(err) {
				errs = append(errs, err)
				return
			}
		}
		if !beginsWith(remainder, 0x3b) {
			log.WithFields(log.Fields{
				"at":     "(Mapping) Values",
				"reason": "expected ;",
			}).Warn("mapping format violation")
			errs = append(errs, errors.New("mapping format violation, expected ;"))
			return
		}
		remainder = remainder[1:]

		// Append the key-value pair and break if there is no more data to read
		map_values = append(map_values, [2]String{key_str, val_str})
		if len(remainder) == 0 {
			break
		}
	}
	return
}

//
// Return true if two keys in a mapping are identical.
//
func (mapping Mapping) HasDuplicateKeys() bool {
	seen_values := make(map[string]bool)
	values, _ := mapping.Values()
	for _, pair := range values {
		key, _ := pair[0].Data()
		if _, present := seen_values[key]; present {
			return true
		} else {
			seen_values[key] = true
		}
	}
	return false
}

//
// Convert a MappingValue struct to a Mapping.  The values are first
// sorted in the order defined in mappingOrder.
//
func ValuesToMapping(values MappingValues) (mapping Mapping) {
	mappingOrder(values)
	for _, kv_pair := range values {
		key_string := kv_pair[0]
		key_string = append(key_string, []byte("=")[0])
		key_value := kv_pair[1]
		key_value = append(key_value, []byte(";")[0])
		mapping = append(append(mapping, key_string...), key_value...)
	}
	map_len := len(mapping)
	len_bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(len_bytes, uint16(map_len))
	mapping = append(len_bytes, mapping...)
	return
}

//
// Convert a Go map of unformatted strings to a sorted Mapping.
//
func GoMapToMapping(gomap map[string]string) (mapping Mapping, err error) {
	map_vals := MappingValues{}
	for k, v := range gomap {
		key_str, kerr := ToI2PString(k)
		if kerr != nil {
			err = kerr
			return
		}
		val_str, verr := ToI2PString(v)
		if verr != nil {
			err = verr
			return
		}
		map_vals = append(
			map_vals,
			[2]String{key_str, val_str},
		)
	}
	mapping = ValuesToMapping(map_vals)
	return
}

type byValue MappingValues

func (set byValue) Len() int      { return len(set) }
func (set byValue) Swap(i, j int) { set[i], set[j] = set[j], set[i] }
func (set byValue) Less(i, j int) bool {
	data1, _ := set[i][1].Data()
	data2, _ := set[j][1].Data()
	return data1 < data2
}

type byKey MappingValues

func (set byKey) Len() int      { return len(set) }
func (set byKey) Swap(i, j int) { set[i], set[j] = set[j], set[i] }
func (set byKey) Less(i, j int) bool {
	data1, _ := set[i][0].Data()
	data2, _ := set[j][0].Data()
	return data1 < data2
}

//
// I2P Mappings require consistent order for for cryptographic signing, and sorting
// by keys.  When new Mappings are created, they are stable sorted first by values
// than by keys to ensure a consistent order.
//
func mappingOrder(values MappingValues) {
	sort.Stable(byValue(values))
	sort.Stable(byKey(values))
}

//
// Check if the string parsing error indicates that the Mapping
// should no longer be parsed.
//
func stopValueRead(err error) bool {
	return err.Error() == "error parsing string: zero length"
}

//
// Determine if the first byte in a slice of bytes is the provided byte.
//
func beginsWith(bytes []byte, chr byte) bool {
	return len(bytes) != 0 &&
		bytes[0] == chr
}
