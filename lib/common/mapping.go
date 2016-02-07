package common

import (
	"encoding/binary"
	"errors"
	"sort"
)

type Mapping []byte
type MappingValues [][2]String

//
// Returns the values contained in a Mapping in
// the form of a MappingValues.
//
func (mapping Mapping) Values() (map_values MappingValues, errs []error) {
	var str String
	var remainder = mapping
	var err error

	length := Integer(remainder[:2])
	remainder = remainder[2:]
	mapping_len := len(mapping)
	if mapping_len > length+2 {
		errs = append(errs, errors.New("warning parsing mapping: data exists beyond length of mapping"))
	} else if length+2 > mapping_len {
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
			errs = append(errs, errors.New("mapping format violation, expected ;"))
			return
		}
		remainder = remainder[1:]

		// Append the key-value pair and break
		// if there is no more data to read
		map_values = append(map_values, [2]String{key_str, val_str})
		if len(remainder) == 0 {
			break
		}
	}
	return
}

//
// Returns true if two keys in a mapping are identical
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
// ValuesToMapping takes a MappingValue struct and
// returns a Mapping.  The values are sorted in the
// order defined in mappingOrder.
//
func ValuesToMapping(values MappingValues) Mapping {
	var mapping Mapping
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
	return mapping
}

//
// This function takes a map of unformatted strings
// and returns a Mapping.
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

type ByValue MappingValues

func (set ByValue) Len() int      { return len(set) }
func (set ByValue) Swap(i, j int) { set[i], set[j] = set[j], set[i] }
func (set ByValue) Less(i, j int) bool {
	data1, _ := set[i][1].Data()
	data2, _ := set[j][1].Data()
	return data1 < data2
}

type ByKey MappingValues

func (set ByKey) Len() int      { return len(set) }
func (set ByKey) Swap(i, j int) { set[i], set[j] = set[j], set[i] }
func (set ByKey) Less(i, j int) bool {
	data1, _ := set[i][0].Data()
	data2, _ := set[j][0].Data()
	return data1 < data2
}

//
// I2P Mappings require consistent order for
// for cryptographic signing, and sorting
// by keys.  When new Mappings are created,
// they are stable sorted first by values
// than by keys to ensure a consistent order.
//
func mappingOrder(values MappingValues) {
	sort.Stable(ByValue(values))
	sort.Stable(ByKey(values))
}

func stopValueRead(err error) bool {
	return err.Error() == "error parsing string: zero length"
}

func beginsWith(bytes []byte, chr byte) bool {
	return len(bytes) != 0 &&
		bytes[0] == chr
}
