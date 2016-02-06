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
	// check length and append any errors needed, max: 65537
	// sanity check no data is missing

	var str String
	var remainder = mapping
	var err error
	for {
		// Read a key, breaking on fatal errors
		// and appending warnings
		str, remainder, err = ReadString(remainder)
		key_str := str
		if err != nil {
			errs = append(errs, err)
			if stopValueRead(err) {
				return
			}
		}
		if !beginsWith(remainder, "=") {
			errs = append(errs, errors.New("mapping format violation, expected ="))
			return
		}
		remainder = remainder[1:]

		// Read a value, breaking on fatal errors
		// and appending warnings
		str, remainder, err = ReadString(remainder)
		val_str := str
		if err != nil {
			errs = append(errs, err)
			if stopValueRead(err) {
				return
			}
		}
		if !beginsWith(remainder, ";") {
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
		key_string := String(kv_pair[0])
		key_value := String(kv_pair[1])
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

func beginsWith(bytes []byte, str string) bool {
	return len(bytes) != 0 &&
		string(bytes[0]) == str
}
