package common

import (
	"encoding/binary"
	"strings"
)

type Mapping []byte

func (mapping Mapping) ToMap() map[string]string {
	gomap := make(map[string]string)
	kv_store := string(mapping[2:])
	pairs := strings.Split(kv_store, ";")
	for _, pair := range pairs {
		values := strings.Split(pair, "=")
		if len(values) != 2 {
			continue
		}
		gomap[values[0]] = values[1]
	}
	return gomap
}

func MappingFromMap(gomap map[string]string) Mapping {
	kv_store := make([]byte, 0)
	for k, v := range gomap {
		key_bytes := []byte(k)
		key_bytes = append(key_bytes, 0x3d)
		value_bytes := []byte(v)
		value_bytes = append(value_bytes, 0x3b)
		kv_store = append(kv_store, key_bytes...)
		kv_store = append(kv_store, value_bytes...)
	}
	kv_size := uint16(len(kv_store))
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], kv_size)
	mapping := Mapping{}
	mapping = append(mapping, size[:]...)
	mapping = append(mapping, kv_store...)
	return mapping
}
