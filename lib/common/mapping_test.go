package common

import (
	"bytes"
	"testing"
)

func TestToMapping(t *testing.T) {
	gomap := map[string]string{
		"a": "1",
	}
	mapping := MappingFromMap(gomap)
	if !bytes.Equal(mapping, []byte{0x00, 0x04, 0x61, 0x3d, 0x31, 0x3b}) {
		t.Fatal("go map to mapping did not create correct mapping")
	}
}

func TestMappingToMap(t *testing.T) {
	mapping := Mapping{0x00, 0x08, 0x61, 0x3d, 0x31, 0x3b, 0x62, 0x3d, 0x32, 0x3b}
	gomap := mapping.ToMap()
	if gomap["a"] != "1" {
		t.Fatal("map does not contain encoded data")
	}
	if gomap["b"] != "2" {
		t.Fatal("map does not comtain encoded data")
	}
}

func TestToAndFromMapping(t *testing.T) {
	gomap := make(map[string]string)
	gomap["foo"] = "bar"
	mapping := MappingFromMap(gomap)
	gomap2 := mapping.ToMap()
	if gomap["foo"] != gomap2["foo"] {
		t.Fatal("rebuilt map has different data")
	}
}
