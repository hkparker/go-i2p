package common

import (
	"bytes"
	"errors"
	"testing"
)

func TestValuesExclusesPairWithBadData(t *testing.T) {
	bad_key := Mapping([]byte{0x00, 0x0c, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x00})
	values, errs := bad_key.Values()
	if len(values) != 1 {
		t.Fatal("Values did not return valid values when some values had bad key")
	} else {
		key, _ := values[0][0].Data()
		val, _ := values[0][1].Data()
		if key != "a" || val != "b" {
			t.Fatal("Value returned by values when other value had invalid key was incorrect")
		}
	}
	if len(errs) != 2 {
		t.Fatal("Values reported wrong error count when some values had invalid data", errs)
	}
}

func TestValuesWarnsMissingData(t *testing.T) {
	mapping := Mapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62})
	_, errs := mapping.Values()
	if len(errs) != 2 || errs[0].Error() != "warning parsing mapping: mapping length exceeds provided data" {
		t.Fatal("Values reported wrong error when missing data", len(errs), errs)
	}
}

func TestValuesWarnsExtraData(t *testing.T) {
	mapping := Mapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x00})
	_, errs := mapping.Values()
	if len(errs) != 2 || errs[0].Error() != "warning parsing mapping: data exists beyond length of mapping" {
		t.Fatal("Values reported wrong error when extra data", len(errs), errs)
	}
}

func TestValuesEnforcesEqualDelimitor(t *testing.T) {
	mapping := Mapping([]byte{0x00, 0x06, 0x01, 0x61, 0x30, 0x01, 0x62, 0x3b})
	values, errs := mapping.Values()
	if len(errs) != 1 || errs[0].Error() != "mapping format violation, expected =" {
		t.Fatal("wrong error reported with equal format error", errs)
	}
	if len(values) != 0 {
		t.Fatal("values not empty with invalid data, equal error")
	}
}

func TestValuesEnforcedSemicolonDelimitor(t *testing.T) {
	mapping := Mapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x30})
	values, errs := mapping.Values()
	if len(errs) != 1 || errs[0].Error() != "mapping format violation, expected ;" {
		t.Fatal("wrong error reported with semicolon format error", errs)
	}
	if len(values) != 0 {
		t.Fatal("values not empty with invalid data, semicolon error")
	}
}

func TestValuesReturnsValues(t *testing.T) {
	mapping := Mapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b})
	_, errs := mapping.Values()
	if errs != nil {
		t.Fatal("errs when parsing valid mapping values", errs)
	}
}

func TestHasDuplicateKeysTrueWhenDuplicates(t *testing.T) {
	dups := Mapping([]byte{0x00, 0x0c, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b})
	if dups.HasDuplicateKeys() != true {
		t.Fatal("HasDuplicateKeys did not report true when duplicate keys present")
	}
}

func TestHasDuplicateKeysFalseWithoutDuplicates(t *testing.T) {
	mapping := Mapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b})
	if mapping.HasDuplicateKeys() != false {
		t.Fatal("HasDuplicateKeys did not report false when duplicate keys were not present")
	}
}

func TestGoMapToMappingProducesCorrectMapping(t *testing.T) {
	gomap := map[string]string{"a": "b"}
	mapping, err := GoMapToMapping(gomap)
	if err != nil {
		t.Fatal("GoMapToMapping returned error with valid data", err)
	}
	expected := []byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b}
	if bytes.Compare(mapping, expected) != 0 {
		t.Fatal("GoMapToMapping did not produce correct Mapping", mapping, expected)
	}
}

func TestMappingOrderSortsValuesThenKeys(t *testing.T) {
	a, _ := ToI2PString("a")
	b, _ := ToI2PString("b")
	values := MappingValues{
		[2]String{b, b},
		[2]String{b, a},
		[2]String{a, b},
		[2]String{a, a},
	}
	mappingOrder(values)
	for i, pair := range values {
		key, _ := pair[0].Data()
		value, _ := pair[1].Data()
		switch i {
		case 0:
			if !(key == "a" && value == "a") {
				t.Fatal("mappingOrder produced incorrect sort output at", i)
			}
		case 1:
			if !(key == "a" && value == "b") {
				t.Fatal("mappingOrder produced incorrect sort output at", i)
			}
		case 2:
			if !(key == "b" && value == "a") {
				t.Fatal("mappingOrder produced incorrect sort output at", i)
			}
		case 3:
			if !(key == "b" && value == "b") {
				t.Fatal("mappingOrder produced incorrect sort output at", i)
			}
		}
	}
}

func TestStopValueReadTrueWhenCorrectErr(t *testing.T) {
	status := stopValueRead(errors.New("error parsing string: zero length"))
	if status != true {
		t.Fatal("stopValueRead not true when String error found")
	}
}

func TestStopValueReadFalseWhenWrongErr(t *testing.T) {
	status := stopValueRead(errors.New("something else"))
	if status != false {
		t.Fatal("stopValueRead not false when error not String error")
	}
}

func TestBeginsWithCorrectWhenTrue(t *testing.T) {
	slice := []byte{0x41}
	status := beginsWith(slice, 0x41)
	if status != true {
		t.Fatal("beginsWith did not return false on empty slice")
	}
}

func TestBeginsWithCorrectWhenFalse(t *testing.T) {
	slice := []byte{0x00}
	status := beginsWith(slice, 0x41)
	if status != false {
		t.Fatal("beginsWith did not return false on empty slice")
	}
}

func TestBeginsWithCorrectWhenNil(t *testing.T) {
	slice := make([]byte, 0)
	status := beginsWith(slice, 0x41)
	if status != false {
		t.Fatal("beginsWith did not return false on empty slice")
	}
}
