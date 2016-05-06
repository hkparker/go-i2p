package common

import (
	"bytes"
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestValuesExclusesPairWithBadData(t *testing.T) {
	assert := assert.New(t)

	bad_key := Mapping([]byte{0x00, 0x0c, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x00})
	values, errs := bad_key.Values()

	if assert.Equal(len(values), 1, "Values() did not return valid values when some values had bad key") {
		key, _ := values[0][0].Data()
		val, _ := values[0][1].Data()
		assert.Equal(key, "a", "Values() returned by data with invalid key contains incorrect present key")
		assert.Equal(val, "b", "Values() returned by data with invalid key contains incorrect present key")
	}
	assert.Equal(len(errs), 2, "Values() reported wrong error count when some values had invalid data")
}

func TestValuesWarnsMissingData(t *testing.T) {
	assert := assert.New(t)

	mapping := Mapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62})
	_, errs := mapping.Values()

	if assert.Equal(len(errs), 2, "Values() reported wrong error count when mapping had missing data") {
		assert.Equal(errs[0].Error(), "warning parsing mapping: mapping length exceeds provided data", "correct error message should be returned")
	}
}

func TestValuesWarnsExtraData(t *testing.T) {
	assert := assert.New(t)

	mapping := Mapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x00})
	_, errs := mapping.Values()

	if assert.Equal(len(errs), 2, "Values() reported wrong error count when mapping had extra data") {
		assert.Equal(errs[0].Error(), "warning parsing mapping: data exists beyond length of mapping", "correct error message should be returned")
	}
}

func TestValuesEnforcesEqualDelimitor(t *testing.T) {
	assert := assert.New(t)

	mapping := Mapping([]byte{0x00, 0x06, 0x01, 0x61, 0x30, 0x01, 0x62, 0x3b})
	values, errs := mapping.Values()

	if assert.Equal(len(errs), 1, "Values() reported wrong error count when mapping had = format error") {
		assert.Equal(errs[0].Error(), "mapping format violation, expected =", "correct error message should be returned")
	}
	assert.Equal(len(values), 0, "Values() not empty with invalid data due to = format error")
}

func TestValuesEnforcedSemicolonDelimitor(t *testing.T) {
	assert := assert.New(t)

	mapping := Mapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x30})
	values, errs := mapping.Values()

	if assert.Equal(len(errs), 1, "Values() reported wrong error count when mapping had ; format error") {
		assert.Equal(errs[0].Error(), "mapping format violation, expected ;", "correct error message should be returned")
	}
	assert.Equal(len(values), 0, "Values() not empty with invalid data due to ; format error")
}

func TestValuesReturnsValues(t *testing.T) {
	assert := assert.New(t)

	mapping := Mapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b})
	values, errs := mapping.Values()
	key, kerr := values[0][0].Data()
	val, verr := values[0][1].Data()

	assert.Nil(errs, "Values() returned a errors with parsing valid data")
	assert.Nil(kerr)
	assert.Nil(verr)
	assert.Equal(key, "a", "Values() did not return key in valid data")
	assert.Equal(val, "b", "Values() did not return value in valid data")
}

func TestHasDuplicateKeysTrueWhenDuplicates(t *testing.T) {
	assert := assert.New(t)

	dups := Mapping([]byte{0x00, 0x0c, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b})

	assert.Equal(dups.HasDuplicateKeys(), true, "HasDuplicateKeys() did not report true when duplicate keys present")
}

func TestHasDuplicateKeysFalseWithoutDuplicates(t *testing.T) {
	assert := assert.New(t)

	mapping := Mapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b})

	assert.Equal(mapping.HasDuplicateKeys(), false, "HasDuplicateKeys() did not report false when no duplicate keys present")
}

func TestGoMapToMappingProducesCorrectMapping(t *testing.T) {
	assert := assert.New(t)

	gomap := map[string]string{"a": "b"}
	mapping, err := GoMapToMapping(gomap)

	assert.Nil(err, "GoMapToMapping() returned error with valid data")
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
	assert := assert.New(t)

	status := stopValueRead(errors.New("error parsing string: zero length"))

	assert.Equal(status, true, "stopValueRead() did not return true when String error found")
}

func TestStopValueReadFalseWhenWrongErr(t *testing.T) {
	assert := assert.New(t)

	status := stopValueRead(errors.New("something else"))

	assert.Equal(status, false, "stopValueRead() did not return false when non String error found")
}

func TestBeginsWithCorrectWhenTrue(t *testing.T) {
	assert := assert.New(t)

	slice := []byte{0x41}

	assert.Equal(beginsWith(slice, 0x41), true, "beginsWith() did not return true when correct")
}

func TestBeginsWithCorrectWhenFalse(t *testing.T) {
	assert := assert.New(t)

	slice := []byte{0x00}

	assert.Equal(beginsWith(slice, 0x41), false, "beginsWith() did not false when incorrect")
}

func TestBeginsWithCorrectWhenNil(t *testing.T) {
	assert := assert.New(t)

	slice := make([]byte, 0)

	assert.Equal(beginsWith(slice, 0x41), false, "beginsWith() did not return false on empty slice")
}
