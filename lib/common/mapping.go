package common

import (
//	"encoding/binary"
//	"strings"
)

type Mapping []byte

//65537

func (mapping Mapping) Values() [][2]String {
	return make([][2]String, 0)
}

func ValuesToMapping(values [][2]String) Mapping {
	return Mapping{}
}
