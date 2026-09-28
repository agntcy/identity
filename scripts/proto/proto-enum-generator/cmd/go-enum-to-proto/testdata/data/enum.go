package data

import (
	"go-enums-test/data/data2"
)

// enum comment
type Enum int

const (
	// Const comment
	//
	// it ends here
	Enum_VALUE_1 Enum = iota
	Enum_VALUE_2
)

type Something struct {
	En  Enum
	En2 []Enum
	En3 map[string]data2.Enum2
}
