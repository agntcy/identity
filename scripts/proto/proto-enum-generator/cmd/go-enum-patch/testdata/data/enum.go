package data

// enum comment
type Enum int

const (
	// Const comment
	//
	// it ends here
	Enum_VALUE_1 Enum = iota

	// Const comment for value 2
	Enum_VALUE_2
)

type Enum3 int

const (
	Enum3_V1 Enum3 = iota
	Enum3_V2
	Enum3_V3
)
