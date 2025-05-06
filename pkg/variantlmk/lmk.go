package variantlmk

import "fmt"

// defaultLMKHex holds the Thales test LMK values for codes 00-39 stepping by 2.
var defaultLMKHex = map[int][2]string{
	0:  {"0101010101010101", "01017902CD1FD36E"},
	2:  {"2020202020202020", "3131313131313131"},
	4:  {"4040404040404040", "5151515151515151"},
	6:  {"6161616161616161", "7070707070707070"},
	8:  {"8080808080808080", "9191919191919191"},
	10: {"A1A1A1A1A1A1A1A1", "B0B0B0B0B0B0B0B0"},
	12: {"C1C1010101010101", "D0D0010101010101"},
	14: {"E0E0010101010101", "F1F1010101010101"},
	16: {"1C587F1C13924FEF", "0101010101010101"},
	18: {"0101010101010101", "0101010101010101"},
	20: {"0202020202020202", "0404040404040404"},
	22: {"0707070707070707", "1010101010101010"},
	24: {"1313131313131313", "1515151515151515"},
	26: {"1616161616161616", "1919191919191919"},
	28: {"1A1A1A1A1A1A1A1A", "1C1C1C1C1C1C1C1C"},
	30: {"2323232323232323", "2525252525252525"},
	32: {"2626262626262626", "2929292929292929"},
	34: {"2A2A2A2A2A2A2A2A", "2C2C2C2C2C2C2C2C"},
	36: {"2F2F2F2F2F2F2F2F", "3131313131313131"},
	38: {"0101010101010101", "0101010101010101"},
}

// DefaultLMKSet returns the default test LMK set with 20 LMK pairs.
func DefaultLMKSet() (LMKSet, error) {
	var set LMKSet
	for code, hexPair := range defaultLMKHex {
		pair, err := LoadLMKFromHex(hexPair[0], hexPair[1])
		if err != nil {
			return set, fmt.Errorf("invalid default LMK at code %d: %v", code, err)
		}

		// insert at pair index (code/2)
		index := code / 2
		if index < 0 || index >= len(set) {
			continue
		}
		set[index] = pair
	}

	return set, nil
}
