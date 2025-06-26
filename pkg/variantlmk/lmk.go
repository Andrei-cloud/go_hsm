package variantlmk

import "fmt"

// defaultLMKHex holds the hex string representations of the default double-length variant test LMK pairs.
// The keys are the LMK pair indices (0-19, corresponding to LMK pairs 00-01 to 38-39).
var defaultLMKHex = map[int][2]string{
	0:  {"0101010101010101", "7902CD1FD36EF8BA"}, // LMK 00-01 (Corrected based on spec page 97)
	1:  {"2020202020202020", "3131313131313131"}, // LMK 02-03
	2:  {"4040404040404040", "5151515151515151"}, // LMK 04-05
	3:  {"6161616161616161", "7070707070707070"}, // LMK 06-07
	4:  {"8080808080808080", "9191919191919191"}, // LMK 08-09
	5:  {"A1A1A1A1A1A1A1A1", "B0B0B0B0B0B0B0B0"}, // LMK 10-11
	6:  {"C1C1010101010101", "D0D0010101010101"}, // LMK 12-13
	7:  {"E0E0010101010101", "F1F1010101010101"}, // LMK 14-15
	8:  {"1C587F1C13924FEF", "0101010101010101"}, // LMK 16-17
	9:  {"0101010101010101", "0101010101010101"}, // LMK 18-19
	10: {"0202020202020202", "0404040404040404"}, // LMK 20-21
	11: {"0707070707070707", "1010101010101010"}, // LMK 22-23
	12: {"1313131313131313", "1515151515151515"}, // LMK 24-25
	13: {"1616161616161616", "1919191919191919"}, // LMK 26-27
	14: {"1A1A1A1A1A1A1A1A", "1C1C1C1C1C1C1C1C"}, // LMK 28-29
	15: {"2323232323232323", "2525252525252525"}, // LMK 30-31
	16: {"2626262626262626", "2929292929292929"}, // LMK 32-33
	17: {"2A2A2A2A2A2A2A2A", "2C2C2C2C2C2C2C2C"}, // LMK 34-35
	18: {"2F2F2F2F2F2F2F2F", "3131313131313131"}, // LMK 36-37
	19: {"0101010101010101", "0101010101010101"}, // LMK 38-39
}

// LoadDefaultLMKSet loads the predefined default LMK set (Double-length Variant Test LMK).
func LoadDefaultLMKSet() (LMKSet, error) {
	var lmkSet LMKSet
	for i := 0; i < 20; i++ {
		hexPair, ok := defaultLMKHex[i]
		if !ok {
			// This should ideally not happen if defaultLMKHex is complete for 0-19.
			return LMKSet{}, fmt.Errorf("missing default LMK hex definition for index %d", i)
		}
		lmkPair, err := LoadLMKFromHex(hexPair[0], hexPair[1])
		if err != nil {
			return LMKSet{}, fmt.Errorf(
				"failed to load LMK pair for index %d (hex: %v): %w",
				i,
				hexPair,
				err,
			)
		}
		lmkSet[i] = lmkPair
	}

	return lmkSet, nil
}
