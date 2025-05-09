package variantlmk

import "fmt"

var pciHSMComplianceMode bool

// KeyTypes maps key type codes to their LMK pair and variant mappings.
// This table is based on the Thales payShield documentation for Variant LMKs,
// specifically the "Key Type Table" (non-PCI compliant version shown first in spec).
var KeyTypes = map[string]KeyType{
	// LMK Pair Code 00 (LMKs 04-05, LMKSet index 2).
	"000": {Name: "ZMK", Code: "000", LMKPair: 2, VariantID: 0},
	"100": {Name: "ZMK (Comp)", Code: "100", LMKPair: 2, VariantID: 1},
	"200": {Name: "KML", Code: "200", LMKPair: 2, VariantID: 2},
	"300": {Name: "KEKr", Code: "300", LMKPair: 2, VariantID: 3},
	"400": {Name: "KEKs", Code: "400", LMKPair: 2, VariantID: 4},

	// LMK Pair Code 01 (LMKs 06-07, LMKSet index 3).
	"001": {Name: "ZPK", Code: "001", LMKPair: 3, VariantID: 0},
	// PEK4a and Auth Para1 would also use LMKPair: 3 with VariantID: 1 and 2 respectively if added.

	// LMK Pair Code 02 (LMKs 14-15, LMKSet index 7).
	"002": {Name: "PVK/Generic", Code: "002", LMKPair: 7, VariantID: 0},
	"102": {Name: "TMK1 (AS2805)", Code: "102", LMKPair: 7, VariantID: 1},
	"202": {Name: "TMK2 (AS2805)", Code: "202", LMKPair: 7, VariantID: 2},
	// IPEK would use LMKPair: 7, VariantID: 3.
	"402": {Name: "CVK/CSCK", Code: "402", LMKPair: 7, VariantID: 4},
	// KIA1 would use LMKPair: 7, VariantID: 6.
	"602": {Name: "KIA (AS2805)", Code: "602", LMKPair: 7, VariantID: 6},
	// PPASN1 would use LMKPair: 7, VariantID: 7.

	// LMK Pair Code 03 (LMKs 16-17, LMKSet index 8).
	"003": {Name: "TAK", Code: "003", LMKPair: 8, VariantID: 0},
	"103": {Name: "TAKs/TAKr (AS2805)", Code: "103", LMKPair: 8, VariantID: 1},

	// LMK Pair Code 04 (LMKs 18-19, LMKSet index 9).
	// DTAB5 (Variant 0), IPB (Variant 1) would use LMKPair: 9.

	// LMK Pair Code 05 (LMKs 20-21, LMKSet index 10).
	"105": {Name: "KML/KMLISS (OBKM)", Code: "105", LMKPair: 10, VariantID: 1},
	"205": {Name: "KMX/KMXISS (OBKM)", Code: "205", LMKPair: 10, VariantID: 2},
	"305": {Name: "KMP/KMPISS (OBKM)", Code: "305", LMKPair: 10, VariantID: 3},
	"405": {Name: "KIS.5 (OBKM)", Code: "405", LMKPair: 10, VariantID: 4},
	"505": {Name: "KM3L/KM3LISS (OBKM)", Code: "505", LMKPair: 10, VariantID: 5},
	"605": {Name: "KM3X/KM3XISS (OBKM)", Code: "605", LMKPair: 10, VariantID: 6},
	"705": {Name: "KMACS4 (OBKM)", Code: "705", LMKPair: 10, VariantID: 7},
	"805": {Name: "KMACS5 (OBKM)", Code: "805", LMKPair: 10, VariantID: 8},
	"905": {Name: "KMACACQ/KMACACK (OBKM)", Code: "905", LMKPair: 10, VariantID: 9},

	// LMK Pair Code 06 (LMKs 22-23, LMKSet index 11).
	"006": {Name: "WWK", Code: "006", LMKPair: 11, VariantID: 0},
	"106": {Name: "KMACUPD (OBKM)", Code: "106", LMKPair: 11, VariantID: 1},
	"206": {Name: "KMACMA (OBKM)", Code: "206", LMKPair: 11, VariantID: 2},
	"306": {Name: "KMACCI/KMACISS (OBKM)", Code: "306", LMKPair: 11, VariantID: 3},
	"406": {Name: "KMSCISS (OBKM)", Code: "406", LMKPair: 11, VariantID: 4},
	"506": {Name: "BKEM (OBKM)", Code: "506", LMKPair: 11, VariantID: 5},
	"606": {Name: "BKAM (OBKM)", Code: "606", LMKPair: 11, VariantID: 6},

	// LMK Pair Code 07 (LMKs 24-25, LMKSet index 12).
	"107": {Name: "KEK (Issuing)", Code: "107", LMKPair: 12, VariantID: 1},
	"207": {Name: "KMC (Issuing)", Code: "207", LMKPair: 12, VariantID: 2},
	"307": {Name: "SK-ENC (Issuing)", Code: "307", LMKPair: 12, VariantID: 3},
	"407": {Name: "SK-MAC (Issuing)", Code: "407", LMKPair: 12, VariantID: 4},
	"507": {Name: "SK-DEK/KDPERSO (Issuing)", Code: "507", LMKPair: 12, VariantID: 5},
	"807": {Name: "MK-KE (Issuing)", Code: "807", LMKPair: 12, VariantID: 8},
	"907": {Name: "MK-AS (Issuing)", Code: "907", LMKPair: 12, VariantID: 9},

	// LMK Pair Code 08 (LMKs 26-27, LMKSet index 13).
	"008": {Name: "ZAK", Code: "008", LMKPair: 13, VariantID: 0},
	"108": {Name: "ZAKs (AS2805)", Code: "108", LMKPair: 13, VariantID: 1},
	"208": {Name: "ZAKr (AS2805)", Code: "208", LMKPair: 13, VariantID: 2},

	// LMK Pair Code 09 (LMKs 28-29, LMKSet index 14).
	"009": {Name: "BDK type-1", Code: "009", LMKPair: 14, VariantID: 0},
	"109": {Name: "MK-AC", Code: "109", LMKPair: 14, VariantID: 1},
	"209": {Name: "MK-SMI", Code: "209", LMKPair: 14, VariantID: 2},
	"309": {Name: "MK-SMC", Code: "309", LMKPair: 14, VariantID: 3},
	"409": {Name: "MK-DAC", Code: "409", LMKPair: 14, VariantID: 4},
	"509": {Name: "MK-DN", Code: "509", LMKPair: 14, VariantID: 5},
	"609": {Name: "BDK type-2", Code: "609", LMKPair: 14, VariantID: 6},
	"709": {Name: "MK-CVC3/MK-DCVV3", Code: "709", LMKPair: 14, VariantID: 7},
	"809": {Name: "BDK type-3", Code: "809", LMKPair: 14, VariantID: 8},

	// LMK Pair Code 0A (LMKs 30-31, LMKSet index 15).
	"00A": {Name: "ZEK", Code: "00A", LMKPair: 15, VariantID: 0},
	"10A": {Name: "ZEKs (AS2805)", Code: "10A", LMKPair: 15, VariantID: 1},
	"20A": {Name: "ZEKr (AS2805)", Code: "20A", LMKPair: 15, VariantID: 2},

	// LMK Pair Code 0B (LMKs 32-33, LMKSet index 16).
	"00B": {Name: "DEK/TEK", Code: "00B", LMKPair: 16, VariantID: 0},
	"10B": {Name: "TEKs/TEKr (AS2805)", Code: "10B", LMKPair: 16, VariantID: 1},
	// TEK (no AS2805) is also listed under Variant 0 for LMK Pair Code 0B.
	// TEK (PCI Code 30B) is listed under Variant 3 for LMK Pair Code 0B.
	"30B": {Name: "TEK (PCI Code 30B)", Code: "30B", LMKPair: 16, VariantID: 3},

	// LMK Pair Code 0C (LMKs 34-35, LMKSet index 17).
	"00C": {Name: "RSA-SK", Code: "00C", LMKPair: 17, VariantID: 0},
	"10C": {Name: "HMAC", Code: "10C", LMKPair: 17, VariantID: 1},

	// LMK Pair Code 0D (LMKs 36-37, LMKSet index 18).
	"00D": {Name: "RSA-PK", Code: "00D", LMKPair: 18, VariantID: 0},
	// DbTAB5, TPK, KEYVAL, PEK1, PEK4b, TMK, KT1, KCA1, KMA1, KI1, TK1, TKR are listed under LMK Pair Code 0D
	// when "Enforce key type 002 separation for PCI HSM compliance” is set to “Y”.
	// For simplicity, we are primarily following the non-PCI table first.
	// These would map to LMKPair: 18 and various VariantIDs if added for PCI-compliant mode.

	// LMK Pair Code 0E (LMKs 38-39, LMKSet index 19) is Reserved.
}

// KeyTypesPCI maps key type codes to their LMK pair and variant mappings for PCI-HSM compliant mode.
// This table is based on the Thales payShield documentation for Variant LMKs,
// specifically "Key Type Table 2" and "Variant Key Type Codes" (Code 2 column).
// Note: Some key types from non-PCI mode are re-mapped to different LMK Pairs/Variants here.
// Key types not explicitly listed in Table 2 but present in the general "Variant Key Type Codes" list
// under "Code 2" are included if their LMK Pair/Variant is clear.
var KeyTypesPCI = map[string]KeyType{
	// LMK Pair Code 00 (LMKs 04-05, LMKSet index 2) - Same as non-PCI.
	"000": {Name: "ZMK", Code: "000", LMKPair: 2, VariantID: 0},
	"100": {Name: "ZMK (Comp)", Code: "100", LMKPair: 2, VariantID: 1},
	"200": {Name: "KML", Code: "200", LMKPair: 2, VariantID: 2},
	"300": {Name: "KEKr", Code: "300", LMKPair: 2, VariantID: 3},
	"400": {Name: "KEKs", Code: "400", LMKPair: 2, VariantID: 4},

	// LMK Pair Code 01 (LMKs 06-07, LMKSet index 3).
	"001": {Name: "ZPK", Code: "001", LMKPair: 3, VariantID: 0},
	// PEK4a (Code "70D" in "Variant Key Type Codes" for PCI) is LMKPair 3, VariantID 1 in Table 2.
	// We use "70D" as the code for TPK/PEK under LMK Pair 0D in PCI mode, so this specific PEK4a needs a distinct code if used.

	// LMK Pair Code 02 (LMKs 14-15, LMKSet index 7).
	"002": {Name: "PVK", Code: "002", LMKPair: 7, VariantID: 0},
	"102": {Name: "TMK1 (AS2805)", Code: "102", LMKPair: 7, VariantID: 1},
	"202": {Name: "TMK2 (AS2805)", Code: "202", LMKPair: 7, VariantID: 2},
	"402": {Name: "CVK/CSCK", Code: "402", LMKPair: 7, VariantID: 4},
	"602": {Name: "KIA (AS2805)", Code: "602", LMKPair: 7, VariantID: 6},

	// LMK Pair Code 03 (LMKs 16-17, LMKSet index 8) - Same as non-PCI.
	"003": {Name: "TAK", Code: "003", LMKPair: 8, VariantID: 0},
	"103": {Name: "TAKs/TAKr (AS2805)", Code: "103", LMKPair: 8, VariantID: 1},

	// LMK Pair Code 05 (LMKs 20-21, LMKSet index 10) - Same as non-PCI.
	"105": {Name: "KML/KMLISS (OBKM)", Code: "105", LMKPair: 10, VariantID: 1},
	"205": {Name: "KMX/KMXISS (OBKM)", Code: "205", LMKPair: 10, VariantID: 2},
	"305": {Name: "KMP/KMPISS (OBKM)", Code: "305", LMKPair: 10, VariantID: 3},
	"405": {Name: "KIS.5 (OBKM)", Code: "405", LMKPair: 10, VariantID: 4},
	"505": {Name: "KM3L/KM3LISS (OBKM)", Code: "505", LMKPair: 10, VariantID: 5},
	"605": {Name: "KM3X/KM3XISS (OBKM)", Code: "605", LMKPair: 10, VariantID: 6},
	"705": {Name: "KMACS4 (OBKM)", Code: "705", LMKPair: 10, VariantID: 7},
	"805": {Name: "KMACS5 (OBKM)", Code: "805", LMKPair: 10, VariantID: 8},
	"905": {Name: "KMACACQ/KMACACK (OBKM)", Code: "905", LMKPair: 10, VariantID: 9},

	// LMK Pair Code 06 (LMKs 22-23, LMKSet index 11) - Same as non-PCI.
	"006": {Name: "WWK", Code: "006", LMKPair: 11, VariantID: 0},
	"106": {Name: "KMACUPD (OBKM)", Code: "106", LMKPair: 11, VariantID: 1},
	"206": {Name: "KMACMA (OBKM)", Code: "206", LMKPair: 11, VariantID: 2},
	"306": {Name: "KMACCI/KMACISS (OBKM)", Code: "306", LMKPair: 11, VariantID: 3},
	"406": {Name: "KMSCISS (OBKM)", Code: "406", LMKPair: 11, VariantID: 4},
	"506": {Name: "BKEM (OBKM)", Code: "506", LMKPair: 11, VariantID: 5},
	"606": {Name: "BKAM (OBKM)", Code: "606", LMKPair: 11, VariantID: 6},

	// LMK Pair Code 07 (LMKs 24-25, LMKSet index 12) - Same as non-PCI.
	"107": {Name: "KEK (Issuing)", Code: "107", LMKPair: 12, VariantID: 1},
	"207": {Name: "KMC (Issuing)", Code: "207", LMKPair: 12, VariantID: 2},
	"307": {Name: "SK-ENC (Issuing)", Code: "307", LMKPair: 12, VariantID: 3},
	"407": {Name: "SK-MAC (Issuing)", Code: "407", LMKPair: 12, VariantID: 4},
	"507": {Name: "SK-DEK/KDPERSO (Issuing)", Code: "507", LMKPair: 12, VariantID: 5},
	"807": {Name: "MK-KE (Issuing)", Code: "807", LMKPair: 12, VariantID: 8},
	"907": {Name: "MK-AS (Issuing)", Code: "907", LMKPair: 12, VariantID: 9},

	// LMK Pair Code 08 (LMKs 26-27, LMKSet index 13) - Same as non-PCI.
	"008": {Name: "ZAK", Code: "008", LMKPair: 13, VariantID: 0},
	"108": {Name: "ZAKs (AS2805)", Code: "108", LMKPair: 13, VariantID: 1},
	"208": {Name: "ZAKr (AS2805)", Code: "208", LMKPair: 13, VariantID: 2},

	// LMK Pair Code 09 (LMKs 28-29, LMKSet index 14) - Same as non-PCI.
	"009": {Name: "BDK type-1", Code: "009", LMKPair: 14, VariantID: 0},
	"109": {Name: "MK-AC", Code: "109", LMKPair: 14, VariantID: 1},
	"209": {Name: "MK-SMI", Code: "209", LMKPair: 14, VariantID: 2},
	"309": {Name: "MK-SMC", Code: "309", LMKPair: 14, VariantID: 3},
	"409": {Name: "MK-DAC", Code: "409", LMKPair: 14, VariantID: 4},
	"509": {Name: "MK-DN", Code: "509", LMKPair: 14, VariantID: 5},
	"609": {Name: "BDK type-2", Code: "609", LMKPair: 14, VariantID: 6},
	"709": {Name: "MK-CVC3/MK-DCVV3", Code: "709", LMKPair: 14, VariantID: 7},
	"809": {Name: "BDK type-3", Code: "809", LMKPair: 14, VariantID: 8},

	// LMK Pair Code 0A (LMKs 30-31, LMKSet index 15) - Same as non-PCI.
	"00A": {Name: "ZEK", Code: "00A", LMKPair: 15, VariantID: 0},
	"10A": {Name: "ZEKs (AS2805)", Code: "10A", LMKPair: 15, VariantID: 1},
	"20A": {Name: "ZEKr (AS2805)", Code: "20A", LMKPair: 15, VariantID: 2},

	// LMK Pair Code 0B (LMKs 32-33, LMKSet index 16) - Same as non-PCI.
	"00B": {Name: "DEK/TEK", Code: "00B", LMKPair: 16, VariantID: 0},
	"10B": {Name: "TEKs/TEKr (AS2805)", Code: "10B", LMKPair: 16, VariantID: 1},
	"30B": {Name: "TEK (PCI Code 30B)", Code: "30B", LMKPair: 16, VariantID: 3},

	// LMK Pair Code 0C (LMKs 34-35, LMKSet index 17) - Same as non-PCI.
	"00C": {Name: "RSA-SK", Code: "00C", LMKPair: 17, VariantID: 0},
	"10C": {Name: "HMAC", Code: "10C", LMKPair: 17, VariantID: 1},

	// LMK Pair Code 0D (LMKs 36-37, LMKSet index 18).
	// In PCI mode, LMK Pair 0D is used for TPK, TMK, etc. (which were under LMK Pair 02 in non-PCI).
	"00D": {Name: "RSA-PK", Code: "00D", LMKPair: 18, VariantID: 0},
	// Key Type Code 2 from "Variant Key Type Codes" table for PCI HSM compliance:.
	"70D": {
		Name:      "TPK / PEK (PCI)",
		Code:      "70D",
		LMKPair:   18,
		VariantID: 2,
	}, // TPK is LMKPair 18, Var 2 in Table 2.
	"80D": {
		Name:      "TMK (PCI)",
		Code:      "80D",
		LMKPair:   18,
		VariantID: 4,
	}, // TMK is LMKPair 18, Var 4 in Table 2.
	"90D": {
		Name:      "TKR (PCI)",
		Code:      "90D",
		LMKPair:   18,
		VariantID: 9,
	}, // TKR is LMKPair 18, Var 9 in Table 2.
	// Other keys like KT, TK, KI, KCA, KMA from non-PCI LMK Pair 02 are also remapped to LMK Pair 18 with different variants in PCI mode.
	// For example, KT1 (AS2805) would be LMKPair 18, Variant 5.
	// These would need their specific "Code 2" values from the "Variant Key Type Codes" table or derived unique codes.
}

// KeyType defines the mapping of a key type to its LMK pair and variant.
// It aligns with the Thales Key Type Table.
// LMKPair is the 0-based index into the LMKSet (e.g., index 2 for LMKs 04-05).
// VariantID is the variant number (0-9) applied to the LMK pair.
// Code is the Thales Key Type Code (e.g., "000", "001", "002-70D").
// Name is a descriptive name for the key type.
type KeyType struct {
	Name      string
	Code      string
	LMKPair   int
	VariantID int
}

// String returns a string representation of the KeyType.
func (kt KeyType) String() string {
	return fmt.Sprintf(
		"Name: %s, Code: %s, LMKPairIndex: %d, VariantID: %d",
		kt.Name,
		kt.Code,
		kt.LMKPair,
		kt.VariantID,
	)
}

// SetPCIComplianceMode sets the HSM operating mode for key type table selection.
// If enabled is true, the PCI-HSM compliant key type table will be used.
func SetPCIComplianceMode(enabled bool) {
	pciHSMComplianceMode = enabled
}

// GetPCIComplianceMode returns true if the HSM is set to operate in PCI-HSM compliant mode.
func GetPCIComplianceMode() bool {
	return pciHSMComplianceMode
}

// GetKeyTypeDetails returns the LMK pair index and variant ID for a given key type string.
// It considers the PCI compliance mode to select the correct key type table.
func GetKeyTypeDetails(keyTypeStr string, pciMode bool) (KeyType, error) {
	var kt KeyType
	var ok bool

	if pciMode {
		kt, ok = KeyTypesPCI[keyTypeStr]
	} else {
		kt, ok = KeyTypes[keyTypeStr]
	}

	if !ok {
		return KeyType{}, fmt.Errorf("unknown key type: %s (PCI mode: %t)", keyTypeStr, pciMode)
	}

	return kt, nil
}
