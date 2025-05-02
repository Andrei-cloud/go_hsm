// Package errorcodes defines HSM errors using a structured type.
// HSMError holds the two-character code and human-readable description.
package errorcodes

// Predefined HSM error instances.
var (
	Err00 = HSMError{"00", "No error"}
	Err01 = HSMError{"01", "Verification failure or warning of imported key parity error"}
	Err02 = HSMError{"02", "Key inappropriate length for algorithm"}
	Err04 = HSMError{"04", "Invalid key type code"}
	Err05 = HSMError{"05", "Invalid key length flag"}
	Err10 = HSMError{"10", "Source key parity error"}
	Err11 = HSMError{"11", "Destination key parity error or key all zeros"}
	Err12 = HSMError{"12", "Contents of user storage not available. Reset, power-down or overwrite"}
	Err13 = HSMError{"13", "Invalid LMK Identifier"}
	Err14 = HSMError{"14", "PIN encrypted under LMK pair 02-03 is invalid"}
	Err15 = HSMError{
		"15",
		"Invalid input data (invalid format, invalid characters, or not enough data provided)",
	}
	Err16 = HSMError{"16", "Console or printer not ready or not connected"}
	Err17 = HSMError{"17", "HSM not authorized, or operation prohibited by security settings"}
	Err18 = HSMError{"18", "Document format definition not loaded"}
	Err19 = HSMError{"19", "Specified Diebold Table is invalid"}
	Err20 = HSMError{"20", "PIN block does not contain valid values"}
	Err21 = HSMError{
		"21",
		"Invalid index value, or index/block count would cause an overflow condition",
	}
	Err22 = HSMError{"22", "Invalid account number"}
	Err23 = HSMError{"23", "Invalid PIN block format code"}
	Err24 = HSMError{"24", "PIN is fewer than 4 or more than 12 digits in length"}
	Err25 = HSMError{"25", "Decimalization Table error"}
	Err26 = HSMError{"26", "Invalid key scheme"}
	Err27 = HSMError{"27", "Incompatible key length"}
	Err28 = HSMError{"28", "Invalid key type"}
	Err29 = HSMError{"29", "Key function not permitted"}
	Err30 = HSMError{"30", "Invalid reference number"}
	Err31 = HSMError{"31", "Insufficient solicitation entries for batch"}
	Err32 = HSMError{"32", "LIC007 (AES) not installed"}
	Err33 = HSMError{"33", "LMK key change storage is corrupted"}
	Err39 = HSMError{"39", "Fraud detection"}
	Err40 = HSMError{"40", "Invalid checksum"}
	Err41 = HSMError{"41", "Internal hardware/software error: bad RAM, invalid error codes, etc."}
	Err42 = HSMError{"42", "DES failure"}
	Err43 = HSMError{"43", "RSA Key Generation Failure"}
	Err47 = HSMError{"47", "Algorithm not licensed"}
	Err49 = HSMError{"49", "Private key error, report to supervisor"}
	Err51 = HSMError{"51", "Invalid message header"}
	Err65 = HSMError{"65", "Transaction Key Scheme set to None"}
	Err67 = HSMError{"67", "Command not licensed"}
	Err68 = HSMError{"68", "Command has been disabled"}
	Err69 = HSMError{"69", "PIN block format has been disabled"}
	Err74 = HSMError{"74", "Invalid digest info syntax (no hash mode only)"}
	Err75 = HSMError{"75", "Single length key masquerading as double or triple length key"}
	Err76 = HSMError{"76", "Public key length error"}
	Err77 = HSMError{"77", "Clear data block error"}
	Err78 = HSMError{"78", "Private key length error"}
	Err79 = HSMError{"79", "Hash algorithm object identifier error"}
	Err80 = HSMError{"80", "Data length error"}
	Err81 = HSMError{"81", "Invalid certificate header"}
	Err82 = HSMError{"82", "Invalid check value length"}
	Err83 = HSMError{"83", "Key block format error"}
	Err84 = HSMError{"84", "Key block check value error"}
	Err85 = HSMError{"85", "Invalid OAEP Mask Generation Function"}
	Err86 = HSMError{"86", "Invalid OAEP MGF Hash Function"}
	Err87 = HSMError{"87", "OAEP Parameter Error"}
	Err90 = HSMError{"90", "Data parity error in the request message received by the HSM"}
	Err91 = HSMError{"91", "Longitudinal Redundancy Check (LRC) mismatch"}
	Err92 = HSMError{"92", "Invalid Count value in async packet"}
	ErrA1 = HSMError{"A1", "Incompatible LMK schemes"}
	ErrA2 = HSMError{"A2", "Incompatible LMK identifiers"}
	ErrA3 = HSMError{"A3", "Incompatible keyblock LMK identifiers"}
	ErrA4 = HSMError{"A4", "Key block authentication failure"}
	ErrA5 = HSMError{"A5", "Incompatible key length"}
	ErrA6 = HSMError{"A6", "Invalid key usage"}
	ErrA7 = HSMError{"A7", "Invalid algorithm"}
	ErrA8 = HSMError{"A8", "Invalid mode of use"}
	ErrA9 = HSMError{"A9", "Invalid key version number"}
	ErrAA = HSMError{"AA", "Invalid export field"}
	ErrAB = HSMError{"AB", "Invalid number of optional blocks"}
	ErrAC = HSMError{"AC", "Optional header block error"}
	ErrAD = HSMError{"AD", "Key status optional block error"}
	ErrAE = HSMError{"AE", "Invalid start date/time"}
	ErrAF = HSMError{"AF", "Invalid end date/time"}
	ErrB0 = HSMError{"B0", "Invalid encryption mode"}
	ErrB1 = HSMError{"B1", "Invalid authentication mode"}
	ErrB2 = HSMError{"B2", "Miscellaneous keyblock error"}
	ErrB3 = HSMError{"B3", "Invalid number of optional blocks"}
	ErrB4 = HSMError{"B4", "Optional block data error"}
	ErrB5 = HSMError{"B5", "Incompatible components"}
	ErrB6 = HSMError{"B6", "Incompatible key status optional blocks"}
	ErrB7 = HSMError{"B7", "Invalid change field"}
	ErrB8 = HSMError{"B8", "Invalid old value"}
	ErrB9 = HSMError{"B9", "Invalid new value"}
	ErrBA = HSMError{"BA", "No key status block in the keyblock"}
	ErrBB = HSMError{"BB", "Invalid wrapping key"}
	ErrBC = HSMError{"BC", "Repeated optional block"}
	ErrBD = HSMError{"BD", "Incompatible key types"}
	ErrBE = HSMError{"BE", "Invalid keyblock header ID"}
)

// HSMError represents an HSM error with its code and description.
type HSMError struct {
	Code        string // two-character error code
	Description string // human-readable description
}

// Error implements the Go error interface: "<Code>: <Description>".
func (e HSMError) Error() string {
	return e.Code + ": " + e.Description
}

// CodeOnly returns only the error code (e.g., "68"), for embedding in HSM responses.
func (e HSMError) CodeOnly() string {
	return e.Code
}
