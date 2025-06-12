// Package keys provides helper functions for key block parsing.
package keys

import "fmt"

func getVersionMeaning(b byte) string {
	switch b {
	case '0':
		return "Thales Key Block protected by a 3-DES key."
	case '1':
		return "Thales Key Block protected by an AES key."
	default:
		return "Unknown version."
	}
}

func getKeyUsageMeaning(u string) string {
	usage := map[string]string{
		"01": "DES/3DES WatchWord Key (WWK)",
		"02": "RSA Public Key",
		"03": "RSA Private Key (for signing/key mgt)",
		"04": "RSA Private Key (for ICCs)",
		"05": "RSA Private Key (for PIN translation)",
		"06": "RSA Private Key (for TLS pre-master secret decryption)",
		"B0": "3DES/AES Base Derivation Key (BDK-1)",
		"41": "3DES/AES Base Derivation Key (BDK-2)",
		"42": "3DES Base Derivation Key (BDK-3)",
		"43": "3DES/AES Base Derivation Key (BDK-4)",
		"B1": "3DES/AES DUKPT Initial Key (IKEY)",
		"C0": "DES/3DES Card Verification Key",
		"11": "DES/3DES Card Verification Key (American Express CSC)",
		"12": "DES/3DES Card Verification Key (Mastercard CVC)",
		"13": "DES/3DES Card Verification Key (Visa CVV)",
		"D0": "AES/DES/3DES Data Encryption Key (Generic)",
		"21": "AES/DES/3DES Data Encryption Key (DEK)",
		"22": "AES/DES/3DES Data Encryption Key (ZEK)",
		"23": "AES/DES/3DES Data Encryption Key (TEK)",
		"24": "AES Key Encryption Key (Transport Key)",
		"E0": "AES/DES/3DES EMV/Chip card Master Key: Application Cryptogram (MKAC)",
		"E1": "DES/3DES EMV/Chip card Master Key: Secure Messaging for Confidentiality (MKSMC)",
		"E2": "DES/3DES/AES EMV/Chip card Master Key: Secure Messaging for Integrity (MKSMI)",
		"E3": "DES/3DES EMV/Chip card Master Key: Data Authentication Code (MKDAC)",
		"E4": "DES/3DES EMV/Chip card Master Key: Dynamic Numbers (MKDN)",
		"E5": "DES/3DES EMV/Chip card Master Key: Card Personalization",
		"E6": "DES/3DES EMV/chip card Master Key: Other",
		"E7": "DES/3DES EMV/Master Personalization Key",
		"31": "DES/3DES Visa Cash Master Load Key (KML)",
		"32": "DES/3DES Dynamic CVV Master Key (MK-CVC3)",
		"33": "AES Mobile Remote Management Master key for message confidentiality (M_KEY_CONF)",
		"34": "AES Mobile Remote Management Master key for message integrity (M_KEY_MAC)",
		"35": "AES Mobile Remote Management Session key for message confidentiality (MS_KEY_CONF)",
		"36": "AES Mobile Remote Management Session key for message integrity (MS_KEY_MAC)",
		"37": "3DES EMV Card Key for cryptograms",
		"38": "3DES EMV Card Key for integrity",
		"39": "3DES EMV Card Key for encryption",
		"40": "3DES EMV Personalization System Key",
		"47": "3DES/AES EMV Session Key for cryptograms",
		"48": "3DES/AES EMV Session Key for integrity",
		"49": "3DES EMV Session Key for encryption",
		"I0": "Initialization Value",
		"K0": "Key Encryption / Wrapping Key (Generic)",
		"51": "3DES Terminal Key Encryption (TMK)",
		"52": "DES/3DES Zone Key Encryption (ZMK)",
		"53": "3DES ZKA Master Key",
		"54": "AES/3DES Key Encryption Key (KEK)",
		"55": "AES Key Encryption Key (Transport Key)",
		"M0": "ISO 16609 MAC algorithm 1 (using 3-DES)",
		"M1": "ISO 9797-1 MAC algorithm 1",
		"M2": "DES/3DES ISO 9797-1 MAC algorithm 2",
		"M3": "3DES ISO 9797-1 MAC algorithm 3",
		"M4": "DES/3DES ISO 9797-1 MAC algorithm 4",
		"M5": "AES CBC MAC",
		"M6": "AES CMAC",
		"61": "HMAC key (using SHA-1)",
		"62": "HMAC key (using SHA-224)",
		"63": "HMAC key (using SHA-256)",
		"64": "HMAC key (using SHA-384)",
		"65": "HMAC key (using SHA-512)",
		"P0": "AES/DES/3DES PIN Encryption Key (Generic)",
		"71": "Terminal PIN Encryption Key (TPK)",
		"72": "Zone PIN Encryption Key (ZPK)",
		"73": "DES/3DES Transaction Key Scheme Terminal Key Register (TKR)",
		"V0": "DES/3DES PIN Verification Key (Generic)",
		"V1": "DES/3DES PIN Verification Key (IBM 3624 algorithm)",
		"V2": "DES/3DES PIN Verification Key (Visa PVV algorithm)",
	}
	if m, ok := usage[u]; ok {
		return m
	}
	return "Unknown key usage."
}

func getAlgorithmMeaning(b byte) string {
	switch b {
	case 'A':
		return "AES"
	case 'D':
		return "DES"
	case 'E':
		return "Elliptic curve"
	case 'H':
		return "HMAC"
	case 'R':
		return "RSA"
	case 'S':
		return "DSA"
	case 'T':
		return "3-DES"
	default:
		return "Unknown algorithm"
	}
}

func getModeOfUseMeaning(b byte) string {
	switch b {
	case 'B':
		return "Both encrypt and decrypt"
	case 'C':
		return "MAC calculation (both generate & verify)"
	case 'D':
		return "Decrypt only"
	case 'E':
		return "Encrypt only"
	case 'G':
		return "MAC generate only"
	case 'N':
		return "No special restrictions"
	case 'S':
		return "Digital signature generation only"
	case 'V':
		return "Digital signature verification only"
	case 'X':
		return "Derivation only"
	default:
		return "Unknown mode of use"
	}
}

func getKeyVersionMeaning(s string) string {
	if s == "00" {
		return "Key versioning not used"
	}
	if len(s) >= 1 && s[0] == 'c' {
		if len(s) >= 2 {
			return fmt.Sprintf("Key component %c", s[1])
		}

		return "Key component (unspecified)"
	}

	return fmt.Sprintf("Version %s", s)
}

func getExportabilityMeaning(b byte) string {
	switch b {
	case 'E':
		return "May only be exported in a trusted key block"
	case 'N':
		return "No export permitted"
	case 'S':
		return "Sensitive; all other export possibilities permitted"
	default:
		return "Unknown exportability"
	}
}
