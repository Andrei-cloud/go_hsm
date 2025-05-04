package cryptoutils

import (
	"reflect"
	"testing"
)

func TestRaw2StrAndRaw2B(t *testing.T) {
	data := []byte{0x01, 0xAB, 0x0F}
	hexStr := Raw2Str(data)
	if hexStr != "01AB0F" {
		t.Errorf("Raw2Str expected 01AB0F, got %s", hexStr)
	}
	hexB := Raw2B(data)
	if !reflect.DeepEqual(hexB, []byte("01AB0F")) {
		t.Errorf("Raw2B expected 01AB0F, got %s", string(hexB))
	}
}

func TestB2Raw(t *testing.T) {
	hexB := []byte("0a0b0c")
	raw, err := B2Raw(hexB)
	if err != nil {
		t.Fatalf("B2Raw unexpected error: %v", err)
	}
	if !reflect.DeepEqual(raw, []byte{0x0A, 0x0B, 0x0C}) {
		t.Errorf("B2Raw expected [0x0A 0x0B 0x0C], got %x", raw)
	}
	_, err = B2Raw([]byte("zz"))
	if err == nil {
		t.Error("B2Raw expected error for invalid hex, got nil")
	}
}

func TestXOR(t *testing.T) {
	b1 := []byte("AA") // hex AA
	b2 := []byte("01")
	res, err := XOR(b1, b2)
	if err != nil {
		t.Fatalf("XOR unexpected error: %v", err)
	}
	// 0xAA ^ 0x01 = 0xAB -> "AB"
	if string(res) != "AB" {
		t.Errorf("XOR expected AB, got %s", string(res))
	}
	_, err = XOR([]byte("A"), []byte("BB"))
	if err == nil {
		t.Error("XOR expected length mismatch error, got nil")
	}
}

func TestHexify(t *testing.T) {
	s, err := Hexify(10)
	if err != nil {
		t.Fatalf("Hexify unexpected error: %v", err)
	}
	if s != "0A" {
		t.Errorf("Hexify expected 0A, got %s", s)
	}
	s, err = Hexify(255)
	if err != nil {
		t.Fatalf("Hexify unexpected error: %v", err)
	}
	if s != "FF" {
		t.Errorf("Hexify expected FF, got %s", s)
	}
	_, err = Hexify(-1)
	if err == nil {
		t.Error("Hexify expected error for negative value, got nil")
	}
}

func TestGetDigitsFromString(t *testing.T) {
	input := "1A2b3c4d"
	out := GetDigitsFromString(input, 3)
	if out != "123" {
		t.Errorf("expected 123, got %s", out)
	}
	// request more digits than available: second pass
	out2 := GetDigitsFromString("ABCDEF", 2)
	// A=10->0, B=11->1 => expect "01"
	if out2 != "01" {
		t.Errorf("expected 01, got %s", out2)
	}
}

func TestParityAndKeyParity(t *testing.T) {
	if ParityOf(0x00) != 0 {
		t.Error("expected even parity for 0x00")
	}
	if ParityOf(0x01) != -1 {
		t.Error("expected odd parity for 0x01")
	}
	key := []byte{0x01, 0x02}
	if CheckKeyParity(key) {
		t.Error("expected CheckKeyParity false for odd parity")
	}
	fixed := ModifyKeyParity(key)
	if !CheckKeyParity(fixed) {
		t.Error("expected fixed key parity to be even")
	}
}

func TestGetPINBlock(t *testing.T) {
	pin := "1234"
	pan := "4000123412341234"
	block, err := GetPINBlock(pin, pan)
	if err != nil {
		t.Fatalf("GetPINBlock unexpected error: %v", err)
	}
	if len(block) != 16 {
		t.Errorf("expected PIN block length 16 hex chars, got %d", len(block))
	}
	// Expect clear pin recovery to fail due to padding logic mismatch.
	_, err = GetClearPin([]byte(block), pan)
	if err == nil {
		t.Error("GetClearPin expected error for mismatched padding, got nil")
	}
}

func TestEmptyPinOrPan(t *testing.T) {
	// Empty pin should return error
	_, err := GetPINBlock("", "1234")
	if err == nil {
		t.Error("expected error for empty pin")
	}

	// Empty pan should return error
	_, err = GetPINBlock("1234", "")
	if err == nil {
		t.Error("expected error for empty pan")
	}

	// GetClearPin with empty input should return error
	_, err = GetClearPin([]byte(""), "1234")
	if err == nil {
		t.Error("expected error for empty pinBlockHex")
	}
}
