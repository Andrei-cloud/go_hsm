package logic

import (
	"encoding/hex"
	"testing"
)

func TestExecuteFA_AllZeroZPK(t *testing.T) {
	t.Parallel()
	// U + 32 hex ZMK + U + 32 hex ZPK (all zero)
	input := []byte(
		"U" + "0123456789ABCDEF0123456789ABCDEF" + "U" + "00000000000000000000000000000000",
	)
	_, err := ExecuteFA(input)
	if err == nil {
		t.Fatal("expected error for all zero ZPK, got nil")
	}
}

func TestExecuteFA_ParityAdvice(t *testing.T) {
	t.Parallel()
	// U + 32 hex ZMK + U + 32 hex ZPK (bad parity)
	zmk := "0123456789ABCDEF0123456789ABCDEF"
	zpk := "0123456789ABCDEF0123456789ABCDEE" // last byte even parity
	input := []byte("U" + zmk + "U" + zpk)
	resp, err := ExecuteFA(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp[2:4]) != "01" {
		t.Errorf("expected parity advice 01, got %s", string(resp[2:4]))
	}
}

func TestExecuteFA_Success(t *testing.T) {
	t.Parallel()
	// U + 32 hex ZMK + U + 32 hex ZPK (good parity)
	zmk := "0123456789ABCDEF0123456789ABCDEF"
	zpk := "0123456789ABCDEF0123456789ABCDEF"
	input := []byte("U" + zmk + "U" + zpk)
	resp, err := ExecuteFA(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp[:2]) != "FB" {
		t.Errorf("expected FB response, got %s", string(resp[:2]))
	}
	if string(resp[2:4]) != "00" {
		t.Errorf("expected error code 00, got %s", string(resp[2:4]))
	}
	if len(resp) < 4+1+32+6 {
		t.Errorf("response too short: %d", len(resp))
	}
	// Check KCV is hex
	kcv := resp[len(resp)-6:]
	_, err = hex.DecodeString(string(kcv))
	if err != nil {
		t.Errorf("invalid KCV: %s", string(kcv))
	}
}
