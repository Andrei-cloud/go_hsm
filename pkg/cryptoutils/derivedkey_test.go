//nolint:all // test package
package cryptoutils

import (
	"crypto/aes"
	"crypto/des"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestDecimalize(t *testing.T) {
	hash, _ := hex.DecodeString("1234567890ABCDEF1234567890ABCDEF12345678")
	got := decimalize(hash)
	if len(got) != 16 {
		t.Errorf("decimalize() length = %d, want 16", len(got))
	}
}

func TestXor(t *testing.T) {
	a := []byte{0xAA, 0x55}
	b := []byte{0xFF, 0x00}
	want := []byte{0x55, 0x55}
	got := xor(a, b)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("xor(%v, %v) = %v, want %v", a, b, got, want)
	}
}

func TestBytesRepeat(t *testing.T) {
	got := bytesRepeat(0xAB, 4)
	want := []byte{0xAB, 0xAB, 0xAB, 0xAB}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("bytesRepeat(0xAB, 4) = %v, want %v", got, want)
	}
}

func TestAesEcbEncryptBlock(t *testing.T) {
	key := make([]byte, aes.BlockSize)
	blk := make([]byte, aes.BlockSize)
	_, err := aesECBEncryptBlock(key, blk)
	if err != nil {
		t.Errorf("aesECBEncryptBlock() error = %v, want nil", err)
	}
	badBlk := make([]byte, 8)
	_, err = aesECBEncryptBlock(key, badBlk)
	if err == nil {
		t.Error("aesECBEncryptBlock() with bad block size: want error, got nil")
	}
}

func TestDerive3DESKey(t *testing.T) {
	imk := make([]byte, 16)
	block8 := make([]byte, des.BlockSize)
	_, err := derive3DESKey(imk, block8)
	if err != nil {
		t.Errorf("derive3DESKey() error = %v, want nil", err)
	}
	badBlock := make([]byte, 7)
	_, err = derive3DESKey(imk, badBlock)
	if err == nil {
		t.Error("derive3DESKey() with bad block size: want error, got nil")
	}
}
