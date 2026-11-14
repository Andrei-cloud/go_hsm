package logic

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/moov-io/tr31/pkg/tr31"
)

// The published ANSI X9 TR-31 example of a version B block: a PIN encryption
// key (P0, encrypt only) under its key block protection key. Its keys carry no
// DES parity, so it is opened here, not through A6, which checks the ZMK's.
const (
	exampleKBPK  = "89E88CF7931444F334BD7547FC3F380C"
	exampleKey   = "F039121BEC83D26B169BDCD5B22AAF8F"
	exampleBlock = "B0120P0TE12E0100KS1800604B120F9292800000" +
		"E6E28F097CB0350B2EB2DF520947F779FA34D9759CEE7E0DEEACF8353DB778D47FA4EC20DA3A9754"
)

func TestOpenKeyBlockOpensThePublishedExample(t *testing.T) {
	t.Parallel()

	kbpk, _ := hex.DecodeString(exampleKBPK)

	key, err := openKeyBlock("A6", kbpk, exampleBlock, "001")
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.ToUpper(hex.EncodeToString(key)); got != exampleKey {
		t.Fatalf("key %s, want %s", got, exampleKey)
	}
}

func TestOpenKeyBlockRefuses(t *testing.T) {
	t.Parallel()

	kbpk, _ := hex.DecodeString(exampleKBPK)
	other, _ := hex.DecodeString("FEDCBA98765432100123456789ABCDEF")

	tests := []struct {
		name    string
		kbpk    []byte
		block   string
		keyType string
		wantErr error
	}{
		{"a PIN key offered as a MAC key", kbpk, exampleBlock, "008", errorcodes.ErrA6},
		{"a block under another key", other, exampleBlock, "001", errorcodes.ErrA4},
		{"a block whose MAC was changed", kbpk, exampleBlock[:len(exampleBlock)-1] + "5", "001", errorcodes.ErrA4},
		{"a block cut short", kbpk, exampleBlock[:len(exampleBlock)-16], "001", errorcodes.Err83},
		{"a key type that never travels in a block", kbpk, exampleBlock, "009", errorcodes.Err04},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := openKeyBlock("A6", tc.kbpk, tc.block, tc.keyType); !errors.Is(err, tc.wantErr) {
				t.Fatalf("error %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestSealKeyBlockCarriesTheKeyTypesUse(t *testing.T) {
	t.Parallel()

	zmk, _ := hex.DecodeString("FEDCBA98765432100123456789ABCDEF")
	key, _ := hex.DecodeString(exchangeKey)

	for keyType, wantHeader := range map[string]string{
		"008": "B0096M3TC00N0000",
		"003": "B0096M3TC00N0000",
		"001": "B0096P0TB00N0000",
		"000": "B0096K0TB00N0000",
	} {
		t.Run(keyType, func(t *testing.T) {
			t.Parallel()

			block, err := sealKeyBlock("A8", zmk, key, keyType)
			if err != nil {
				t.Fatal(err)
			}

			if !strings.HasPrefix(block, wantHeader) {
				t.Fatalf("block %s, want header %s", block, wantHeader)
			}

			if block != strings.ToUpper(block) {
				t.Fatalf("block %s, want upper-case hex", block)
			}

			// Anyone holding the ZMK opens it with the standard, not with this package.
			kb, err := tr31.NewKeyBlock(zmk, nil)
			if err != nil {
				t.Fatal(err)
			}

			back, err := kb.Unwrap(block)
			if err != nil || hex.EncodeToString(back) != strings.ToLower(exchangeKey) {
				t.Fatalf("opened %x, %v", back, err)
			}
		})
	}
}

func TestA8AndA6CarryAKeyBlockBothWays(t *testing.T) {
	t.Parallel()

	// The test LMK takes a key "under LMK" as given and returns one encrypted.
	exported, err := ExecuteA8([]byte("008" + exchangeZMK + "U" + exchangeKey + "R"))
	if err != nil {
		t.Fatal(err)
	}

	resp := string(exported)
	if !strings.HasPrefix(resp, "A900RB0096M3TC00N0000") || !strings.HasSuffix(resp, exchangeKeyKCV) {
		t.Fatalf("A8 answered %s", resp)
	}

	block := resp[len("A900"):strings.LastIndex(resp, exchangeKeyKCV)]

	imported, err := ExecuteA6([]byte("008" + exchangeZMK + block + "U"))
	if err != nil {
		t.Fatal(err)
	}

	if want := "A700U" + underTestLMK(t, exchangeKey) + exchangeKeyKCV; string(imported) != want {
		t.Fatalf("A6 answered %s, want %s", imported, want)
	}
}

func TestA6RefusesAKeyBlockThatDoesntFit(t *testing.T) {
	t.Parallel()

	zmk, _ := hex.DecodeString("FEDCBA98765432100123456789ABCDEF")
	key, _ := hex.DecodeString(exchangeKey)

	pinBlock, err := sealKeyBlock("A8", zmk, key, "001")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"a PIN key block taken in as a ZAK", "008" + exchangeZMK + "R" + pinBlock + "U", errorcodes.ErrA6},
		{"a block whose length is not digits", "008" + exchangeZMK + "RB00X6" + pinBlock[6:] + "U", errorcodes.Err83},
		{"a block longer than the request", "008" + exchangeZMK + "RB9999" + pinBlock[5:], errorcodes.Err83},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := ExecuteA6([]byte(tc.input)); !errors.Is(err, tc.wantErr) {
				t.Fatalf("error %v, want %v", err, tc.wantErr)
			}
		})
	}
}
