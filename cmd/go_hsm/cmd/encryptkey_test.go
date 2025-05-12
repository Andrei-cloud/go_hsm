// nolint:all // test package
package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptKeyCmd(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name: "Valid double length key",
			args: []string{
				"--key", "0123456789ABCDEFFEDCBA9876543210",
				"--type", "002",
				"--scheme", "U",
			},
			wantErr: false,
		},
		{
			name: "Valid triple length key",
			args: []string{
				"--key", "0123456789ABCDEFFEDCBA98765432100123456789ABCDEF",
				"--type", "002",
				"--scheme", "T",
			},
			wantErr: false,
		},
		{
			name: "Invalid key parity",
			args: []string{
				"--key", "0123456789ABCDEEFEDCBA9876543210",
				"--type", "002",
				"--scheme", "U",
			},
			wantErr: true,
		},
		{
			name: "Invalid scheme",
			args: []string{
				"--key", "0123456789ABCDEFFEDCBA9876543210",
				"--type", "002",
				"--scheme", "X",
			},
			wantErr: true,
		},
		{
			name: "Invalid key length for scheme",
			args: []string{
				"--key", "0123456789ABCDEFFEDCBA9876543210",
				"--type", "002",
				"--scheme", "T",
			},
			wantErr: true,
		},
		{
			name: "Invalid hex key",
			args: []string{
				"--key", "0123456789ABCDEFFEDCBA987654321G",
				"--type", "002",
				"--scheme", "U",
			},
			wantErr: true,
		},
		{
			name: "Missing required flag",
			args: []string{
				"--key", "0123456789ABCDEFFEDCBA9876543210",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := encryptKeyCmd
			b := bytes.NewBufferString("")
			cmd.SetOut(b)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				out := b.String()
				assert.Contains(t, out, "Encrypted Key:")
				assert.Contains(t, out, "KCV:")
				assert.Contains(t, out, "Key Type:")
				assert.Contains(t, out, "Key Scheme:")
			}
		})
	}
}
