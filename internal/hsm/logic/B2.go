package logic

import (
	"fmt"
	"strconv"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
)

// ExecuteB2 processes the B2 command payload.
// B2 is an Echo command that returns the same data back to the caller.
func ExecuteB2(input []byte) ([]byte, error) {
	logInfo("B2: Starting command processing.")
	logDebug(fmt.Sprintf("B2: command input length: %d", len(input)))

	if len(input) < 4 {
		return nil, errorcodes.Err15
	}

	// First 4 bytes are the data length in hex (ASCII encoded).
	lengthField := input[:4]

	dataLen64, err := strconv.ParseUint(string(lengthField), 16, 32)
	if err != nil {
		return nil, errorcodes.Err15
	}

	dataLen := int(dataLen64)

	logInfo(fmt.Sprintf("B2: data length: %d", dataLen))
	if len(input) < 4+dataLen {
		return nil, errorcodes.Err15
	}
	dataField := input[4 : 4+dataLen]

	resp := make([]byte, 0, 4+len(dataField))
	resp = append(resp, []byte("B300")...)
	resp = append(resp, dataField...)

	return resp, nil
}
