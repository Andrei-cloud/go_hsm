package logic

import (
	"encoding/hex"
	"strings"
)

// ExecuteM6 generates a MAC over a message under a TAK (003) or ZAK (008) with
// ISO/IEC 9797-1 algorithm 1 or 3. The request is the mode flag, input format
// flag, MAC size, MAC algorithm, padding method, key type, MAC key under LMK,
// message length (4H) and message block; see parseMACRequest. The response is
// "M7" + "00" + the MAC in hex (8 or 16 digits).
func ExecuteM6(input []byte) ([]byte, error) {
	logInfo("M6: generating MAC")

	req, err := parseMACRequest("M6", input)
	if err != nil {
		return nil, err
	}

	mac, err := req.mac()
	if err != nil {
		logError("M6: MAC calculation failed")
		return nil, err
	}

	resp := []byte("M700")
	resp = append(resp, strings.ToUpper(hex.EncodeToString(mac))...)

	return resp, nil
}
