package logic

import (
	"crypto/subtle"
	"encoding/hex"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
)

// ExecuteM8 verifies a MAC over a message under a TAK (003) or ZAK (008). The
// request is as M6's, followed by the MAC to verify in hex (8 or 16 digits, per
// the MAC size). The response is "M9" + "00" when the MAC holds, and "M9" +
// "01" when it does not.
func ExecuteM8(input []byte) ([]byte, error) {
	logInfo("M8: verifying MAC")

	req, err := parseMACRequest("M8", input)
	if err != nil {
		return nil, err
	}

	digits := req.macBytes * 2
	if len(req.rest) < digits {
		logError("M8: missing MAC")
		return nil, errorcodes.Err15
	}
	given, err := hex.DecodeString(string(req.rest[:digits]))
	if err != nil {
		logError("M8: MAC is not hex")
		return nil, errorcodes.Err15
	}

	want, err := req.mac()
	if err != nil {
		logError("M8: MAC calculation failed")
		return nil, err
	}
	if subtle.ConstantTimeCompare(want, given) != 1 {
		logInfo("M8: MAC verification failed")
		return nil, errorcodes.Err01
	}

	return []byte("M900"), nil
}
