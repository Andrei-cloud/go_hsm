package message

// NewA0 parses an A0 Generate Key command from payload data.
func NewA0(data []byte) *BaseMessage {
	m := NewBaseMessage("A0", "Generate a Key")
	// Mode (1).
	m.Fields["Mode"], data = data[:1], data[1:]
	// Key Type (3).
	m.Fields["Key Type"], data = data[:3], data[3:]
	// Key Scheme (1).
	m.Fields["Key Scheme"], data = data[:1], data[1:]
	if m.Fields["Mode"][0] == '1' {
		if data[0] == ';' {
			data = data[1:]
			m.Fields["ZMK/TMK Flag"], data = data[:1], data[1:]
		}
		if data[0] == 'U' {
			m.Fields["ZMK/TMK"], _ = data[:33], data[33:]
		}
	}

	return m
}

// NewBU parses a BU Generate Key Check Value command from payload data.
func NewBU(data []byte) *BaseMessage {
	m := NewBaseMessage("BU", "Generate a Key check value")
	m.Fields["Key Type Code"], data = data[:2], data[2:]
	m.Fields["Key Length Flag"], data = data[:1], data[1:]
	if data[0] == 'U' {
		m.Fields["Key"], _ = data[:33], data[33:]
	}

	return m
}
