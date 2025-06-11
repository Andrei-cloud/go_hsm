package keyblocklmk

// OptionalBlock represents a TLV-encoded optional header block.
// Tag is a 2-character string, Value is the raw bytes of the TLV value.
type OptionalBlock struct {
	Tag   string
	Value []byte
}

// Marshal returns the TLV encoding of the OptionalBlock.
func (o OptionalBlock) Marshal() []byte {
	// Tag: ASCII characters (2 bytes)
	// Length: 1 byte of value length
	// Value: raw bytes
	buf := make([]byte, 0, 2+1+len(o.Value))
	buf = append(buf, []byte(o.Tag)...)
	buf = append(buf, byte(len(o.Value)))
	buf = append(buf, o.Value...)

	return buf
}
