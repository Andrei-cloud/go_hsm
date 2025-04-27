package message

import (
	"bytes"
	"fmt"
)

// Message defines the interface for HSM messages.
type Message interface {
	Get(field string) []byte
	Set(field string, val []byte)
	CommandCode() string
	Trace() string
}

// BaseMessage implements Message and holds command fields.
type BaseMessage struct {
	header      []byte
	cmdCode     string
	description string
	Fields      map[string][]byte
}

// NewBaseMessage creates a new BaseMessage with the given code and description.
func NewBaseMessage(cmdCode, description string) *BaseMessage {
	return &BaseMessage{cmdCode: cmdCode, description: description, Fields: make(map[string][]byte)}
}

func (m *BaseMessage) Get(field string) []byte {
	return m.Fields[field]
}

func (m *BaseMessage) Set(field string, val []byte) {
	m.Fields[field] = val
}

func (m *BaseMessage) CommandCode() string {
	return m.cmdCode
}

func (m *BaseMessage) Trace() string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("Command: %s — %s\n", m.cmdCode, m.description))
	for k, v := range m.Fields {
		buf.WriteString(fmt.Sprintf("\t[%s]=%x\n", k, v))
	}

	return buf.String()
}
