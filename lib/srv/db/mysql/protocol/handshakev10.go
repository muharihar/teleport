/*
Copyright 2020 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package protocol

import "encoding/binary"

//
type PacketHeader struct {
	Length     uint32
	SequenceId uint8
}

//
type HandshakeV10 struct {
	ProtocolVersion    byte
	ServerVersion      string
	ConnectionID       uint32
	ServerCapabilities uint32
	AuthPlugin         string
	Salt               []byte
}

//
func NewHandshakeV10() *HandshakeV10 {
	return &HandshakeV10{
		ProtocolVersion:    ProtocolVersion,
		ServerVersion:      ServerVersion,
		ConnectionID:       0,
		ServerCapabilities: AllCapabilities,
	}
}

//
func (h *HandshakeV10) Encode() []byte {
	buf := make([]byte, 0)

	// Protocol version.
	buf = append(buf, h.ProtocolVersion)

	// Server version, null-terminated.
	buf = append(buf, h.ServerVersion...)
	buf = append(buf, byte(0x00))

	// Connection id.
	connectionID := make([]byte, 4)
	binary.LittleEndian.PutUint32(connectionID, h.ConnectionID)
	buf = append(buf, connectionID...)

	salt := make([]byte, 20)

	// First 8 bytes of auth plugin data.
	//auth1 := r.AuthPluginData[0:8]
	//auth1 := make([]byte, 8)
	auth1 := salt[0:8]
	buf = append(buf, auth1...)

	// Filler byte.
	buf = append(buf, 0x00)

	cap := make([]byte, 4)
	binary.LittleEndian.PutUint32(cap, uint32(h.ServerCapabilities))

	cap1 := cap[0:2]
	cap2 := cap[2:]

	buf = append(buf, cap1...)
	buf = append(buf, CharacterSetUTF8)

	// Status flags.
	statusFlag := make([]byte, 2)
	var statusFlags uint16
	binary.LittleEndian.PutUint16(statusFlag, statusFlags)
	buf = append(buf, statusFlag...)

	// Upper 2 bytes of capabilities.
	buf = append(buf, cap2...)

	// Length of auth plugin data, always 21.
	authPluginLen := []byte{21}
	buf = append(buf, authPluginLen...)

	// Reserved 10 bytes: all 0
	reserved := make([]byte, 10)
	buf = append(buf, reserved...)

	// Remaining bytes of auth plugin data.
	auth2 := salt[8:]
	buf = append(buf, auth2...)

	// Auth plugin name.
	buf = append(buf, MysqlNativePassword...)
	buf = append(buf, 0x00)

	header := PacketHeader{
		Length:     uint32(len(buf)),
		SequenceId: 0,
	}

	newBuf := make([]byte, 0, header.Length+4)

	ln := make([]byte, 4)
	binary.LittleEndian.PutUint32(ln, header.Length)

	newBuf = append(newBuf, ln[:3]...)
	newBuf = append(newBuf, header.SequenceId)
	newBuf = append(newBuf, buf...)

	return newBuf
}
