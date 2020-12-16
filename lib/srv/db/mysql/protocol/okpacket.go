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

import (
	"bytes"
	"encoding/binary"
)

//
type OKPacket struct {
	PacketType   byte
	AffectedRows uint64
	LastInsertID uint64
	StatusFlags  uint16
	Warnings     uint16
}

func NewOKPacket() *OKPacket {
	return &OKPacket{
		PacketType: 0x00,
	}
}

//
func (p *OKPacket) Encode() []byte {
	b := bytes.Buffer{}

	b.WriteByte(p.PacketType)

	// Affected rows.
	b.WriteByte(0)

	// Last insert id.
	b.WriteByte(0)

	// Status flags
	b.WriteByte(0)

	// Number of warnings.
	b.WriteByte(0)

	// Status information
	b.Write([]byte(""))

	header := PacketHeader{
		Length:     uint32(b.Len()),
		SequenceId: 10,
	}

	newBuf := make([]byte, 0, header.Length+4)

	ln := make([]byte, 4)
	binary.LittleEndian.PutUint32(ln, header.Length)

	newBuf = append(newBuf, ln[:3]...)
	newBuf = append(newBuf, header.SequenceId)
	newBuf = append(newBuf, b.Bytes()...)

	return newBuf
}
