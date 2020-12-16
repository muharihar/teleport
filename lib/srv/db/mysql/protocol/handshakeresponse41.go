package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/gravitational/trace"
)

// ReadPacket ...
func ReadPacket(conn net.Conn) ([]byte, error) {

	// Read packet header
	header := []byte{0, 0, 0, 0}
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	// Calculate packet body length
	bodyLen := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)

	// Read packet body
	body := make([]byte, bodyLen)
	n, err := io.ReadFull(conn, body)
	if err != nil {
		return nil, err
	}

	return append(header, body[0:n]...), nil
}

type HandshakeResponse41 struct {
	Header          []byte
	CapabilityFlags uint32
	MaxPacketSize   uint32
	ClientCharset   uint8
	Username        string
	AuthLength      int64
	AuthPluginName  string
	AuthResponse    []byte
	Database        string
	PacketTail      []byte
}

// UnpackHandshakeResponse41 decodes handshake response packet send by client.
// TODO: Add packet struct comment
// TODO: Add packet length check
func UnpackHandshakeResponse41(packet []byte) (*HandshakeResponse41, error) {
	r := bytes.NewReader(packet)

	// Skip packet header (but save in struct)
	header, err := GetPacketHeader(r)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Read CapabilityFlags
	clientCapabilitiesBuf := make([]byte, 4)
	if _, err := r.Read(clientCapabilitiesBuf); err != nil {
		return nil, trace.Wrap(err)
	}
	capabilityFlags := binary.LittleEndian.Uint32(clientCapabilitiesBuf)

	// Check that the server is using protocol 4.1
	if capabilityFlags&CapabilityClientProtocol41 == 0 {
		return nil, errors.New("Client Protocol mismatch")
	}

	// client requesting SSL, we don't support it
	// clientRequestedSSL := capabilityFlags&CapabilityClientSSL > 0
	// if clientRequestedSSL {
	// 	return nil, errors.New("SSL Protocol mismatch")
	// }

	// Read MaxPacketSize
	maxPacketSizeBuf := make([]byte, 4)
	if _, err := r.Read(maxPacketSizeBuf); err != nil {
		return nil, trace.Wrap(err)
	}
	maxPacketSize := binary.LittleEndian.Uint32(maxPacketSizeBuf)

	// Read Charset
	charset, err := r.ReadByte()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Skip 23 byte buffer
	if _, err := r.Seek(23, io.SeekCurrent); err != nil {
		return nil, trace.Wrap(err)
	}

	// Read Username
	username := ReadNullTerminatedString(r)

	// Read Auth
	var auth []byte
	var authLength int64
	if capabilityFlags&CapabilityClientSecureConnection > 0 {
		authLengthByte, err := r.ReadByte()
		if err != nil {
			return nil, trace.Wrap(err)
		}
		authLength = int64(authLengthByte)

		auth = make([]byte, authLength)
		if _, err := r.Read(auth); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		auth = ReadNullTerminatedBytes(r)
	}

	// Read Database
	var database string
	if capabilityFlags&CapabilityClientConnectWithDB > 0 {
		database = ReadNullTerminatedString(r)
	}

	// check whether the auth method was specified
	var authPluginName string
	if capabilityFlags&CapabilityClientPluginAuth > 0 {
		authPluginName = ReadNullTerminatedString(r)
	}

	// get the rest of the packet
	var packetTail []byte
	remainingByteLen := r.Len()
	if remainingByteLen > 0 {
		packetTail = make([]byte, remainingByteLen)
		if _, err := r.Read(packetTail); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return &HandshakeResponse41{
		Header:          header,
		CapabilityFlags: capabilityFlags,
		MaxPacketSize:   maxPacketSize,
		ClientCharset:   charset,
		Username:        username,
		AuthLength:      authLength,
		AuthPluginName:  authPluginName,
		AuthResponse:    auth,
		Database:        database,
		PacketTail:      packetTail,
	}, nil
}

// See https://mariadb.com/kb/en/mariadb/protocol-data-types/#null-terminated-strings
func ReadNullTerminatedString(r *bytes.Reader) string {
	var str []byte
	for {
		//TODO: Check for error
		b, _ := r.ReadByte()

		if b == 0x00 {
			return string(str)
		}

		str = append(str, b)
	}
}

// ReadNullTerminatedBytes reads bytes from reader until 0x00 byte
func ReadNullTerminatedBytes(r *bytes.Reader) (str []byte) {
	for {
		//TODO: Check for error
		b, _ := r.ReadByte()

		if b == 0x00 {
			return
		}

		str = append(str, b)
	}
}

// GetPacketHeader rewinds reader to packet payload
func GetPacketHeader(r *bytes.Reader) (s []byte, e error) {
	s = make([]byte, 4)

	if _, e = r.Read(s); e != nil {
		return nil, e
	}

	return
}
