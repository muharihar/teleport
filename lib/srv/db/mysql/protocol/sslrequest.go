package protocol

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/gravitational/trace"
)

type SSLRequest struct {
	Header          []byte
	CapabilityFlags uint32
	MaxPacketSize   uint32
	ClientCharset   uint8
}

//
func UnpackSSLRequest(packet []byte) (*SSLRequest, error) {
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
		return nil, trace.BadParameter("client protocol mismatch")
	}

	// client requesting SSL, we don't support it
	clientRequestedSSL := capabilityFlags&CapabilityClientSSL > 0
	if !clientRequestedSSL {
		return nil, trace.BadParameter("only TLS connections are supported")
	}

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

	return &SSLRequest{
		Header:          header,
		CapabilityFlags: capabilityFlags,
		MaxPacketSize:   maxPacketSize,
		ClientCharset:   charset,
	}, nil
}
