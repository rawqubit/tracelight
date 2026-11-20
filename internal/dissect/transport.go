package dissect

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	TCPFlagFIN uint8 = 1 << 0
	TCPFlagSYN uint8 = 1 << 1
	TCPFlagRST uint8 = 1 << 2
	TCPFlagPSH uint8 = 1 << 3
	TCPFlagACK uint8 = 1 << 4
	TCPFlagURG uint8 = 1 << 5
	TCPFlagECE uint8 = 1 << 6
	TCPFlagCWR uint8 = 1 << 7
)

type TCPFlags uint8

func (f TCPFlags) Has(flag uint8) bool {
	return (uint8(f) & flag) != 0
}

func (f TCPFlags) String() string {
	var names []string
	if f.Has(TCPFlagSYN) {
		names = append(names, "SYN")
	}
	if f.Has(TCPFlagACK) {
		names = append(names, "ACK")
	}
	if f.Has(TCPFlagFIN) {
		names = append(names, "FIN")
	}
	if f.Has(TCPFlagRST) {
		names = append(names, "RST")
	}
	if f.Has(TCPFlagPSH) {
		names = append(names, "PSH")
	}
	if f.Has(TCPFlagURG) {
		names = append(names, "URG")
	}
	if f.Has(TCPFlagECE) {
		names = append(names, "ECE")
	}
	if f.Has(TCPFlagCWR) {
		names = append(names, "CWR")
	}
	if len(names) == 0 {
		return "NONE"
	}
	return strings.Join(names, ",")
}

type TCPLayer struct {
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	DataOffset uint8
	Flags      TCPFlags
	Window     uint16
	Checksum   uint16
	Urgent     uint16
	Options    []byte
	Payload    []byte
}

func (t *TCPLayer) Summary() string {
	return fmt.Sprintf("TCP [%s] seq=%d ack=%d win=%d len=%d", t.Flags, t.Seq, t.Ack, t.Window, len(t.Payload))
}

func DecodeTCP(data []byte) (*TCPLayer, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("tcp: length %d < 20", len(data))
	}
	doff := data[12] >> 4
	hdrLen := int(doff) * 4
	if hdrLen < 20 || hdrLen > len(data) {
		return nil, fmt.Errorf("tcp: invalid data offset %d (%d B) for segment length %d", doff, hdrLen, len(data))
	}
	var opts []byte
	if hdrLen > 20 {
		opts = data[20:hdrLen]
	}
	return &TCPLayer{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		Seq:        binary.BigEndian.Uint32(data[4:8]),
		Ack:        binary.BigEndian.Uint32(data[8:12]),
		DataOffset: doff,
		Flags:      TCPFlags(data[13]),
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		Urgent:     binary.BigEndian.Uint16(data[18:20]),
		Options:    opts,
		Payload:    data[hdrLen:],
	}, nil
}

type UDPLayer struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
	Payload  []byte
}

func (u *UDPLayer) Summary() string {
	return fmt.Sprintf("UDP %d -> %d len=%d payload=%d B", u.SrcPort, u.DstPort, u.Length, len(u.Payload))
}

func DecodeUDP(data []byte) (*UDPLayer, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("udp: length %d < 8", len(data))
	}
	udpLen := binary.BigEndian.Uint16(data[4:6])
	if int(udpLen) < 8 {
		return nil, fmt.Errorf("udp: invalid length %d < 8", udpLen)
	}
	end := int(udpLen)
	if end > len(data) {
		end = len(data)
	}
	return &UDPLayer{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   udpLen,
		Checksum: binary.BigEndian.Uint16(data[6:8]),
		Payload:  data[8:end],
	}, nil
}
