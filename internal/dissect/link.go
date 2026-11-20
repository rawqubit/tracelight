package dissect

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const (
	EtherTypeIPv4 uint16 = 0x0800
	EtherTypeARP  uint16 = 0x0806
	EtherTypeVLAN uint16 = 0x8100
	EtherTypeQinQ uint16 = 0x88a8
	EtherTypeIPv6 uint16 = 0x86dd
)

type VLANHeader struct {
	TPID      uint16
	PCP       uint8
	DEI       bool
	VID       uint16
	EtherType uint16
}

type EthernetLayer struct {
	DstMAC    net.HardwareAddr
	SrcMAC    net.HardwareAddr
	VLANs     []VLANHeader
	EtherType uint16
	Payload   []byte
}

func (e *EthernetLayer) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "eth %s -> %s", e.SrcMAC, e.DstMAC)
	for _, v := range e.VLANs {
		fmt.Fprintf(&b, " vlan=%d", v.VID)
	}
	fmt.Fprintf(&b, " type=0x%04x (%d B)", e.EtherType, len(e.Payload))
	return b.String()
}

// DecodeEthernet parses an Ethernet II frame including stacked 802.1Q / 802.1ad VLAN tags.
func DecodeEthernet(data []byte) (*EthernetLayer, error) {
	if len(data) < 14 {
		return nil, fmt.Errorf("ethernet: frame length %d < 14", len(data))
	}
	dst := make(net.HardwareAddr, 6)
	src := make(net.HardwareAddr, 6)
	copy(dst, data[0:6])
	copy(src, data[6:12])
	etherType := binary.BigEndian.Uint16(data[12:14])
	off := 14

	var vlans []VLANHeader
	for (etherType == EtherTypeVLAN || etherType == EtherTypeQinQ) && len(vlans) < 4 {
		if off+4 > len(data) {
			return nil, fmt.Errorf("ethernet: truncated VLAN tag at offset %d", off)
		}
		tci := binary.BigEndian.Uint16(data[off : off+2])
		nextType := binary.BigEndian.Uint16(data[off+2 : off+4])
		vlans = append(vlans, VLANHeader{
			TPID:      etherType,
			PCP:       uint8(tci >> 13),
			DEI:       (tci & 0x1000) != 0,
			VID:       tci & 0x0fff,
			EtherType: nextType,
		})
		etherType = nextType
		off += 4
	}

	return &EthernetLayer{
		DstMAC:    dst,
		SrcMAC:    src,
		VLANs:     vlans,
		EtherType: etherType,
		Payload:   data[off:],
	}, nil
}

func decodeNullLoopback(data []byte) uint16 {
	if len(data) < 4 {
		return 0
	}
	// BSD loopback stores AF_INET (2) or AF_INET6 (10 on Linux, 24/28/30 on BSD) in host byte order.
	le := binary.LittleEndian.Uint32(data[0:4])
	be := binary.BigEndian.Uint32(data[0:4])
	for _, af := range []uint32{le, be} {
		switch af {
		case 2:
			return EtherTypeIPv4
		case 10, 24, 28, 30:
			return EtherTypeIPv6
		}
	}
	return 0
}
