package dissect

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const (
	IPProtoICMP   uint8 = 1
	IPProtoTCP    uint8 = 6
	IPProtoUDP    uint8 = 17
	IPProtoICMPv6 uint8 = 58
)

type IPv4Layer struct {
	Version    uint8
	IHL        uint8
	DSCP       uint8
	ECN        uint8
	TotalLen   uint16
	ID         uint16
	Flags      uint8
	FragOffset uint16
	TTL        uint8
	Protocol   uint8
	Checksum   uint16
	SrcIP      netip.Addr
	DstIP      netip.Addr
	Options    []byte
	Payload    []byte
}

func (ip *IPv4Layer) Summary() string {
	return fmt.Sprintf("IPv4 %s -> %s proto=%d ttl=%d len=%d", ip.SrcIP, ip.DstIP, ip.Protocol, ip.TTL, ip.TotalLen)
}

func DecodeIPv4(data []byte) (*IPv4Layer, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("ipv4: length %d < 20", len(data))
	}
	ver := data[0] >> 4
	if ver != 4 {
		return nil, fmt.Errorf("ipv4: invalid version %d", ver)
	}
	ihl := data[0] & 0x0f
	hdrLen := int(ihl) * 4
	if hdrLen < 20 || hdrLen > len(data) {
		return nil, fmt.Errorf("ipv4: invalid header length %d for packet size %d", hdrLen, len(data))
	}

	totalLen := binary.BigEndian.Uint16(data[2:4])
	if int(totalLen) < hdrLen {
		return nil, fmt.Errorf("ipv4: total length %d < header length %d", totalLen, hdrLen)
	}
	end := int(totalLen)
	if end > len(data) {
		// Packet may have been snaplen-truncated; clamp safely to available bytes.
		end = len(data)
	}

	var srcBytes, dstBytes [4]byte
	copy(srcBytes[:], data[12:16])
	copy(dstBytes[:], data[16:20])

	flagsFrag := binary.BigEndian.Uint16(data[6:8])

	var opts []byte
	if hdrLen > 20 {
		opts = data[20:hdrLen]
	}

	return &IPv4Layer{
		Version:    ver,
		IHL:        ihl,
		DSCP:       data[1] >> 2,
		ECN:        data[1] & 0x03,
		TotalLen:   totalLen,
		ID:         binary.BigEndian.Uint16(data[4:6]),
		Flags:      uint8(flagsFrag >> 13),
		FragOffset: flagsFrag & 0x1fff,
		TTL:        data[8],
		Protocol:   data[9],
		Checksum:   binary.BigEndian.Uint16(data[10:12]),
		SrcIP:      netip.AddrFrom4(srcBytes),
		DstIP:      netip.AddrFrom4(dstBytes),
		Options:    opts,
		Payload:    data[hdrLen:end],
	}, nil
}

type IPv6Layer struct {
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32
	PayloadLen   uint16
	NextHeader   uint8
	HopLimit     uint8
	SrcIP        netip.Addr
	DstIP        netip.Addr
	ExtHeaders   []uint8
	UpperProto   uint8
	Payload      []byte
}

func (ip *IPv6Layer) Summary() string {
	return fmt.Sprintf("IPv6 %s -> %s next=%d hlim=%d len=%d", ip.SrcIP, ip.DstIP, ip.UpperProto, ip.HopLimit, ip.PayloadLen)
}

func DecodeIPv6(data []byte) (*IPv6Layer, error) {
	if len(data) < 40 {
		return nil, fmt.Errorf("ipv6: length %d < 40", len(data))
	}
	ver := data[0] >> 4
	if ver != 6 {
		return nil, fmt.Errorf("ipv6: invalid version %d", ver)
	}
	payloadLen := binary.BigEndian.Uint16(data[4:6])
	nextHdr := data[6]
	hopLimit := data[7]

	var srcBytes, dstBytes [16]byte
	copy(srcBytes[:], data[8:24])
	copy(dstBytes[:], data[24:40])

	end := 40 + int(payloadLen)
	if end > len(data) {
		end = len(data)
	}
	payload := data[40:end]

	var exts []uint8
	upper := nextHdr
	for i := 0; i < 8; i++ {
		switch upper {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			if len(payload) < 2 {
				return nil, fmt.Errorf("ipv6: truncated extension header %d", upper)
			}
			extLen := (int(payload[1]) + 1) * 8
			if extLen > len(payload) {
				return nil, fmt.Errorf("ipv6: extension header %d length %d exceeds payload %d", upper, extLen, len(payload))
			}
			exts = append(exts, upper)
			upper = payload[0]
			payload = payload[extLen:]
		case 44: // Fragment header (fixed 8 bytes)
			if len(payload) < 8 {
				return nil, fmt.Errorf("ipv6: truncated fragment header")
			}
			exts = append(exts, upper)
			upper = payload[0]
			payload = payload[8:]
		case 51: // Authentication Header: length in 32-bit words minus 2
			if len(payload) < 2 {
				return nil, fmt.Errorf("ipv6: truncated AH header")
			}
			extLen := (int(payload[1]) + 2) * 4
			if extLen < 8 || extLen > len(payload) {
				return nil, fmt.Errorf("ipv6: invalid AH header length %d", extLen)
			}
			exts = append(exts, upper)
			upper = payload[0]
			payload = payload[extLen:]
		default:
			i = 8 // stop loop
		}
	}

	return &IPv6Layer{
		Version:      ver,
		TrafficClass: ((data[0] & 0x0f) << 4) | (data[1] >> 4),
		FlowLabel:    (uint32(data[1]&0x0f) << 16) | (uint32(data[2]) << 8) | uint32(data[3]),
		PayloadLen:   payloadLen,
		NextHeader:   nextHdr,
		HopLimit:     hopLimit,
		SrcIP:        netip.AddrFrom16(srcBytes),
		DstIP:        netip.AddrFrom16(dstBytes),
		ExtHeaders:   exts,
		UpperProto:   upper,
		Payload:      payload,
	}, nil
}

type ICMPLayer struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	ID       uint16
	Seq      uint16
	IsV6     bool
	Payload  []byte
}

func (ic *ICMPLayer) Summary() string {
	proto := "ICMP"
	if ic.IsV6 {
		proto = "ICMPv6"
	}
	name := icmpTypeName(ic.Type, ic.IsV6)
	if name != "" {
		return fmt.Sprintf("%s %s (type=%d code=%d id=%d seq=%d)", proto, name, ic.Type, ic.Code, ic.ID, ic.Seq)
	}
	return fmt.Sprintf("%s type=%d code=%d", proto, ic.Type, ic.Code)
}

func DecodeICMP(data []byte, isV6 bool) (*ICMPLayer, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("icmp: length %d < 4", len(data))
	}
	layer := &ICMPLayer{
		Type:     data[0],
		Code:     data[1],
		Checksum: binary.BigEndian.Uint16(data[2:4]),
		IsV6:     isV6,
	}
	if len(data) >= 8 {
		layer.ID = binary.BigEndian.Uint16(data[4:6])
		layer.Seq = binary.BigEndian.Uint16(data[6:8])
		layer.Payload = data[8:]
	} else {
		layer.Payload = data[4:]
	}
	return layer, nil
}

func icmpTypeName(t uint8, isV6 bool) string {
	if isV6 {
		switch t {
		case 128:
			return "Echo Request"
		case 129:
			return "Echo Reply"
		case 135:
			return "Neighbor Solicitation"
		case 136:
			return "Neighbor Advertisement"
		default:
			return ""
		}
	}
	switch t {
	case 0:
		return "Echo Reply"
	case 3:
		return "Dest Unreachable"
	case 8:
		return "Echo Request"
	case 11:
		return "Time Exceeded"
	default:
		return ""
	}
}
