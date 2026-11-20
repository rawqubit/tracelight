package dissect

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

type DNSRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  string
}

type DNSLayer struct {
	ID         uint16
	IsResponse bool
	Opcode     uint8
	AA         bool
	TC         bool
	RD         bool
	RA         bool
	RCode      uint8
	Questions  []DNSQuestion
	Answers    []DNSRecord
}

func (d *DNSLayer) PrimaryName() string {
	if len(d.Questions) > 0 && d.Questions[0].Name != "" {
		return d.Questions[0].Name
	}
	if len(d.Answers) > 0 && d.Answers[0].Name != "" {
		return d.Answers[0].Name
	}
	return ""
}

func (d *DNSLayer) Summary() string {
	if !d.IsResponse {
		if len(d.Questions) > 0 {
			q := d.Questions[0]
			return fmt.Sprintf("DNS query #%d %s %s", d.ID, dnsTypeName(q.Type), q.Name)
		}
		return fmt.Sprintf("DNS query #%d", d.ID)
	}
	rcode := dnsRCodeName(d.RCode)
	if len(d.Answers) > 0 {
		var vals []string
		for i, a := range d.Answers {
			if i >= 3 {
				vals = append(vals, fmt.Sprintf("+%d more", len(d.Answers)-3))
				break
			}
			vals = append(vals, a.Data)
		}
		name := d.PrimaryName()
		return fmt.Sprintf("DNS resp #%d %s %s -> %s", d.ID, rcode, name, strings.Join(vals, ", "))
	}
	if len(d.Questions) > 0 {
		return fmt.Sprintf("DNS resp #%d %s %s %s (0 answers)", d.ID, rcode, dnsTypeName(d.Questions[0].Type), d.Questions[0].Name)
	}
	return fmt.Sprintf("DNS resp #%d %s", d.ID, rcode)
}

func DecodeDNS(data []byte) (*DNSLayer, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("dns: length %d < 12", len(data))
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	qdCount := int(binary.BigEndian.Uint16(data[4:6]))
	anCount := int(binary.BigEndian.Uint16(data[6:8]))

	layer := &DNSLayer{
		ID:         binary.BigEndian.Uint16(data[0:2]),
		IsResponse: (flags & 0x8000) != 0,
		Opcode:     uint8((flags >> 11) & 0x0f),
		AA:         (flags & 0x0400) != 0,
		TC:         (flags & 0x0200) != 0,
		RD:         (flags & 0x0100) != 0,
		RA:         (flags & 0x0080) != 0,
		RCode:      uint8(flags & 0x000f),
	}

	off := 12
	for i := 0; i < qdCount; i++ {
		if off >= len(data) {
			return nil, fmt.Errorf("dns: truncated question %d", i)
		}
		name, next, err := decodeDNSName(data, off)
		if err != nil {
			return nil, fmt.Errorf("dns: question %d name: %w", i, err)
		}
		if next+4 > len(data) {
			return nil, fmt.Errorf("dns: question %d truncated fields", i)
		}
		qType := binary.BigEndian.Uint16(data[next : next+2])
		qClass := binary.BigEndian.Uint16(data[next+2 : next+4])
		layer.Questions = append(layer.Questions, DNSQuestion{
			Name:  name,
			Type:  qType,
			Class: qClass,
		})
		off = next + 4
	}

	for i := 0; i < anCount; i++ {
		if off >= len(data) {
			return nil, fmt.Errorf("dns: truncated answer %d", i)
		}
		name, next, err := decodeDNSName(data, off)
		if err != nil {
			return nil, fmt.Errorf("dns: answer %d name: %w", i, err)
		}
		if next+10 > len(data) {
			return nil, fmt.Errorf("dns: answer %d truncated RR header", i)
		}
		rType := binary.BigEndian.Uint16(data[next : next+2])
		rClass := binary.BigEndian.Uint16(data[next+2 : next+4])
		ttl := binary.BigEndian.Uint32(data[next+4 : next+8])
		rdLen := int(binary.BigEndian.Uint16(data[next+8 : next+10]))
		rdataOff := next + 10
		if rdataOff+rdLen > len(data) {
			return nil, fmt.Errorf("dns: answer %d rdata length %d exceeds packet", i, rdLen)
		}
		rdata := decodeDNSRData(data, rdataOff, rdLen, rType)
		layer.Answers = append(layer.Answers, DNSRecord{
			Name:  name,
			Type:  rType,
			Class: rClass,
			TTL:   ttl,
			Data:  rdata,
		})
		off = rdataOff + rdLen
	}

	return layer, nil
}

func decodeDNSName(msg []byte, start int) (string, int, error) {
	if start < 0 || start >= len(msg) {
		return "", 0, fmt.Errorf("offset %d out of bounds (%d)", start, len(msg))
	}
	var labels []string
	off := start
	nextAfterFirstPtr := -1
	visited := make(map[int]bool)

	for steps := 0; steps < 128; steps++ {
		if off >= len(msg) {
			return "", 0, fmt.Errorf("truncated name at offset %d", off)
		}
		if visited[off] {
			return "", 0, fmt.Errorf("compression pointer loop at offset %d", off)
		}
		visited[off] = true

		b := msg[off]
		if b == 0 {
			if nextAfterFirstPtr == -1 {
				nextAfterFirstPtr = off + 1
			}
			if len(labels) == 0 {
				return ".", nextAfterFirstPtr, nil
			}
			return strings.Join(labels, "."), nextAfterFirstPtr, nil
		}

		switch b & 0xc0 {
		case 0xc0:
			if off+1 >= len(msg) {
				return "", 0, fmt.Errorf("truncated compression pointer at offset %d", off)
			}
			ptr := (int(b&0x3f) << 8) | int(msg[off+1])
			if ptr >= len(msg) {
				return "", 0, fmt.Errorf("compression pointer %d out of bounds (%d)", ptr, len(msg))
			}
			if nextAfterFirstPtr == -1 {
				nextAfterFirstPtr = off + 2
			}
			off = ptr
		case 0x00:
			labelLen := int(b)
			off++
			if off+labelLen > len(msg) {
				return "", 0, fmt.Errorf("label length %d exceeds message at offset %d", labelLen, off)
			}
			labels = append(labels, string(msg[off:off+labelLen]))
			off += labelLen
		default:
			return "", 0, fmt.Errorf("unsupported label tag 0x%02x at offset %d", b, off)
		}
	}
	return "", 0, fmt.Errorf("name exceeded maximum jump/label limit")
}

func decodeDNSRData(msg []byte, off, rdLen int, rType uint16) string {
	raw := msg[off : off+rdLen]
	switch rType {
	case 1: // A
		if len(raw) == 4 {
			var b [4]byte
			copy(b[:], raw)
			return netip.AddrFrom4(b).String()
		}
	case 28: // AAAA
		if len(raw) == 16 {
			var b [16]byte
			copy(b[:], raw)
			return netip.AddrFrom16(b).String()
		}
	case 2, 5, 12: // NS, CNAME, PTR
		if name, _, err := decodeDNSName(msg, off); err == nil {
			return name
		}
	case 15: // MX
		if len(raw) >= 3 {
			pref := binary.BigEndian.Uint16(raw[0:2])
			if name, _, err := decodeDNSName(msg, off+2); err == nil {
				return fmt.Sprintf("%d %s", pref, name)
			}
		}
	case 16: // TXT
		var parts []string
		for i := 0; i < len(raw); {
			l := int(raw[i])
			i++
			if i+l > len(raw) {
				break
			}
			parts = append(parts, string(raw[i:i+l]))
			i += l
		}
		if len(parts) > 0 {
			return strings.Join(parts, " ")
		}
	}
	return fmt.Sprintf("%s (%d B)", dnsTypeName(rType), rdLen)
}

func dnsTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 65:
		return "HTTPS"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

// DNSTypeName exports human-readable DNS RR type names for UI/CLI formatting.
func DNSTypeName(t uint16) string {
	return dnsTypeName(t)
}

func dnsRCodeName(code uint8) string {
	switch code {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", code)
	}
}
