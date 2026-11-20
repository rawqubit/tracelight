package dissect

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/rawqubit/tracelight/internal/capture"
)

type DecodedPacket struct {
	Ethernet *EthernetLayer
	IPv4     *IPv4Layer
	IPv6     *IPv6Layer
	ICMP     *ICMPLayer
	TCP      *TCPLayer
	UDP      *UDPLayer
	DNS      *DNSLayer
	HTTP     *HTTPLayer
	TLS      *TLSLayer

	// Normalized metadata across layers
	SrcIP       netip.Addr
	DstIP       netip.Addr
	HasIP       bool
	SrcPort     uint16
	DstPort     uint16
	HasPorts    bool
	L4Proto     string // "tcp", "udp", "icmp", or ""
	AppProto    string // "dns", "http", "tls", or ""
	Host        string // TLS SNI, HTTP Host, or DNS primary query/answer name
	AppPayload  []byte
	LayerErrors []string
	Summary     string
}

// Protocol returns the highest-level classified protocol for this packet.
func (d *DecodedPacket) Protocol() string {
	if d.AppProto != "" {
		return d.AppProto
	}
	if d.L4Proto != "" {
		return d.L4Proto
	}
	if d.IPv6 != nil {
		return "ipv6"
	}
	if d.IPv4 != nil {
		return "ipv4"
	}
	if d.Ethernet != nil {
		return "eth"
	}
	return "unknown"
}

// Decode dissects a raw captured packet starting from its link-layer type.
// Partial decodes succeed as far as valid layers reach; lower-layer errors are recorded in LayerErrors.
func Decode(linkType capture.LinkType, data []byte) *DecodedPacket {
	out := &DecodedPacket{}
	var networkProto uint16
	var l3Data []byte

	switch linkType {
	case capture.LinkTypeEthernet, 0:
		// Note: LinkType 0 is Null/Loopback in pcap, unless explicitly 0 when default; handle LinkTypeNull below if explicit.
		if linkType == capture.LinkTypeNull && len(data) >= 4 {
			if fam := decodeNullLoopback(data); fam != 0 {
				networkProto = fam
				l3Data = data[4:]
				break
			}
		}
		eth, err := DecodeEthernet(data)
		if err != nil {
			out.LayerErrors = append(out.LayerErrors, err.Error())
			out.Summary = fmt.Sprintf("malformed frame (%d B): %v", len(data), err)
			return out
		}
		out.Ethernet = eth
		networkProto = eth.EtherType
		l3Data = eth.Payload

	case capture.LinkTypeRawIP:
		if len(data) == 0 {
			out.Summary = "empty raw IP packet"
			return out
		}
		switch data[0] >> 4 {
		case 4:
			networkProto = EtherTypeIPv4
		case 6:
			networkProto = EtherTypeIPv6
		default:
			out.LayerErrors = append(out.LayerErrors, fmt.Sprintf("raw IP unknown version %d", data[0]>>4))
			out.Summary = fmt.Sprintf("raw IP unknown version %d (%d B)", data[0]>>4, len(data))
			return out
		}
		l3Data = data

	case capture.LinkTypeIPv4:
		networkProto = EtherTypeIPv4
		l3Data = data

	case capture.LinkTypeIPv6:
		networkProto = EtherTypeIPv6
		l3Data = data

	case capture.LinkTypeLinuxSLL:
		if len(data) < 16 {
			out.LayerErrors = append(out.LayerErrors, "truncated Linux SLL header")
			out.Summary = fmt.Sprintf("truncated Linux SLL (%d B)", len(data))
			return out
		}
		networkProto = uint16(data[14])<<8 | uint16(data[15])
		l3Data = data[16:]

	default:
		out.Summary = fmt.Sprintf("%s frame (%d B)", linkType, len(data))
		return out
	}

	var upperProto uint8
	var l4Data []byte

	switch networkProto {
	case EtherTypeIPv4:
		ip4, err := DecodeIPv4(l3Data)
		if err != nil {
			out.LayerErrors = append(out.LayerErrors, err.Error())
			out.Summary = out.buildSummary(data)
			return out
		}
		out.IPv4 = ip4
		out.SrcIP = ip4.SrcIP
		out.DstIP = ip4.DstIP
		out.HasIP = true
		upperProto = ip4.Protocol
		l4Data = ip4.Payload

	case EtherTypeIPv6:
		ip6, err := DecodeIPv6(l3Data)
		if err != nil {
			out.LayerErrors = append(out.LayerErrors, err.Error())
			out.Summary = out.buildSummary(data)
			return out
		}
		out.IPv6 = ip6
		out.SrcIP = ip6.SrcIP
		out.DstIP = ip6.DstIP
		out.HasIP = true
		upperProto = ip6.UpperProto
		l4Data = ip6.Payload

	case EtherTypeARP:
		out.Summary = fmt.Sprintf("ARP (%d B)", len(l3Data))
		if out.Ethernet != nil && len(out.Ethernet.VLANs) > 0 {
			out.Summary = fmt.Sprintf("ARP vlan=%d (%d B)", out.Ethernet.VLANs[0].VID, len(l3Data))
		}
		return out

	default:
		out.Summary = out.buildSummary(data)
		return out
	}

	switch upperProto {
	case IPProtoTCP:
		out.L4Proto = "tcp"
		tcp, err := DecodeTCP(l4Data)
		if err != nil {
			out.LayerErrors = append(out.LayerErrors, err.Error())
			out.Summary = out.buildSummary(data)
			return out
		}
		out.TCP = tcp
		out.SrcPort = tcp.SrcPort
		out.DstPort = tcp.DstPort
		out.HasPorts = true
		out.AppPayload = tcp.Payload
		out.dissectTCPApp(tcp.Payload)

	case IPProtoUDP:
		out.L4Proto = "udp"
		udp, err := DecodeUDP(l4Data)
		if err != nil {
			out.LayerErrors = append(out.LayerErrors, err.Error())
			out.Summary = out.buildSummary(data)
			return out
		}
		out.UDP = udp
		out.SrcPort = udp.SrcPort
		out.DstPort = udp.DstPort
		out.HasPorts = true
		out.AppPayload = udp.Payload
		out.dissectUDPApp(udp.Payload)

	case IPProtoICMP, IPProtoICMPv6:
		out.L4Proto = "icmp"
		icmp, err := DecodeICMP(l4Data, upperProto == IPProtoICMPv6)
		if err != nil {
			out.LayerErrors = append(out.LayerErrors, err.Error())
		} else {
			out.ICMP = icmp
		}

	default:
		out.L4Proto = fmt.Sprintf("ipproto(%d)", upperProto)
	}

	out.Summary = out.buildSummary(data)
	return out
}

func (d *DecodedPacket) dissectTCPApp(payload []byte) {
	if len(payload) == 0 {
		return
	}
	// TLS ClientHello (or ServerHello)
	if tlsLayer, err := DecodeTLSClientHello(payload); err == nil {
		d.TLS = tlsLayer
		d.AppProto = "tls"
		if tlsLayer.SNI != "" {
			d.Host = tlsLayer.SNI
		}
		return
	}
	if tlsLayer, err := DecodeTLSRecord(payload); err == nil {
		d.TLS = tlsLayer
		d.AppProto = "tls"
		return
	}
	// HTTP/1.1
	if httpLayer, err := DecodeHTTP(payload); err == nil {
		d.HTTP = httpLayer
		d.AppProto = "http"
		if httpLayer.Host != "" {
			d.Host = httpLayer.Host
		}
		return
	}
	// DNS over TCP (2-byte length prefix)
	if (d.SrcPort == 53 || d.DstPort == 53) && len(payload) >= 14 {
		msgLen := int(payload[0])<<8 | int(payload[1])
		if msgLen >= 12 && msgLen <= len(payload)-2 {
			if dnsLayer, err := DecodeDNS(payload[2 : 2+msgLen]); err == nil {
				d.DNS = dnsLayer
				d.AppProto = "dns"
				if q := dnsLayer.PrimaryName(); q != "" {
					d.Host = q
				}
				return
			}
		}
	}
}

func (d *DecodedPacket) dissectUDPApp(payload []byte) {
	if len(payload) == 0 {
		return
	}
	if d.SrcPort == 53 || d.DstPort == 53 || d.SrcPort == 5353 || d.DstPort == 5353 {
		if dnsLayer, err := DecodeDNS(payload); err == nil {
			d.DNS = dnsLayer
			d.AppProto = "dns"
			if q := dnsLayer.PrimaryName(); q != "" {
				d.Host = q
			}
			return
		}
	}
}

func (d *DecodedPacket) buildSummary(raw []byte) string {
	var parts []string

	if d.DNS != nil {
		parts = append(parts, d.DNS.Summary())
	} else if d.HTTP != nil {
		parts = append(parts, d.HTTP.Summary())
	} else if d.TLS != nil {
		parts = append(parts, d.TLS.Summary())
	} else if d.ICMP != nil {
		parts = append(parts, d.ICMP.Summary())
	} else if d.TCP != nil {
		parts = append(parts, d.TCP.Summary())
	} else if d.UDP != nil {
		parts = append(parts, d.UDP.Summary())
	} else if d.IPv4 != nil {
		parts = append(parts, d.IPv4.Summary())
	} else if d.IPv6 != nil {
		parts = append(parts, d.IPv6.Summary())
	} else if d.Ethernet != nil {
		parts = append(parts, d.Ethernet.Summary())
	} else {
		parts = append(parts, fmt.Sprintf("raw %d B", len(raw)))
	}

	if d.HasIP && d.HasPorts {
		prefix := fmt.Sprintf("%s -> %s", formatEndpoint(d.SrcIP, d.SrcPort), formatEndpoint(d.DstIP, d.DstPort))
		if d.DNS == nil && d.HTTP == nil && d.TLS == nil {
			return prefix + " " + strings.Join(parts, " ")
		}
		return prefix + " | " + strings.Join(parts, " ")
	}
	if d.HasIP {
		return fmt.Sprintf("%s -> %s | %s", d.SrcIP, d.DstIP, strings.Join(parts, " "))
	}
	return strings.Join(parts, " ")
}

func formatEndpoint(ip netip.Addr, port uint16) string {
	if ip.Is6() {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}
