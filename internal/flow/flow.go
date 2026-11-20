package flow

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/rawqubit/tracelight/internal/capture"
	"github.com/rawqubit/tracelight/internal/dissect"
)

type Direction string

const (
	DirFwd Direction = "fwd"
	DirRev Direction = "rev"
)

func (d Direction) Arrow() string {
	if d == DirRev {
		return "<-"
	}
	return "->"
}

type Endpoint struct {
	IP   netip.Addr
	Port uint16
}

func (e Endpoint) String() string {
	if !e.IP.IsValid() {
		return "-"
	}
	if e.Port == 0 {
		return e.IP.String()
	}
	if e.IP.Is6() {
		return fmt.Sprintf("[%s]:%d", e.IP, e.Port)
	}
	return fmt.Sprintf("%s:%d", e.IP, e.Port)
}

func compareEndpoint(a, b Endpoint) int {
	if c := a.IP.Compare(b.IP); c != 0 {
		return c
	}
	if a.Port < b.Port {
		return -1
	}
	if a.Port > b.Port {
		return 1
	}
	return 0
}

// FlowKey uniquely identifies a bidirectional 5-tuple flow regardless of packet direction.
type FlowKey struct {
	Proto string
	A     Endpoint
	B     Endpoint
}

func NewFlowKey(proto string, srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) FlowKey {
	a := Endpoint{IP: srcIP, Port: srcPort}
	b := Endpoint{IP: dstIP, Port: dstPort}
	if compareEndpoint(a, b) > 0 {
		a, b = b, a
	}
	return FlowKey{
		Proto: strings.ToLower(proto),
		A:     a,
		B:     b,
	}
}

func (k FlowKey) String() string {
	return fmt.Sprintf("%s %s <-> %s", k.Proto, k.A, k.B)
}

type FlowPacket struct {
	PacketIndex  int
	Timestamp    time.Time
	RelCapture   time.Duration
	RelFlow      time.Duration
	Direction    Direction
	Length       int
	OrigLen      int
	Raw          []byte
	Decoded      *dissect.DecodedPacket
	IsRetransmit bool
	Summary      string
}

type Flow struct {
	ID              int
	Key             FlowKey
	SrcIP           netip.Addr
	SrcPort         uint16
	DstIP           netip.Addr
	DstPort         uint16
	Protocol        string // dns, http, tls, tcp, udp, icmp, or lower layer
	L4Proto         string
	Host            string
	TLSVersion      string
	ALPN            []string
	Info            string
	PacketCount     int
	ByteCount       int64
	FwdPackets      int
	RevPackets      int
	FwdBytes        int64
	RevBytes        int64
	Retransmissions int
	FirstSeen       time.Time
	LastSeen        time.Time
	Duration        time.Duration
	RTTEstimate     time.Duration
	HasRTT          bool
	Packets         []FlowPacket

	// Internal tracking for RTT & retransmission
	synTime      time.Time
	synAckTime   time.Time
	synDir       Direction
	hasSYN       bool
	hasSYNACK    bool
	fwdSeqInit   bool
	fwdMaxSeqEnd uint32
	revSeqInit   bool
	revMaxSeqEnd uint32
}

type Result struct {
	Flows       []*Flow
	AllPackets  []FlowPacket
	StartTime   time.Time
	EndTime     time.Time
	Duration    time.Duration
	TotalBytes  int64
	ProtoCounts map[string]int
}

// Assemble decodes all packets in a capture and groups them into bidirectional 5-tuple flows.
func Assemble(capData *capture.Capture) *Result {
	res := &Result{
		ProtoCounts: make(map[string]int),
	}
	if capData == nil || len(capData.Packets) == 0 {
		return res
	}

	var capStart time.Time
	for _, p := range capData.Packets {
		if !p.Timestamp.IsZero() {
			capStart = p.Timestamp
			break
		}
	}
	res.StartTime = capStart

	flowMap := make(map[FlowKey]*Flow)
	var flows []*Flow

	for _, pkt := range capData.Packets {
		dec := dissect.Decode(pkt.LinkType, pkt.Data)
		pktLen := len(pkt.Data)
		res.TotalBytes += int64(pktLen)
		if !pkt.Timestamp.IsZero() && (res.EndTime.IsZero() || pkt.Timestamp.After(res.EndTime)) {
			res.EndTime = pkt.Timestamp
		}

		l4 := dec.L4Proto
		if l4 == "" {
			l4 = dec.Protocol()
		}

		var key FlowKey
		if dec.HasIP {
			key = NewFlowKey(l4, dec.SrcIP, dec.SrcPort, dec.DstIP, dec.DstPort)
		} else {
			// Non-IP traffic (e.g. ARP) grouped under link-layer key
			key = FlowKey{Proto: dec.Protocol()}
		}

		fl, ok := flowMap[key]
		if !ok {
			fl = &Flow{
				ID:        len(flows) + 1,
				Key:       key,
				SrcIP:     dec.SrcIP,
				SrcPort:   dec.SrcPort,
				DstIP:     dec.DstIP,
				DstPort:   dec.DstPort,
				Protocol:  dec.Protocol(),
				L4Proto:   l4,
				FirstSeen: pkt.Timestamp,
				LastSeen:  pkt.Timestamp,
			}
			flowMap[key] = fl
			flows = append(flows, fl)
		}

		dir := DirFwd
		if dec.HasIP && (dec.SrcIP != fl.SrcIP || dec.SrcPort != fl.SrcPort) {
			dir = DirRev
		}

		var relCap, relFlow time.Duration
		if !pkt.Timestamp.IsZero() {
			if !capStart.IsZero() {
				relCap = pkt.Timestamp.Sub(capStart)
			}
			if !fl.FirstSeen.IsZero() {
				relFlow = pkt.Timestamp.Sub(fl.FirstSeen)
			}
			if fl.FirstSeen.IsZero() || pkt.Timestamp.Before(fl.FirstSeen) {
				fl.FirstSeen = pkt.Timestamp
			}
			if pkt.Timestamp.After(fl.LastSeen) {
				fl.LastSeen = pkt.Timestamp
			}
		}

		fl.PacketCount++
		fl.ByteCount += int64(pktLen)
		if dir == DirFwd {
			fl.FwdPackets++
			fl.FwdBytes += int64(pktLen)
		} else {
			fl.RevPackets++
			fl.RevBytes += int64(pktLen)
		}

		// Upgrade flow protocol classification when higher-layer app protocol is observed.
		if dec.AppProto != "" {
			fl.Protocol = chooseHigherProto(fl.Protocol, dec.AppProto)
		} else if fl.Protocol == "" {
			fl.Protocol = dec.Protocol()
		}

		if dec.Host != "" && fl.Host == "" {
			fl.Host = dec.Host
		}
		if dec.TLS != nil && dec.TLS.IsClientHello {
			fl.TLSVersion = dec.TLS.VersionName
			if len(dec.TLS.ALPN) > 0 {
				fl.ALPN = append([]string(nil), dec.TLS.ALPN...)
			}
			if dec.TLS.SNI != "" {
				fl.Host = dec.TLS.SNI
			}
		}
		if dec.HTTP != nil && fl.Info == "" {
			fl.Info = dec.HTTP.Summary()
		} else if dec.DNS != nil && fl.Info == "" {
			fl.Info = dec.DNS.Summary()
		} else if dec.TLS != nil && dec.TLS.IsClientHello && fl.Info == "" {
			fl.Info = dec.TLS.Summary()
		}

		isRetrans := false
		if dec.TCP != nil {
			updateTCPTiming(fl, dec.TCP, dir, pkt.Timestamp)
			isRetrans = detectTCPRetransmission(fl, dec.TCP, dir)
			if isRetrans {
				fl.Retransmissions++
			}
		}

		summary := dec.Summary
		if isRetrans {
			summary = "[TCP Retransmission] " + summary
		}

		fp := FlowPacket{
			PacketIndex:  pkt.Index,
			Timestamp:    pkt.Timestamp,
			RelCapture:   relCap,
			RelFlow:      relFlow,
			Direction:    dir,
			Length:       pktLen,
			OrigLen:      int(pkt.OrigLen),
			Raw:          pkt.Data,
			Decoded:      dec,
			IsRetransmit: isRetrans,
			Summary:      summary,
		}
		fl.Packets = append(fl.Packets, fp)
		res.AllPackets = append(res.AllPackets, fp)
	}

	for _, fl := range flows {
		if !fl.FirstSeen.IsZero() && !fl.LastSeen.IsZero() && !fl.LastSeen.Before(fl.FirstSeen) {
			fl.Duration = fl.LastSeen.Sub(fl.FirstSeen)
		}
		if fl.Info == "" {
			if fl.Host != "" {
				fl.Info = fl.Host
			} else if len(fl.Packets) > 0 {
				fl.Info = fl.Packets[0].Summary
			}
		}
		res.ProtoCounts[fl.Protocol]++
	}

	if !res.StartTime.IsZero() && !res.EndTime.IsZero() && !res.EndTime.Before(res.StartTime) {
		res.Duration = res.EndTime.Sub(res.StartTime)
	}
	res.Flows = flows
	return res
}

func chooseHigherProto(current, candidate string) string {
	rank := map[string]int{
		"tls":  5,
		"http": 4,
		"dns":  3,
		"tcp":  2,
		"udp":  2,
		"icmp": 2,
	}
	if rank[candidate] >= rank[current] {
		return candidate
	}
	return current
}

func updateTCPTiming(fl *Flow, tcp *dissect.TCPLayer, dir Direction, ts time.Time) {
	if ts.IsZero() {
		return
	}
	isSYN := tcp.Flags.Has(dissect.TCPFlagSYN) && !tcp.Flags.Has(dissect.TCPFlagACK)
	isSYNACK := tcp.Flags.Has(dissect.TCPFlagSYN) && tcp.Flags.Has(dissect.TCPFlagACK)
	isACK := tcp.Flags.Has(dissect.TCPFlagACK) && !tcp.Flags.Has(dissect.TCPFlagSYN)

	if isSYN && !fl.hasSYN {
		fl.hasSYN = true
		fl.synTime = ts
		fl.synDir = dir
		return
	}
	if isSYNACK && !fl.hasSYNACK {
		fl.hasSYNACK = true
		fl.synAckTime = ts
		if fl.hasSYN && dir != fl.synDir && !ts.Before(fl.synTime) {
			fl.RTTEstimate = ts.Sub(fl.synTime)
			fl.HasRTT = true
		}
		return
	}
	if isACK && !fl.HasRTT && fl.hasSYNACK && dir == fl.synDir && !ts.Before(fl.synAckTime) {
		fl.RTTEstimate = ts.Sub(fl.synAckTime)
		fl.HasRTT = true
	}
}

func detectTCPRetransmission(fl *Flow, tcp *dissect.TCPLayer, dir Direction) bool {
	if tcp.Flags.Has(dissect.TCPFlagRST) {
		return false
	}
	segLen := uint32(len(tcp.Payload))
	if tcp.Flags.Has(dissect.TCPFlagSYN) {
		segLen++
	}
	if tcp.Flags.Has(dissect.TCPFlagFIN) {
		segLen++
	}
	// Pure ACKs without payload or SYN/FIN do not advance sequence space.
	if segLen == 0 {
		return false
	}
	seqEnd := tcp.Seq + segLen

	if dir == DirFwd {
		if !fl.fwdSeqInit {
			fl.fwdSeqInit = true
			fl.fwdMaxSeqEnd = seqEnd
			return false
		}
		if seqBefore(tcp.Seq, fl.fwdMaxSeqEnd) {
			if seqAfter(seqEnd, fl.fwdMaxSeqEnd) {
				fl.fwdMaxSeqEnd = seqEnd
			}
			return true
		}
		if seqAfter(seqEnd, fl.fwdMaxSeqEnd) {
			fl.fwdMaxSeqEnd = seqEnd
		}
		return false
	}

	if !fl.revSeqInit {
		fl.revSeqInit = true
		fl.revMaxSeqEnd = seqEnd
		return false
	}
	if seqBefore(tcp.Seq, fl.revMaxSeqEnd) {
		if seqAfter(seqEnd, fl.revMaxSeqEnd) {
			fl.revMaxSeqEnd = seqEnd
		}
		return true
	}
	if seqAfter(seqEnd, fl.revMaxSeqEnd) {
		fl.revMaxSeqEnd = seqEnd
	}
	return false
}

// Modular 32-bit sequence comparisons (RFC 1982).
func seqBefore(a, b uint32) bool {
	return int32(a-b) < 0
}

func seqAfter(a, b uint32) bool {
	return int32(a-b) > 0
}

// SortFlows sorts a slice of flows in place by the given field ("start", "bytes", "packets", "duration", "rtt", "proto", "id").
func SortFlows(flows []*Flow, field string, desc bool) {
	sort.SliceStable(flows, func(i, j int) bool {
		a, b := flows[i], flows[j]
		var less bool
		switch strings.ToLower(field) {
		case "bytes":
			less = a.ByteCount < b.ByteCount
		case "packets":
			less = a.PacketCount < b.PacketCount
		case "duration":
			less = a.Duration < b.Duration
		case "rtt":
			if a.HasRTT != b.HasRTT {
				// Put flows with RTT first when descending or ascending? Put valid RTT before missing RTT.
				return a.HasRTT
			}
			less = a.RTTEstimate < b.RTTEstimate
		case "proto", "protocol":
			less = a.Protocol < b.Protocol
		case "id":
			less = a.ID < b.ID
		default: // "start"
			less = a.FirstSeen.Before(b.FirstSeen)
		}
		if desc {
			return !less
		}
		return less
	})
}
