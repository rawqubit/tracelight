package flow

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/rawqubit/tracelight/internal/capture"
	"github.com/rawqubit/tracelight/internal/dissect"
)

func TestFlowKeyBidirectional(t *testing.T) {
	ipA := netip.MustParseAddr("10.0.0.1")
	ipB := netip.MustParseAddr("93.184.216.34")
	k1 := NewFlowKey("tcp", ipA, 54000, ipB, 443)
	k2 := NewFlowKey("TCP", ipB, 443, ipA, 54000)
	if k1 != k2 {
		t.Fatalf("bidirectional flow keys differ: %+v vs %+v", k1, k2)
	}

	kDiffPort := NewFlowKey("tcp", ipA, 54001, ipB, 443)
	if k1 == kDiffPort {
		t.Fatalf("different ports should produce distinct flow keys")
	}
	kDiffProto := NewFlowKey("udp", ipA, 54000, ipB, 443)
	if k1 == kDiffProto {
		t.Fatalf("different protocols should produce distinct flow keys")
	}
}

func makeTestTCPFrame(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)

	ip := make([]byte, 20+len(tcp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = dissect.IPProtoTCP
	s4 := srcIP.As4()
	d4 := dstIP.As4()
	copy(ip[12:16], s4[:])
	copy(ip[16:20], d4[:])
	copy(ip[20:], tcp)
	return ip
}

func makeTestICMPFrame(srcIP, dstIP netip.Addr, icmpType uint8) []byte {
	icmp := []byte{icmpType, 0, 0, 0, 0, 1, 0, 1}
	ip := make([]byte, 20+len(icmp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = dissect.IPProtoICMP
	s4 := srcIP.As4()
	d4 := dstIP.As4()
	copy(ip[12:16], s4[:])
	copy(ip[16:20], d4[:])
	copy(ip[20:], icmp)
	return ip
}

func TestAssembleRTTClassificationAndRetransmission(t *testing.T) {
	base := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	cIP := netip.MustParseAddr("10.0.1.10")
	sIP := netip.MustParseAddr("10.0.2.20")

	req := []byte("GET / HTTP/1.1\r\nHost: svc.local\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

	capData := &capture.Capture{
		Format:   capture.FormatPCAP,
		LinkType: capture.LinkTypeRawIP,
		Packets: []capture.Packet{
			{Index: 1, Timestamp: base, LinkType: capture.LinkTypeRawIP, Data: makeTestTCPFrame(cIP, sIP, 50000, 80, 100, 0, dissect.TCPFlagSYN, nil)},
			{Index: 2, Timestamp: base.Add(15 * time.Millisecond), LinkType: capture.LinkTypeRawIP, Data: makeTestTCPFrame(sIP, cIP, 80, 50000, 500, 101, dissect.TCPFlagSYN|dissect.TCPFlagACK, nil)},
			{Index: 3, Timestamp: base.Add(16 * time.Millisecond), LinkType: capture.LinkTypeRawIP, Data: makeTestTCPFrame(cIP, sIP, 50000, 80, 101, 501, dissect.TCPFlagACK, nil)},
			{Index: 4, Timestamp: base.Add(17 * time.Millisecond), LinkType: capture.LinkTypeRawIP, Data: makeTestTCPFrame(cIP, sIP, 50000, 80, 101, 501, dissect.TCPFlagPSH|dissect.TCPFlagACK, req)},
			// Retransmission of seq 101
			{Index: 5, Timestamp: base.Add(40 * time.Millisecond), LinkType: capture.LinkTypeRawIP, Data: makeTestTCPFrame(cIP, sIP, 50000, 80, 101, 501, dissect.TCPFlagPSH|dissect.TCPFlagACK, req)},
			{Index: 6, Timestamp: base.Add(42 * time.Millisecond), LinkType: capture.LinkTypeRawIP, Data: makeTestTCPFrame(sIP, cIP, 80, 50000, 501, uint32(101+len(req)), dissect.TCPFlagPSH|dissect.TCPFlagACK, resp)},
			// Separate ICMP flow
			{Index: 7, Timestamp: base.Add(50 * time.Millisecond), LinkType: capture.LinkTypeRawIP, Data: makeTestICMPFrame(cIP, sIP, 8)},
			{Index: 8, Timestamp: base.Add(53 * time.Millisecond), LinkType: capture.LinkTypeRawIP, Data: makeTestICMPFrame(sIP, cIP, 0)},
		},
	}

	res := Assemble(capData)
	if len(res.Flows) != 2 {
		t.Fatalf("expected 2 flows, got %d", len(res.Flows))
	}

	httpFl := res.Flows[0]
	if httpFl.Protocol != "http" || httpFl.Host != "svc.local" {
		t.Fatalf("expected http flow with host svc.local, got proto=%q host=%q", httpFl.Protocol, httpFl.Host)
	}
	if httpFl.PacketCount != 6 || httpFl.FwdPackets != 4 || httpFl.RevPackets != 2 {
		t.Fatalf("unexpected directional counts: total=%d fwd=%d rev=%d", httpFl.PacketCount, httpFl.FwdPackets, httpFl.RevPackets)
	}
	if !httpFl.HasRTT || httpFl.RTTEstimate != 15*time.Millisecond {
		t.Fatalf("expected RTT 15ms, got has=%v rtt=%v", httpFl.HasRTT, httpFl.RTTEstimate)
	}
	if httpFl.Retransmissions != 1 || !httpFl.Packets[4].IsRetransmit {
		t.Fatalf("expected 1 retransmission on packet 5, got %d (pkt5=%v)", httpFl.Retransmissions, httpFl.Packets[4].IsRetransmit)
	}
	if httpFl.Duration != 42*time.Millisecond {
		t.Fatalf("expected duration 42ms, got %v", httpFl.Duration)
	}

	icmpFl := res.Flows[1]
	if icmpFl.Protocol != "icmp" || icmpFl.PacketCount != 2 {
		t.Fatalf("expected icmp flow with 2 packets, got proto=%q pkts=%d", icmpFl.Protocol, icmpFl.PacketCount)
	}
}
