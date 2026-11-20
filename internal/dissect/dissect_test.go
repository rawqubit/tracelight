package dissect

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/rawqubit/tracelight/internal/capture"
)

func TestDecodeEthernetWithVLANs(t *testing.T) {
	var frame bytes.Buffer
	// Dst MAC, Src MAC
	frame.Write([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	frame.Write([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	// Outer 802.1ad QinQ tag (0x88a8), VID=100, PCP=3
	binary.Write(&frame, binary.BigEndian, EtherTypeQinQ)
	binary.Write(&frame, binary.BigEndian, uint16((3<<13)|100))
	// Inner 802.1Q tag (0x8100), VID=200
	binary.Write(&frame, binary.BigEndian, EtherTypeVLAN)
	binary.Write(&frame, binary.BigEndian, uint16(200))
	// Inner EtherType IPv4
	binary.Write(&frame, binary.BigEndian, EtherTypeIPv4)
	frame.Write([]byte{0xaa, 0xbb})

	eth, err := DecodeEthernet(frame.Bytes())
	if err != nil {
		t.Fatalf("DecodeEthernet: %v", err)
	}
	if len(eth.VLANs) != 2 || eth.VLANs[0].VID != 100 || eth.VLANs[1].VID != 200 {
		t.Fatalf("unexpected VLANs: %+v", eth.VLANs)
	}
	if eth.EtherType != EtherTypeIPv4 {
		t.Fatalf("expected IPv4 ethertype, got 0x%04x", eth.EtherType)
	}
	if !strings.Contains(eth.Summary(), "vlan=100") {
		t.Fatalf("summary missing vlan: %q", eth.Summary())
	}
}

func TestDecodeIPv4AndTCP(t *testing.T) {
	// IPv4 with IHL=6 (24 bytes including 4 bytes options) + TCP (20 bytes) + "hi"
	pkt := make([]byte, 24+20+2)
	pkt[0] = 0x46 // v4, ihl=6
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = IPProtoTCP
	copy(pkt[12:16], []byte{10, 1, 2, 3})
	copy(pkt[16:20], []byte{10, 4, 5, 6})

	tcp := pkt[24:]
	binary.BigEndian.PutUint16(tcp[0:2], 51234)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint32(tcp[4:8], 1001)
	binary.BigEndian.PutUint32(tcp[8:12], 2002)
	tcp[12] = 5 << 4
	tcp[13] = TCPFlagSYN | TCPFlagACK
	binary.BigEndian.PutUint16(tcp[14:16], 32768)
	copy(tcp[20:], "hi")

	ip4, err := DecodeIPv4(pkt)
	if err != nil {
		t.Fatalf("DecodeIPv4: %v", err)
	}
	if ip4.SrcIP != netip.MustParseAddr("10.1.2.3") || ip4.DstIP != netip.MustParseAddr("10.4.5.6") {
		t.Fatalf("unexpected IPs: %v -> %v", ip4.SrcIP, ip4.DstIP)
	}
	if len(ip4.Options) != 4 {
		t.Fatalf("expected 4 bytes of IP options, got %d", len(ip4.Options))
	}
	tcpl, err := DecodeTCP(ip4.Payload)
	if err != nil {
		t.Fatalf("DecodeTCP: %v", err)
	}
	if tcpl.SrcPort != 51234 || tcpl.DstPort != 443 || !tcpl.Flags.Has(TCPFlagSYN) || !tcpl.Flags.Has(TCPFlagACK) {
		t.Fatalf("unexpected TCP layer: %+v", tcpl)
	}
	if string(tcpl.Payload) != "hi" {
		t.Fatalf("unexpected TCP payload: %q", tcpl.Payload)
	}
	if !strings.Contains(tcpl.Summary(), "SYN,ACK") {
		t.Fatalf("unexpected TCP summary: %q", tcpl.Summary())
	}
}

func TestDecodeIPv6WithExtHeaderAndUDP(t *testing.T) {
	// IPv6 (40) -> Hop-by-Hop (8, next=UDP 17) -> UDP (8) -> "ping" (4)
	pkt := make([]byte, 40+8+8+4)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], 8+8+4)
	pkt[6] = 0 // Hop-by-Hop
	pkt[7] = 64
	src := netip.MustParseAddr("2001:db8::1").As16()
	dst := netip.MustParseAddr("2001:db8::2").As16()
	copy(pkt[8:24], src[:])
	copy(pkt[24:40], dst[:])

	// Hop-by-Hop ext header: next=17 (UDP), len=0 (8 bytes total)
	pkt[40] = IPProtoUDP
	pkt[41] = 0

	// UDP header
	udp := pkt[48:]
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], 5353)
	binary.BigEndian.PutUint16(udp[4:6], 12)
	copy(udp[8:], "ping")

	ip6, err := DecodeIPv6(pkt)
	if err != nil {
		t.Fatalf("DecodeIPv6: %v", err)
	}
	if ip6.UpperProto != IPProtoUDP || len(ip6.ExtHeaders) != 1 || ip6.ExtHeaders[0] != 0 {
		t.Fatalf("unexpected IPv6 ext parsing: upper=%d exts=%v", ip6.UpperProto, ip6.ExtHeaders)
	}
	udpl, err := DecodeUDP(ip6.Payload)
	if err != nil {
		t.Fatalf("DecodeUDP: %v", err)
	}
	if udpl.SrcPort != 40000 || udpl.DstPort != 5353 || string(udpl.Payload) != "ping" {
		t.Fatalf("unexpected UDP: %+v", udpl)
	}
	if !strings.Contains(ip6.Summary(), "2001:db8::1") {
		t.Fatalf("unexpected IPv6 summary: %q", ip6.Summary())
	}
}

func TestDecodeDNSAndLoopGuard(t *testing.T) {
	var msg bytes.Buffer
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], 0x1234)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8180) // response NOERROR
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // qd=1
	binary.BigEndian.PutUint16(hdr[6:8], 1)      // an=1
	msg.Write(hdr[:])
	msg.Write([]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0})
	msg.Write([]byte{0, 1, 0, 1}) // A, IN
	// Answer: pointer to offset 12 (0xc00c), A, IN, TTL=60, 4 bytes 93.184.216.34
	msg.Write([]byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34})

	dnsLayer, err := DecodeDNS(msg.Bytes())
	if err != nil {
		t.Fatalf("DecodeDNS: %v", err)
	}
	if !dnsLayer.IsResponse || len(dnsLayer.Questions) != 1 || len(dnsLayer.Answers) != 1 {
		t.Fatalf("unexpected DNS layer: %+v", dnsLayer)
	}
	if dnsLayer.Questions[0].Name != "example.com" || dnsLayer.Answers[0].Data != "93.184.216.34" {
		t.Fatalf("unexpected DNS question/answer: q=%+v a=%+v", dnsLayer.Questions[0], dnsLayer.Answers[0])
	}
	if !strings.Contains(dnsLayer.Summary(), "93.184.216.34") {
		t.Fatalf("unexpected DNS summary: %q", dnsLayer.Summary())
	}

	// Self-referential pointer loop at offset 12 (0xc00c)
	loopMsg := []byte{
		0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
	}
	if _, err := DecodeDNS(loopMsg); err == nil {
		t.Fatalf("expected error on DNS pointer loop, got nil")
	}
}

func TestDecodeHTTPRequestAndResponse(t *testing.T) {
	reqRaw := []byte("POST /v1/events HTTP/1.1\r\nHost: logs.example.com\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}")
	req, err := DecodeHTTP(reqRaw)
	if err != nil {
		t.Fatalf("DecodeHTTP request: %v", err)
	}
	if req.IsResponse || req.Method != "POST" || req.Target != "/v1/events" || req.Host != "logs.example.com" {
		t.Fatalf("unexpected HTTP req: %+v", req)
	}
	if !strings.Contains(req.Summary(), "POST logs.example.com/v1/events") {
		t.Fatalf("unexpected HTTP req summary: %q", req.Summary())
	}

	respRaw := []byte("HTTP/1.1 204 No Content\r\nX-Trace-Id: abc123\r\n\r\n")
	resp, err := DecodeHTTP(respRaw)
	if err != nil {
		t.Fatalf("DecodeHTTP response: %v", err)
	}
	if !resp.IsResponse || resp.StatusCode != 204 || resp.Reason != "No Content" || resp.Header("x-trace-id") != "abc123" {
		t.Fatalf("unexpected HTTP resp: %+v", resp)
	}
	if !strings.Contains(resp.Summary(), "204 No Content") {
		t.Fatalf("unexpected HTTP resp summary: %q", resp.Summary())
	}
}

func TestDecodeTLSClientHello(t *testing.T) {
	var exts bytes.Buffer
	// SNI: api.example.com
	sni := "api.example.com"
	binary.Write(&exts, binary.BigEndian, uint16(0x0000))
	binary.Write(&exts, binary.BigEndian, uint16(2+1+2+len(sni)))
	binary.Write(&exts, binary.BigEndian, uint16(1+2+len(sni)))
	exts.WriteByte(0x00)
	binary.Write(&exts, binary.BigEndian, uint16(len(sni)))
	exts.WriteString(sni)

	// ALPN: h2, http/1.1
	alpnData := []byte{2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	binary.Write(&exts, binary.BigEndian, uint16(0x0010))
	binary.Write(&exts, binary.BigEndian, uint16(2+len(alpnData)))
	binary.Write(&exts, binary.BigEndian, uint16(len(alpnData)))
	exts.Write(alpnData)

	// supported_versions: GREASE 0x0a0a + TLS 1.3 (0x0304)
	binary.Write(&exts, binary.BigEndian, uint16(0x002b))
	binary.Write(&exts, binary.BigEndian, uint16(5))
	exts.WriteByte(4)
	binary.Write(&exts, binary.BigEndian, uint16(0x0a0a))
	binary.Write(&exts, binary.BigEndian, uint16(0x0304))

	var body bytes.Buffer
	binary.Write(&body, binary.BigEndian, uint16(0x0303))
	body.Write(make([]byte, 32))
	body.WriteByte(0) // session id
	binary.Write(&body, binary.BigEndian, uint16(2))
	binary.Write(&body, binary.BigEndian, uint16(0x1301))
	body.Write([]byte{1, 0})
	binary.Write(&body, binary.BigEndian, uint16(exts.Len()))
	body.Write(exts.Bytes())

	var rec bytes.Buffer
	rec.WriteByte(0x16)
	binary.Write(&rec, binary.BigEndian, uint16(0x0301))
	binary.Write(&rec, binary.BigEndian, uint16(4+body.Len()))
	rec.WriteByte(0x01)
	l := body.Len()
	rec.Write([]byte{byte(l >> 16), byte(l >> 8), byte(l)})
	rec.Write(body.Bytes())

	tlsLayer, err := DecodeTLSClientHello(rec.Bytes())
	if err != nil {
		t.Fatalf("DecodeTLSClientHello: %v", err)
	}
	if tlsLayer.SNI != "api.example.com" {
		t.Fatalf("expected SNI api.example.com, got %q", tlsLayer.SNI)
	}
	if tlsLayer.Version != 0x0304 || tlsLayer.VersionName != "TLS 1.3" {
		t.Fatalf("expected TLS 1.3, got %s (0x%04x)", tlsLayer.VersionName, tlsLayer.Version)
	}
	if len(tlsLayer.ALPN) != 2 || tlsLayer.ALPN[0] != "h2" || tlsLayer.ALPN[1] != "http/1.1" {
		t.Fatalf("unexpected ALPN: %v", tlsLayer.ALPN)
	}
	if !strings.Contains(tlsLayer.Summary(), "sni=api.example.com") {
		t.Fatalf("unexpected TLS summary: %q", tlsLayer.Summary())
	}
}

func TestDissectorsFuzzNoPanic2000(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	for i := 0; i < 2000; i++ {
		n := rng.Intn(512)
		buf := make([]byte, n)
		rng.Read(buf)
		_ = Decode(capture.LinkTypeEthernet, buf)
		_ = Decode(capture.LinkTypeRawIP, buf)
		_, _ = DecodeEthernet(buf)
		_, _ = DecodeIPv4(buf)
		_, _ = DecodeIPv6(buf)
		_, _ = DecodeICMP(buf, i%2 == 0)
		_, _ = DecodeTCP(buf)
		_, _ = DecodeUDP(buf)
		_, _ = DecodeDNS(buf)
		_, _ = DecodeHTTP(buf)
		_, _ = DecodeTLSClientHello(buf)
		_, _ = DecodeTLSRecord(buf)
	}
}
