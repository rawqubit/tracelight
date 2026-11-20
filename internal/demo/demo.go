package demo

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"time"

	"github.com/rawqubit/tracelight/internal/capture"
	"github.com/rawqubit/tracelight/internal/dissect"
	"github.com/rawqubit/tracelight/internal/flow"
)

// GeneratePCAPBytes creates a realistic synthetic pcap capture in memory containing:
// 1. A DNS A query + compressed response for api.example.com
// 2. A TCP 3-way handshake + TLS 1.3 ClientHello (SNI + ALPN) + ServerHello/AppData
// 3. A TCP 3-way handshake + HTTP/1.1 GET/200 exchange with a TCP retransmission
func GeneratePCAPBytes() ([]byte, error) {
	base := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

	clientMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	gwMAC := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0xfe}

	clientIP := netip.MustParseAddr("10.0.1.42")
	dnsIP := netip.MustParseAddr("1.1.1.1")
	tlsIP := netip.MustParseAddr("93.184.216.34")
	httpIP := netip.MustParseAddr("10.0.2.15")

	var pkts []capture.Packet
	add := func(offset time.Duration, frame []byte) {
		pkts = append(pkts, capture.Packet{
			Timestamp: base.Add(offset),
			OrigLen:   uint32(len(frame)),
			Data:      frame,
		})
	}

	// 1. DNS query + response
	dnsQuery := buildDNSQuery(0x4a1b, "api.example.com", 1)
	dnsResp := buildDNSResponseA(0x4a1b, "api.example.com", [4]byte{93, 184, 216, 34})
	add(0, buildUDPPacket(clientMAC, gwMAC, clientIP, dnsIP, 54321, 53, dnsQuery))
	add(4200*time.Microsecond, buildUDPPacket(gwMAC, clientMAC, dnsIP, clientIP, 53, 54321, dnsResp))

	// 2. TLS 1.3 handshake with SNI + ALPN
	var cSeq uint32 = 1000
	var sSeq uint32 = 9000
	add(5*time.Millisecond, buildTCPPacket(clientMAC, gwMAC, clientIP, tlsIP, 51820, 443, cSeq, 0, dissect.TCPFlagSYN, nil))
	cSeq++
	add(18400*time.Microsecond, buildTCPPacket(gwMAC, clientMAC, tlsIP, clientIP, 443, 51820, sSeq, cSeq, dissect.TCPFlagSYN|dissect.TCPFlagACK, nil))
	sSeq++
	add(18600*time.Microsecond, buildTCPPacket(clientMAC, gwMAC, clientIP, tlsIP, 51820, 443, cSeq, sSeq, dissect.TCPFlagACK, nil))

	ch := buildTLSClientHello("api.example.com", []string{"h2", "http/1.1"})
	add(19100*time.Microsecond, buildTCPPacket(clientMAC, gwMAC, clientIP, tlsIP, 51820, 443, cSeq, sSeq, dissect.TCPFlagPSH|dissect.TCPFlagACK, ch))
	cSeq += uint32(len(ch))

	sh := buildTLSServerHello()
	add(33*time.Millisecond, buildTCPPacket(gwMAC, clientMAC, tlsIP, clientIP, 443, 51820, sSeq, cSeq, dissect.TCPFlagPSH|dissect.TCPFlagACK, sh))
	sSeq += uint32(len(sh))

	appData := buildTLSAppData(64)
	add(34*time.Millisecond, buildTCPPacket(clientMAC, gwMAC, clientIP, tlsIP, 51820, 443, cSeq, sSeq, dissect.TCPFlagPSH|dissect.TCPFlagACK, appData))
	cSeq += uint32(len(appData))

	add(48*time.Millisecond, buildTCPPacket(clientMAC, gwMAC, clientIP, tlsIP, 51820, 443, cSeq, sSeq, dissect.TCPFlagFIN|dissect.TCPFlagACK, nil))

	// 3. HTTP/1.1 request/response with a TCP retransmission
	var hcSeq uint32 = 2000
	var hsSeq uint32 = 7000
	add(50*time.Millisecond, buildTCPPacket(clientMAC, gwMAC, clientIP, httpIP, 51900, 8080, hcSeq, 0, dissect.TCPFlagSYN, nil))
	hcSeq++
	add(52100*time.Microsecond, buildTCPPacket(gwMAC, clientMAC, httpIP, clientIP, 8080, 51900, hsSeq, hcSeq, dissect.TCPFlagSYN|dissect.TCPFlagACK, nil))
	hsSeq++
	add(52200*time.Microsecond, buildTCPPacket(clientMAC, gwMAC, clientIP, httpIP, 51900, 8080, hcSeq, hsSeq, dissect.TCPFlagACK, nil))

	httpReq := []byte("GET /v1/health HTTP/1.1\r\nHost: internal.example.com\r\nUser-Agent: tracelight-demo/1.0\r\nAccept: application/json\r\n\r\n")
	add(52500*time.Microsecond, buildTCPPacket(clientMAC, gwMAC, clientIP, httpIP, 51900, 8080, hcSeq, hsSeq, dissect.TCPFlagPSH|dissect.TCPFlagACK, httpReq))
	// Retransmit the exact same segment (same hcSeq) after 50ms timeout
	add(102500*time.Microsecond, buildTCPPacket(clientMAC, gwMAC, clientIP, httpIP, 51900, 8080, hcSeq, hsSeq, dissect.TCPFlagPSH|dissect.TCPFlagACK, httpReq))
	hcSeq += uint32(len(httpReq))

	httpResp := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 31\r\n\r\n{\"status\":\"ok\",\"uptime_s\":4821}")
	add(105*time.Millisecond, buildTCPPacket(gwMAC, clientMAC, httpIP, clientIP, 8080, 51900, hsSeq, hcSeq, dissect.TCPFlagPSH|dissect.TCPFlagACK, httpResp))
	hsSeq += uint32(len(httpResp))

	add(105200*time.Microsecond, buildTCPPacket(clientMAC, gwMAC, clientIP, httpIP, 51900, 8080, hcSeq, hsSeq, dissect.TCPFlagACK, nil))

	var buf bytes.Buffer
	if err := capture.WritePCAP(&buf, pkts, capture.LinkTypeEthernet, 65535); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Run generates the synthetic pcap in memory and runs the full capture -> dissect -> flow pipeline.
func Run() (*capture.Capture, *flow.Result, error) {
	raw, err := GeneratePCAPBytes()
	if err != nil {
		return nil, nil, err
	}
	capData, err := capture.Read(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, err
	}
	res := flow.Assemble(capData)
	return capData, res, nil
}

func buildUDPPacket(srcMAC, dstMAC [6]byte, srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	return buildIPv4EthFrame(srcMAC, dstMAC, srcIP, dstIP, dissect.IPProtoUDP, udp)
}

func buildTCPPacket(srcMAC, dstMAC [6]byte, srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4 // data offset 5 (20 bytes)
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)
	return buildIPv4EthFrame(srcMAC, dstMAC, srcIP, dstIP, dissect.IPProtoTCP, tcp)
}

func buildIPv4EthFrame(srcMAC, dstMAC [6]byte, srcIP, dstIP netip.Addr, proto uint8, l4 []byte) []byte {
	totalLen := 20 + len(l4)
	frame := make([]byte, 14+totalLen)
	copy(frame[0:6], dstMAC[:])
	copy(frame[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], dissect.EtherTypeIPv4)

	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ip[4:6], 0x1234)
	binary.BigEndian.PutUint16(ip[6:8], 0x4000) // DF
	ip[8] = 64                                  // TTL
	ip[9] = proto
	s4 := srcIP.As4()
	d4 := dstIP.As4()
	copy(ip[12:16], s4[:])
	copy(ip[16:20], d4[:])
	binary.BigEndian.PutUint16(ip[10:12], ipv4Checksum(ip[:20]))
	copy(ip[20:], l4)
	return frame
}

func ipv4Checksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func encodeDNSName(name string) []byte {
	var out bytes.Buffer
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		out.WriteByte(byte(len(label)))
		out.WriteString(label)
	}
	out.WriteByte(0)
	return out.Bytes()
}

func buildDNSQuery(id uint16, qname string, qtype uint16) []byte {
	var b bytes.Buffer
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT=1
	b.Write(hdr[:])
	b.Write(encodeDNSName(qname))
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], 1) // IN
	b.Write(tail[:])
	return b.Bytes()
}

func buildDNSResponseA(id uint16, qname string, addr [4]byte) []byte {
	var b bytes.Buffer
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8180) // QR=1, RD=1, RA=1, NOERROR
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT=1
	binary.BigEndian.PutUint16(hdr[6:8], 1)      // ANCOUNT=1
	b.Write(hdr[:])
	b.Write(encodeDNSName(qname))
	var qtail [4]byte
	binary.BigEndian.PutUint16(qtail[0:2], 1) // A
	binary.BigEndian.PutUint16(qtail[2:4], 1) // IN
	b.Write(qtail[:])

	// Answer using compression pointer to offset 12 (0xc00c)
	b.Write([]byte{0xc0, 0x0c})
	var rr [10]byte
	binary.BigEndian.PutUint16(rr[0:2], 1)   // A
	binary.BigEndian.PutUint16(rr[2:4], 1)   // IN
	binary.BigEndian.PutUint32(rr[4:8], 300) // TTL
	binary.BigEndian.PutUint16(rr[8:10], 4)  // RDLENGTH
	b.Write(rr[:])
	b.Write(addr[:])
	return b.Bytes()
}

func buildTLSClientHello(sni string, alpn []string) []byte {
	var exts bytes.Buffer

	// SNI extension (0x0000)
	if sni != "" {
		var sniBuf bytes.Buffer
		entryLen := 1 + 2 + len(sni)
		binary.Write(&sniBuf, binary.BigEndian, uint16(entryLen))
		sniBuf.WriteByte(0x00) // host_name
		binary.Write(&sniBuf, binary.BigEndian, uint16(len(sni)))
		sniBuf.WriteString(sni)

		binary.Write(&exts, binary.BigEndian, uint16(0x0000))
		binary.Write(&exts, binary.BigEndian, uint16(sniBuf.Len()))
		exts.Write(sniBuf.Bytes())
	}

	// ALPN extension (0x0010)
	if len(alpn) > 0 {
		var alpnList bytes.Buffer
		for _, p := range alpn {
			alpnList.WriteByte(byte(len(p)))
			alpnList.WriteString(p)
		}
		var alpnBuf bytes.Buffer
		binary.Write(&alpnBuf, binary.BigEndian, uint16(alpnList.Len()))
		alpnBuf.Write(alpnList.Bytes())

		binary.Write(&exts, binary.BigEndian, uint16(0x0010))
		binary.Write(&exts, binary.BigEndian, uint16(alpnBuf.Len()))
		exts.Write(alpnBuf.Bytes())
	}

	// supported_versions extension (0x002b): TLS 1.3 (0x0304), TLS 1.2 (0x0303)
	binary.Write(&exts, binary.BigEndian, uint16(0x002b))
	binary.Write(&exts, binary.BigEndian, uint16(5))
	exts.WriteByte(4)
	binary.Write(&exts, binary.BigEndian, uint16(0x0304))
	binary.Write(&exts, binary.BigEndian, uint16(0x0303))

	var body bytes.Buffer
	// Legacy version TLS 1.2 (0x0303)
	binary.Write(&body, binary.BigEndian, uint16(0x0303))
	// 32-byte random
	var random [32]byte
	for i := range random {
		random[i] = byte(i + 1)
	}
	body.Write(random[:])
	// Session ID (empty)
	body.WriteByte(0)
	// Cipher suites: TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA384 (0x1302)
	binary.Write(&body, binary.BigEndian, uint16(4))
	binary.Write(&body, binary.BigEndian, uint16(0x1301))
	binary.Write(&body, binary.BigEndian, uint16(0x1302))
	// Compression methods: null (0x00)
	body.WriteByte(1)
	body.WriteByte(0)
	// Extensions
	binary.Write(&body, binary.BigEndian, uint16(exts.Len()))
	body.Write(exts.Bytes())

	// Handshake header
	var hs bytes.Buffer
	hs.WriteByte(dissect.TLSHandshakeClientHello)
	l := body.Len()
	hs.WriteByte(byte(l >> 16))
	hs.WriteByte(byte(l >> 8))
	hs.WriteByte(byte(l))
	hs.Write(body.Bytes())

	// TLS record header (0x16, 0x0301, len)
	var rec bytes.Buffer
	rec.WriteByte(dissect.TLSContentHandshake)
	binary.Write(&rec, binary.BigEndian, uint16(0x0301))
	binary.Write(&rec, binary.BigEndian, uint16(hs.Len()))
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

func buildTLSServerHello() []byte {
	var body bytes.Buffer
	binary.Write(&body, binary.BigEndian, uint16(0x0303))
	body.Write(make([]byte, 32))
	body.WriteByte(0) // session id
	binary.Write(&body, binary.BigEndian, uint16(0x1301))
	body.WriteByte(0) // compression

	var hs bytes.Buffer
	hs.WriteByte(dissect.TLSHandshakeServerHello)
	l := body.Len()
	hs.WriteByte(byte(l >> 16))
	hs.WriteByte(byte(l >> 8))
	hs.WriteByte(byte(l))
	hs.Write(body.Bytes())

	var rec bytes.Buffer
	rec.WriteByte(dissect.TLSContentHandshake)
	binary.Write(&rec, binary.BigEndian, uint16(0x0303))
	binary.Write(&rec, binary.BigEndian, uint16(hs.Len()))
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

func buildTLSAppData(n int) []byte {
	var rec bytes.Buffer
	rec.WriteByte(dissect.TLSContentAppData)
	binary.Write(&rec, binary.BigEndian, uint16(0x0303))
	binary.Write(&rec, binary.BigEndian, uint16(n))
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(0x41 + (i % 26))
	}
	rec.Write(payload)
	return rec.Bytes()
}
