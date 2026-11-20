package dissect

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	TLSContentChangeCipherSpec uint8 = 20
	TLSContentAlert            uint8 = 21
	TLSContentHandshake        uint8 = 22
	TLSContentAppData          uint8 = 23

	TLSHandshakeClientHello uint8 = 1
	TLSHandshakeServerHello uint8 = 2

	tlsExtServerName        uint16 = 0x0000
	tlsExtALPN              uint16 = 0x0010
	tlsExtSupportedVersions uint16 = 0x002b
)

type TLSLayer struct {
	ContentType   uint8
	RecordVersion uint16
	HandshakeType uint8
	IsClientHello bool
	Version       uint16
	VersionName   string
	SNI           string
	ALPN          []string
	CipherSuites  []uint16
}

func (t *TLSLayer) Summary() string {
	if t.IsClientHello {
		var parts []string
		parts = append(parts, fmt.Sprintf("%s ClientHello", t.VersionName))
		if t.SNI != "" {
			parts = append(parts, "sni="+t.SNI)
		}
		if len(t.ALPN) > 0 {
			parts = append(parts, "alpn=["+strings.Join(t.ALPN, ",")+"]")
		}
		return strings.Join(parts, " ")
	}
	if t.ContentType == TLSContentHandshake {
		return fmt.Sprintf("%s %s", t.VersionName, tlsHandshakeName(t.HandshakeType))
	}
	return fmt.Sprintf("%s %s", t.VersionName, tlsContentName(t.ContentType))
}

// DecodeTLSClientHello parses a TLS ClientHello record and extracts SNI, effective version,
// cipher suites, and offered ALPN protocols.
func DecodeTLSClientHello(data []byte) (*TLSLayer, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("tls: length %d < 9", len(data))
	}
	if data[0] != TLSContentHandshake {
		return nil, fmt.Errorf("tls: content type %d != Handshake(22)", data[0])
	}
	if data[1] != 0x03 {
		return nil, fmt.Errorf("tls: invalid record major version 0x%02x", data[1])
	}
	recVer := binary.BigEndian.Uint16(data[1:3])
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if recLen < 4 || 5+recLen > len(data) {
		return nil, fmt.Errorf("tls: record length %d out of bounds (%d available)", recLen, len(data)-5)
	}

	hs := data[5 : 5+recLen]
	if hs[0] != TLSHandshakeClientHello {
		return nil, fmt.Errorf("tls: handshake type %d != ClientHello(1)", hs[0])
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if hsLen+4 > len(hs) {
		return nil, fmt.Errorf("tls: handshake length %d exceeds record (%d)", hsLen, len(hs)-4)
	}
	body := hs[4 : 4+hsLen]
	if len(body) < 34 {
		return nil, fmt.Errorf("tls: ClientHello body too short (%d < 34)", len(body))
	}

	clientVer := binary.BigEndian.Uint16(body[0:2])
	off := 34 // 2-byte version + 32-byte random

	// Session ID
	if off >= len(body) {
		return nil, fmt.Errorf("tls: truncated session_id length")
	}
	sessLen := int(body[off])
	off++
	if off+sessLen > len(body) {
		return nil, fmt.Errorf("tls: truncated session_id")
	}
	off += sessLen

	// Cipher Suites
	if off+2 > len(body) {
		return nil, fmt.Errorf("tls: truncated cipher_suites length")
	}
	csLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if csLen%2 != 0 || off+csLen > len(body) {
		return nil, fmt.Errorf("tls: invalid cipher_suites length %d", csLen)
	}
	suites := make([]uint16, 0, csLen/2)
	for i := 0; i < csLen; i += 2 {
		suites = append(suites, binary.BigEndian.Uint16(body[off+i:off+i+2]))
	}
	off += csLen

	// Compression Methods
	if off >= len(body) {
		return nil, fmt.Errorf("tls: truncated compression_methods length")
	}
	compLen := int(body[off])
	off++
	if off+compLen > len(body) {
		return nil, fmt.Errorf("tls: truncated compression_methods")
	}
	off += compLen

	layer := &TLSLayer{
		ContentType:   TLSContentHandshake,
		RecordVersion: recVer,
		HandshakeType: TLSHandshakeClientHello,
		IsClientHello: true,
		Version:       clientVer,
		VersionName:   tlsVersionName(clientVer),
		CipherSuites:  suites,
	}

	// Extensions (optional if ClientHello ends right after compression methods)
	if off == len(body) {
		return layer, nil
	}
	if off+2 > len(body) {
		return nil, fmt.Errorf("tls: truncated extensions length")
	}
	extTotal := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if off+extTotal > len(body) {
		return nil, fmt.Errorf("tls: extensions length %d exceeds body", extTotal)
	}
	exts := body[off : off+extTotal]
	for len(exts) > 0 {
		if len(exts) < 4 {
			return nil, fmt.Errorf("tls: truncated extension header")
		}
		extType := binary.BigEndian.Uint16(exts[0:2])
		extLen := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if extLen > len(exts) {
			return nil, fmt.Errorf("tls: extension 0x%04x length %d exceeds remaining %d", extType, extLen, len(exts))
		}
		extData := exts[:extLen]
		exts = exts[extLen:]

		switch extType {
		case tlsExtServerName:
			if sni, err := parseSNIExtension(extData); err == nil && sni != "" {
				layer.SNI = sni
			}
		case tlsExtALPN:
			if alpns, err := parseALPNExtension(extData); err == nil {
				layer.ALPN = alpns
			}
		case tlsExtSupportedVersions:
			if bestVer := parseSupportedVersionsClient(extData); bestVer != 0 {
				layer.Version = bestVer
				layer.VersionName = tlsVersionName(bestVer)
			}
		}
	}

	return layer, nil
}

// DecodeTLSRecord identifies non-ClientHello TLS records (ServerHello, Alert, AppData, etc.).
func DecodeTLSRecord(data []byte) (*TLSLayer, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("tls: length %d < 5", len(data))
	}
	ct := data[0]
	if ct < TLSContentChangeCipherSpec || ct > TLSContentAppData {
		return nil, fmt.Errorf("tls: unknown content type %d", ct)
	}
	if data[1] != 0x03 || data[2] > 0x04 {
		return nil, fmt.Errorf("tls: invalid record version 0x%02x%02x", data[1], data[2])
	}
	recVer := binary.BigEndian.Uint16(data[1:3])
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if recLen == 0 || 5+recLen > len(data) {
		return nil, fmt.Errorf("tls: record length %d out of bounds", recLen)
	}
	layer := &TLSLayer{
		ContentType:   ct,
		RecordVersion: recVer,
		Version:       recVer,
		VersionName:   tlsVersionName(recVer),
	}
	if ct == TLSContentHandshake && recLen >= 4 {
		layer.HandshakeType = data[5]
		if layer.HandshakeType == TLSHandshakeServerHello && recLen >= 6 {
			sv := binary.BigEndian.Uint16(data[9:11])
			layer.Version = sv
			layer.VersionName = tlsVersionName(sv)
		}
	}
	return layer, nil
}

func parseSNIExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("sni too short")
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLen > len(data) {
		return "", fmt.Errorf("sni list out of bounds")
	}
	entries := data[2 : 2+listLen]
	for len(entries) >= 3 {
		nameType := entries[0]
		nameLen := int(binary.BigEndian.Uint16(entries[1:3]))
		entries = entries[3:]
		if nameLen > len(entries) {
			return "", fmt.Errorf("sni entry out of bounds")
		}
		if nameType == 0 {
			return string(entries[:nameLen]), nil
		}
		entries = entries[nameLen:]
	}
	return "", nil
}

func parseALPNExtension(data []byte) ([]string, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("alpn too short")
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLen > len(data) {
		return nil, fmt.Errorf("alpn list out of bounds")
	}
	entries := data[2 : 2+listLen]
	var out []string
	for len(entries) > 0 {
		l := int(entries[0])
		entries = entries[1:]
		if l == 0 || l > len(entries) {
			return nil, fmt.Errorf("alpn protocol length invalid")
		}
		out = append(out, string(entries[:l]))
		entries = entries[l:]
	}
	return out, nil
}

func parseSupportedVersionsClient(data []byte) uint16 {
	if len(data) < 3 {
		return 0
	}
	listLen := int(data[0])
	if 1+listLen > len(data) || listLen%2 != 0 {
		return 0
	}
	var best uint16
	for i := 1; i+1 < 1+listLen; i += 2 {
		v := binary.BigEndian.Uint16(data[i : i+2])
		// Ignore GREASE values (0x?a?a)
		if (v&0x0f0f) == 0x0a0a && (v>>8) == (v&0xff) {
			continue
		}
		if v >= 0x0300 && v <= 0x0304 && v > best {
			best = v
		}
	}
	return best
}

func tlsVersionName(v uint16) string {
	switch v {
	case 0x0304:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	case 0x0302:
		return "TLS 1.1"
	case 0x0301:
		return "TLS 1.0"
	case 0x0300:
		return "SSL 3.0"
	default:
		return fmt.Sprintf("TLS(0x%04x)", v)
	}
}

func tlsHandshakeName(t uint8) string {
	switch t {
	case 1:
		return "ClientHello"
	case 2:
		return "ServerHello"
	case 11:
		return "Certificate"
	case 12:
		return "ServerKeyExchange"
	case 14:
		return "ServerHelloDone"
	case 16:
		return "ClientKeyExchange"
	case 20:
		return "Finished"
	default:
		return fmt.Sprintf("Handshake(%d)", t)
	}
}

func tlsContentName(ct uint8) string {
	switch ct {
	case TLSContentChangeCipherSpec:
		return "ChangeCipherSpec"
	case TLSContentAlert:
		return "Alert"
	case TLSContentHandshake:
		return "Handshake"
	case TLSContentAppData:
		return "ApplicationData"
	default:
		return fmt.Sprintf("Record(%d)", ct)
	}
}
