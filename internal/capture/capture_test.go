package capture

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
	"time"
)

func buildPCAPBytes(order binary.ByteOrder, nano bool, pkts []Packet) []byte {
	var buf bytes.Buffer
	var gh [24]byte
	magic := uint32(0xa1b2c3d4)
	if nano {
		magic = 0xa1b23c4d
	}
	order.PutUint32(gh[0:4], magic)
	order.PutUint16(gh[4:6], 2)
	order.PutUint16(gh[6:8], 4)
	order.PutUint32(gh[16:20], 65535)
	order.PutUint32(gh[20:24], uint32(LinkTypeEthernet))
	buf.Write(gh[:])

	var ph [16]byte
	for _, p := range pkts {
		order.PutUint32(ph[0:4], uint32(p.Timestamp.Unix()))
		sub := uint32(p.Timestamp.Nanosecond())
		if !nano {
			sub /= 1000
		}
		order.PutUint32(ph[4:8], sub)
		order.PutUint32(ph[8:12], uint32(len(p.Data)))
		order.PutUint32(ph[12:16], p.OrigLen)
		buf.Write(ph[:])
		buf.Write(p.Data)
	}
	return buf.Bytes()
}

func buildPCAPNGBytes(order binary.ByteOrder, tsResol byte, includeSPB bool, payload []byte) []byte {
	var buf bytes.Buffer

	// SHB (28 bytes)
	var shb [28]byte
	order.PutUint32(shb[0:4], pcapngSHBType)
	order.PutUint32(shb[4:8], 28)
	order.PutUint32(shb[8:12], pcapngByteOrderMagic)
	order.PutUint16(shb[12:14], 1)
	order.PutUint16(shb[14:16], 0)
	order.PutUint64(shb[16:24], ^uint64(0))
	order.PutUint32(shb[24:28], 28)
	buf.Write(shb[:])

	// IDB (32 bytes with if_tsresol option)
	var idb [32]byte
	order.PutUint32(idb[0:4], pcapngIDBType)
	order.PutUint32(idb[4:8], 32)
	order.PutUint16(idb[8:10], uint16(LinkTypeEthernet))
	order.PutUint32(idb[12:16], 65535)
	order.PutUint16(idb[16:18], optIFTSResol)
	order.PutUint16(idb[18:20], 1)
	idb[20] = tsResol
	order.PutUint16(idb[24:26], optEndOfOpt)
	order.PutUint32(idb[28:32], 32)
	buf.Write(idb[:])

	// Unknown metadata block (16 bytes) to verify skipping
	var unk [16]byte
	order.PutUint32(unk[0:4], 0x00000005)
	order.PutUint32(unk[4:8], 16)
	order.PutUint32(unk[12:16], 16)
	buf.Write(unk[:])

	// EPB
	padded := (len(payload) + 3) &^ 3
	epbLen := 32 + padded
	epb := make([]byte, epbLen)
	order.PutUint32(epb[0:4], pcapngEPBType)
	order.PutUint32(epb[4:8], uint32(epbLen))
	order.PutUint32(epb[8:12], 0) // iface 0
	// timestamp = 1700000000 seconds in target resolution
	var tsRaw uint64
	switch tsResol {
	case 6:
		tsRaw = 1700000000*1_000_000 + 123456
	case 9:
		tsRaw = 1700000000*1_000_000_000 + 123456789
	case 0x80 | 10:
		tsRaw = (1700000000 << 10) + 512 // +0.5s
	}
	order.PutUint32(epb[12:16], uint32(tsRaw>>32))
	order.PutUint32(epb[16:20], uint32(tsRaw))
	order.PutUint32(epb[20:24], uint32(len(payload)))
	order.PutUint32(epb[24:28], uint32(len(payload)))
	copy(epb[28:28+len(payload)], payload)
	order.PutUint32(epb[epbLen-4:epbLen], uint32(epbLen))
	buf.Write(epb)

	if includeSPB {
		spbLen := 16 + padded
		spb := make([]byte, spbLen)
		order.PutUint32(spb[0:4], pcapngSPBType)
		order.PutUint32(spb[4:8], uint32(spbLen))
		order.PutUint32(spb[8:12], uint32(len(payload)))
		copy(spb[12:12+len(payload)], payload)
		order.PutUint32(spb[spbLen-4:spbLen], uint32(spbLen))
		buf.Write(spb)
	}

	return buf.Bytes()
}

func TestReadPCAPVariants(t *testing.T) {
	ts := time.Date(2026, 11, 19, 10, 0, 0, 123456789, time.UTC)
	payload := []byte{1, 2, 3, 4, 5, 6}
	in := []Packet{{Timestamp: ts, OrigLen: 6, Data: payload}}

	cases := []struct {
		name  string
		order binary.ByteOrder
		nano  bool
	}{
		{"little-endian usec", binary.LittleEndian, false},
		{"big-endian usec", binary.BigEndian, false},
		{"little-endian nsec", binary.LittleEndian, true},
		{"big-endian nsec", binary.BigEndian, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildPCAPBytes(tc.order, tc.nano, in)
			c, err := Read(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("Read failed: %v", err)
			}
			if c.Format != FormatPCAP {
				t.Fatalf("expected FormatPCAP, got %q", c.Format)
			}
			if len(c.Packets) != 1 {
				t.Fatalf("expected 1 packet, got %d", len(c.Packets))
			}
			got := c.Packets[0]
			if !bytes.Equal(got.Data, payload) {
				t.Fatalf("payload mismatch: got %x want %x", got.Data, payload)
			}
			if tc.nano {
				if !got.Timestamp.Equal(ts) {
					t.Fatalf("timestamp mismatch: got %v want %v", got.Timestamp, ts)
				}
			} else {
				want := ts.Truncate(time.Microsecond)
				if !got.Timestamp.Equal(want) {
					t.Fatalf("timestamp mismatch: got %v want %v", got.Timestamp, want)
				}
			}
		})
	}
}

func TestReadPCAPNGVariants(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef, 0x01}

	cases := []struct {
		name     string
		order    binary.ByteOrder
		tsResol  byte
		wantNano int
	}{
		{"LE microsecond", binary.LittleEndian, 6, 123456000},
		{"BE nanosecond", binary.BigEndian, 9, 123456789},
		{"LE binary 2^-10", binary.LittleEndian, 0x80 | 10, 500000000},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildPCAPNGBytes(tc.order, tc.tsResol, true, payload)
			c, err := Read(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("Read failed: %v", err)
			}
			if c.Format != FormatPCAPNG {
				t.Fatalf("expected FormatPCAPNG, got %q", c.Format)
			}
			if len(c.Packets) != 2 {
				t.Fatalf("expected 2 packets (EPB+SPB), got %d", len(c.Packets))
			}
			if !bytes.Equal(c.Packets[0].Data, payload) {
				t.Fatalf("EPB payload mismatch")
			}
			if c.Packets[0].Timestamp.Unix() != 1700000000 || c.Packets[0].Timestamp.Nanosecond() != tc.wantNano {
				t.Fatalf("EPB timestamp mismatch: got %v (nsec=%d want %d)",
					c.Packets[0].Timestamp, c.Packets[0].Timestamp.Nanosecond(), tc.wantNano)
			}
			if !bytes.Equal(c.Packets[1].Data, payload) {
				t.Fatalf("SPB payload mismatch")
			}
		})
	}
}

func TestReadFixtureFiles(t *testing.T) {
	pcapCap, err := ReadFile("../../testdata/sample.pcap")
	if err != nil {
		t.Fatalf("ReadFile sample.pcap: %v", err)
	}
	ngCap, err := ReadFile("../../testdata/sample.pcapng")
	if err != nil {
		t.Fatalf("ReadFile sample.pcapng: %v", err)
	}

	if pcapCap.Format != FormatPCAP || ngCap.Format != FormatPCAPNG {
		t.Fatalf("unexpected formats: %q / %q", pcapCap.Format, ngCap.Format)
	}
	if len(pcapCap.Packets) != 16 || len(ngCap.Packets) != 16 {
		t.Fatalf("expected 16 packets in fixtures, got %d and %d", len(pcapCap.Packets), len(ngCap.Packets))
	}
	for i := range pcapCap.Packets {
		if !bytes.Equal(pcapCap.Packets[i].Data, ngCap.Packets[i].Data) {
			t.Fatalf("packet %d payload mismatch between pcap and pcapng fixtures", i+1)
		}
		if !pcapCap.Packets[i].Timestamp.Equal(ngCap.Packets[i].Timestamp) {
			t.Fatalf("packet %d timestamp mismatch: %v vs %v", i+1, pcapCap.Packets[i].Timestamp, ngCap.Packets[i].Timestamp)
		}
	}
}

func TestRejectCorruptCaptures(t *testing.T) {
	validPCAP := buildPCAPBytes(binary.LittleEndian, false, []Packet{{
		Timestamp: time.Unix(1700000000, 0),
		OrigLen:   4,
		Data:      []byte{1, 2, 3, 4},
	}})

	validNG := buildPCAPNGBytes(binary.LittleEndian, 6, false, []byte{1, 2, 3, 4})

	// Corrupt pcapng trailing length
	badTrailNG := append([]byte(nil), validNG...)
	badTrailNG[len(badTrailNG)-1] ^= 0xff

	// Oversized incl_len in pcap
	hugeLenPCAP := append([]byte(nil), validPCAP...)
	binary.LittleEndian.PutUint32(hugeLenPCAP[24+8:24+12], 0xffffffff)

	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"short magic", []byte{0xd4, 0xc3}},
		{"unknown magic", []byte{0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0}},
		{"truncated pcap global hdr", validPCAP[:12]},
		{"truncated pcap pkt hdr", validPCAP[:30]},
		{"truncated pcap pkt body", validPCAP[:len(validPCAP)-1]},
		{"huge pcap incl_len", hugeLenPCAP},
		{"truncated pcapng shb", validNG[:16]},
		{"pcapng bad trailing len", badTrailNG},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Read(bytes.NewReader(tc.data)); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestCaptureFuzzNoPanic2000(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	validPCAP := buildPCAPBytes(binary.LittleEndian, false, []Packet{{
		Timestamp: time.Unix(1700000000, 0),
		OrigLen:   4,
		Data:      []byte{1, 2, 3, 4},
	}})
	validNG := buildPCAPNGBytes(binary.LittleEndian, 6, false, []byte{1, 2, 3, 4})

	for i := 0; i < 2000; i++ {
		n := rng.Intn(256)
		buf := make([]byte, n)
		rng.Read(buf)
		// Mix in header-prefixed mutations on half the iterations to exercise deeper parsing paths
		switch i % 4 {
		case 0:
			if n >= 4 {
				copy(buf[:4], validPCAP[:4])
			}
		case 1:
			if n >= 8 {
				copy(buf[:8], validNG[:8])
			}
		case 2:
			if n >= len(validNG) {
				copy(buf, validNG)
				buf[rng.Intn(len(validNG))] ^= byte(rng.Intn(255) + 1)
			}
		}
		_, _ = Read(bytes.NewReader(buf))
		_, _ = ReadPCAP(bytes.NewReader(buf))
		_, _ = ReadPCAPNG(bytes.NewReader(buf))
	}
}
