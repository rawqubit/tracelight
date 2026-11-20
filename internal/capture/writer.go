package capture

import (
	"encoding/binary"
	"fmt"
	"io"
)

// WritePCAP writes packets in standard little-endian microsecond pcap format.
func WritePCAP(w io.Writer, packets []Packet, linkType LinkType, snapLen uint32) error {
	if snapLen == 0 {
		snapLen = 65535
	}
	var gh [pcapGlobalHeaderLen]byte
	binary.LittleEndian.PutUint32(gh[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(gh[4:6], 2)
	binary.LittleEndian.PutUint16(gh[6:8], 4)
	binary.LittleEndian.PutUint32(gh[16:20], snapLen)
	binary.LittleEndian.PutUint32(gh[20:24], uint32(linkType))
	if _, err := w.Write(gh[:]); err != nil {
		return fmt.Errorf("write pcap global header: %w", err)
	}

	var ph [pcapPacketHeaderLen]byte
	for _, p := range packets {
		sec := uint32(p.Timestamp.Unix())
		usec := uint32(p.Timestamp.Nanosecond() / 1000)
		inclLen := uint32(len(p.Data))
		origLen := p.OrigLen
		if origLen < inclLen {
			origLen = inclLen
		}
		binary.LittleEndian.PutUint32(ph[0:4], sec)
		binary.LittleEndian.PutUint32(ph[4:8], usec)
		binary.LittleEndian.PutUint32(ph[8:12], inclLen)
		binary.LittleEndian.PutUint32(ph[12:16], origLen)
		if _, err := w.Write(ph[:]); err != nil {
			return fmt.Errorf("write pcap packet header: %w", err)
		}
		if _, err := w.Write(p.Data); err != nil {
			return fmt.Errorf("write pcap packet data: %w", err)
		}
	}
	return nil
}

// WritePCAPNG writes packets in little-endian pcapng format (SHB + IDB + EPBs) with nanosecond resolution.
func WritePCAPNG(w io.Writer, packets []Packet, linkType LinkType, snapLen uint32) error {
	if snapLen == 0 {
		snapLen = 65535
	}
	// SHB (28 bytes)
	var shb [28]byte
	binary.LittleEndian.PutUint32(shb[0:4], pcapngSHBType)
	binary.LittleEndian.PutUint32(shb[4:8], 28)
	binary.LittleEndian.PutUint32(shb[8:12], pcapngByteOrderMagic)
	binary.LittleEndian.PutUint16(shb[12:14], 1) // major
	binary.LittleEndian.PutUint16(shb[14:16], 0) // minor
	binary.LittleEndian.PutUint64(shb[16:24], ^uint64(0))
	binary.LittleEndian.PutUint32(shb[24:28], 28)
	if _, err := w.Write(shb[:]); err != nil {
		return fmt.Errorf("write pcapng SHB: %w", err)
	}

	// IDB with if_tsresol=9 (nanoseconds): 20 bytes base + 8 bytes option + 4 bytes endofopt = 32 bytes
	var idb [32]byte
	binary.LittleEndian.PutUint32(idb[0:4], pcapngIDBType)
	binary.LittleEndian.PutUint32(idb[4:8], 32)
	binary.LittleEndian.PutUint16(idb[8:10], uint16(linkType))
	binary.LittleEndian.PutUint16(idb[10:12], 0)
	binary.LittleEndian.PutUint32(idb[12:16], snapLen)
	binary.LittleEndian.PutUint16(idb[16:18], optIFTSResol)
	binary.LittleEndian.PutUint16(idb[18:20], 1)
	idb[20] = 9 // 10^-9s
	binary.LittleEndian.PutUint16(idb[24:26], optEndOfOpt)
	binary.LittleEndian.PutUint16(idb[26:28], 0)
	binary.LittleEndian.PutUint32(idb[28:32], 32)
	if _, err := w.Write(idb[:]); err != nil {
		return fmt.Errorf("write pcapng IDB: %w", err)
	}

	for _, p := range packets {
		capLen := len(p.Data)
		origLen := int(p.OrigLen)
		if origLen < capLen {
			origLen = capLen
		}
		paddedData := (capLen + 3) &^ 3
		totalLen := 32 + paddedData
		buf := make([]byte, totalLen)
		binary.LittleEndian.PutUint32(buf[0:4], pcapngEPBType)
		binary.LittleEndian.PutUint32(buf[4:8], uint32(totalLen))
		binary.LittleEndian.PutUint32(buf[8:12], 0) // interface id
		ns := uint64(p.Timestamp.UnixNano())
		binary.LittleEndian.PutUint32(buf[12:16], uint32(ns>>32))
		binary.LittleEndian.PutUint32(buf[16:20], uint32(ns))
		binary.LittleEndian.PutUint32(buf[20:24], uint32(capLen))
		binary.LittleEndian.PutUint32(buf[24:28], uint32(origLen))
		copy(buf[28:28+capLen], p.Data)
		binary.LittleEndian.PutUint32(buf[totalLen-4:totalLen], uint32(totalLen))
		if _, err := w.Write(buf); err != nil {
			return fmt.Errorf("write pcapng EPB: %w", err)
		}
	}
	return nil
}
