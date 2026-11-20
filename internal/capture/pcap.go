package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	pcapMagicBE     uint32 = 0xa1b2c3d4
	pcapMagicLE     uint32 = 0xd4c3b2a1
	pcapNanoMagicBE uint32 = 0xa1b23c4d
	pcapNanoMagicLE uint32 = 0x4d3cb2a1

	pcapGlobalHeaderLen = 24
	pcapPacketHeaderLen = 16
)

// ReadPCAP parses a classic libpcap stream (big-endian or little-endian, microsecond or nanosecond).
func ReadPCAP(r io.Reader) (*Capture, error) {
	var hdr [pcapGlobalHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrEmptyCapture
		}
		return nil, fmt.Errorf("%w: truncated pcap global header: %v", ErrCorruptCapture, err)
	}

	magicBE := binary.BigEndian.Uint32(hdr[0:4])
	var order binary.ByteOrder
	var nano bool

	switch magicBE {
	case pcapMagicBE:
		order = binary.BigEndian
	case pcapMagicLE:
		order = binary.LittleEndian
	case pcapNanoMagicBE:
		order = binary.BigEndian
		nano = true
	case pcapNanoMagicLE:
		order = binary.LittleEndian
		nano = true
	default:
		return nil, fmt.Errorf("%w: invalid pcap magic 0x%08x", ErrUnknownFormat, magicBE)
	}

	major := order.Uint16(hdr[4:6])
	minor := order.Uint16(hdr[6:8])
	if major != 2 {
		return nil, fmt.Errorf("%w: unsupported pcap version %d.%d", ErrCorruptCapture, major, minor)
	}

	snapLen := order.Uint32(hdr[16:20])
	linkRaw := order.Uint32(hdr[20:24])
	// Mask FCS bits in upper byte per libpcap linktype spec, preserving lower 28 bits.
	linkType := LinkType(linkRaw & 0x0fffffff)

	capOut := &Capture{
		Format:   FormatPCAP,
		SnapLen:  snapLen,
		LinkType: linkType,
		Interfaces: []InterfaceInfo{
			{
				ID:       0,
				LinkType: linkType,
				SnapLen:  snapLen,
			},
		},
	}

	var pktHdr [pcapPacketHeaderLen]byte
	for idx := 1; ; idx++ {
		_, err := io.ReadFull(r, pktHdr[:])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: packet %d truncated header: %v", ErrCorruptCapture, idx, err)
		}

		tsSec := order.Uint32(pktHdr[0:4])
		tsSub := order.Uint32(pktHdr[4:8])
		inclLen := order.Uint32(pktHdr[8:12])
		origLen := order.Uint32(pktHdr[12:16])

		if inclLen > MaxPacketSize {
			return nil, fmt.Errorf("%w: packet %d captured length %d exceeds max %d", ErrCorruptCapture, idx, inclLen, MaxPacketSize)
		}
		if nano {
			if tsSub >= 1_000_000_000 {
				return nil, fmt.Errorf("%w: packet %d invalid nanosecond timestamp %d", ErrCorruptCapture, idx, tsSub)
			}
		} else {
			if tsSub >= 1_000_000 {
				return nil, fmt.Errorf("%w: packet %d invalid microsecond timestamp %d", ErrCorruptCapture, idx, tsSub)
			}
		}

		data := make([]byte, inclLen)
		if inclLen > 0 {
			if _, err := io.ReadFull(r, data); err != nil {
				return nil, fmt.Errorf("%w: packet %d truncated payload (expected %d bytes): %v", ErrCorruptCapture, idx, inclLen, err)
			}
		}

		nsec := int64(tsSub)
		if !nano {
			nsec *= 1000
		}

		capOut.Packets = append(capOut.Packets, Packet{
			Index:       idx,
			Timestamp:   time.Unix(int64(tsSec), nsec).UTC(),
			CaptureLen:  inclLen,
			OrigLen:     origLen,
			LinkType:    linkType,
			InterfaceID: 0,
			Data:        data,
		})
	}

	return capOut, nil
}
