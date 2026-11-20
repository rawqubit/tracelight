package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"
)

const (
	pcapngSHBType        uint32 = 0x0a0d0d0a
	pcapngIDBType        uint32 = 0x00000001
	pcapngObsoletePktTyp uint32 = 0x00000002
	pcapngSPBType        uint32 = 0x00000003
	pcapngEPBType        uint32 = 0x00000006

	pcapngByteOrderMagic uint32 = 0x1a2b3c4d

	optEndOfOpt      uint16 = 0
	optIFName        uint16 = 2
	optIFDescription uint16 = 3
	optIFTSResol     uint16 = 9
	optIFTSOffset    uint16 = 14
)

// ReadPCAPNG parses a pcapng stream supporting SHB, IDB (with if_tsresol/if_tsoffset),
// Enhanced Packet Blocks, Simple Packet Blocks, and Obsolete Packet Blocks.
func ReadPCAPNG(r io.Reader) (*Capture, error) {
	capOut := &Capture{
		Format: FormatPCAPNG,
	}

	var order binary.ByteOrder
	var interfaces []InterfaceInfo
	pktIdx := 0
	offset := int64(0)

	for blockNum := 1; ; blockNum++ {
		var hdr8 [8]byte
		_, err := io.ReadFull(r, hdr8[:])
		if errors.Is(err, io.EOF) {
			if blockNum == 1 {
				return nil, ErrEmptyCapture
			}
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: block %d at offset %d truncated header: %v", ErrCorruptCapture, blockNum, offset, err)
		}

		// SHB (0x0a0d0d0a) is palindromic; inspect byte-order magic before interpreting length.
		rawTypeBE := binary.BigEndian.Uint32(hdr8[0:4])
		if rawTypeBE == pcapngSHBType {
			var bom [4]byte
			if _, err := io.ReadFull(r, bom[:]); err != nil {
				return nil, fmt.Errorf("%w: SHB at offset %d truncated byte-order magic: %v", ErrCorruptCapture, offset, err)
			}

			switch {
			case binary.LittleEndian.Uint32(bom[:]) == pcapngByteOrderMagic:
				order = binary.LittleEndian
			case binary.BigEndian.Uint32(bom[:]) == pcapngByteOrderMagic:
				order = binary.BigEndian
			default:
				return nil, fmt.Errorf("%w: SHB at offset %d invalid byte-order magic 0x%08x", ErrCorruptCapture, offset, binary.BigEndian.Uint32(bom[:]))
			}

			totalLen := order.Uint32(hdr8[4:8])
			if totalLen < 28 || totalLen%4 != 0 || totalLen > MaxBlockSize {
				return nil, fmt.Errorf("%w: SHB at offset %d invalid length %d", ErrCorruptCapture, offset, totalLen)
			}

			rem := make([]byte, totalLen-12)
			if _, err := io.ReadFull(r, rem); err != nil {
				return nil, fmt.Errorf("%w: SHB at offset %d truncated body: %v", ErrCorruptCapture, offset, err)
			}

			trailingLen := order.Uint32(rem[len(rem)-4:])
			if trailingLen != totalLen {
				return nil, fmt.Errorf("%w: SHB at offset %d trailing length %d != leading length %d", ErrCorruptCapture, offset, trailingLen, totalLen)
			}

			major := order.Uint16(rem[0:2])
			if major != 1 {
				return nil, fmt.Errorf("%w: SHB at offset %d unsupported version %d.%d", ErrCorruptCapture, offset, major, order.Uint16(rem[2:4]))
			}

			// Each new Section Header Block resets section interface table.
			interfaces = nil
			offset += int64(totalLen)
			continue
		}

		if order == nil {
			return nil, fmt.Errorf("%w: expected Section Header Block first, got block type 0x%08x", ErrCorruptCapture, rawTypeBE)
		}

		blockType := order.Uint32(hdr8[0:4])
		totalLen := order.Uint32(hdr8[4:8])
		if totalLen < 12 || totalLen%4 != 0 || totalLen > MaxBlockSize {
			return nil, fmt.Errorf("%w: block %d (0x%08x) at offset %d invalid length %d", ErrCorruptCapture, blockNum, blockType, offset, totalLen)
		}

		bodyAndTrail := make([]byte, totalLen-8)
		if _, err := io.ReadFull(r, bodyAndTrail); err != nil {
			return nil, fmt.Errorf("%w: block %d (0x%08x) at offset %d truncated: %v", ErrCorruptCapture, blockNum, blockType, offset, err)
		}

		trailingLen := order.Uint32(bodyAndTrail[len(bodyAndTrail)-4:])
		if trailingLen != totalLen {
			return nil, fmt.Errorf("%w: block %d (0x%08x) at offset %d trailing length %d != leading length %d", ErrCorruptCapture, blockNum, blockType, offset, trailingLen, totalLen)
		}

		body := bodyAndTrail[:len(bodyAndTrail)-4]

		switch blockType {
		case pcapngIDBType:
			iface, err := parseIDB(body, order, uint32(len(interfaces)))
			if err != nil {
				return nil, fmt.Errorf("%w: IDB at offset %d: %v", ErrCorruptCapture, offset, err)
			}
			interfaces = append(interfaces, iface)
			capOut.Interfaces = append(capOut.Interfaces, iface)
			if len(capOut.Interfaces) == 1 {
				capOut.LinkType = iface.LinkType
				capOut.SnapLen = iface.SnapLen
			}

		case pcapngEPBType:
			pktIdx++
			pkt, err := parseEPB(body, order, interfaces, pktIdx)
			if err != nil {
				return nil, fmt.Errorf("%w: EPB at offset %d: %v", ErrCorruptCapture, offset, err)
			}
			capOut.Packets = append(capOut.Packets, pkt)

		case pcapngSPBType:
			pktIdx++
			pkt, err := parseSPB(body, order, interfaces, pktIdx)
			if err != nil {
				return nil, fmt.Errorf("%w: SPB at offset %d: %v", ErrCorruptCapture, offset, err)
			}
			capOut.Packets = append(capOut.Packets, pkt)

		case pcapngObsoletePktTyp:
			pktIdx++
			pkt, err := parseObsoletePacketBlock(body, order, interfaces, pktIdx)
			if err != nil {
				return nil, fmt.Errorf("%w: obsolete packet block at offset %d: %v", ErrCorruptCapture, offset, err)
			}
			capOut.Packets = append(capOut.Packets, pkt)

		default:
			// Unknown or metadata block (e.g., Interface Statistics, Name Resolution, Decryption Secrets); skip safely.
		}

		offset += int64(totalLen)
	}

	return capOut, nil
}

func parseIDB(body []byte, order binary.ByteOrder, id uint32) (InterfaceInfo, error) {
	if len(body) < 8 {
		return InterfaceInfo{}, fmt.Errorf("body length %d < 8", len(body))
	}
	linkType := LinkType(order.Uint16(body[0:2]))
	snapLen := order.Uint32(body[4:8])

	info := InterfaceInfo{
		ID:       id,
		LinkType: linkType,
		SnapLen:  snapLen,
	}

	opts := body[8:]
	for len(opts) >= 4 {
		code := order.Uint16(opts[0:2])
		optLen := int(order.Uint16(opts[2:4]))
		opts = opts[4:]
		if code == optEndOfOpt {
			break
		}
		padded := (optLen + 3) &^ 3
		if padded > len(opts) {
			return InterfaceInfo{}, fmt.Errorf("option %d length %d exceeds remaining bytes %d", code, optLen, len(opts))
		}
		val := opts[:optLen]
		switch code {
		case optIFName:
			info.Name = string(val)
		case optIFDescription:
			info.Description = string(val)
		case optIFTSResol:
			if len(val) != 1 {
				return InterfaceInfo{}, fmt.Errorf("if_tsresol length %d != 1", len(val))
			}
			info.TSResol = val[0]
			info.HasTSResol = true
		case optIFTSOffset:
			if len(val) != 8 {
				return InterfaceInfo{}, fmt.Errorf("if_tsoffset length %d != 8", len(val))
			}
			info.TSOffsetSec = int64(order.Uint64(val))
		}
		opts = opts[padded:]
	}
	if len(opts) != 0 && len(opts) < 4 {
		return InterfaceInfo{}, fmt.Errorf("trailing %d option bytes", len(opts))
	}

	return info, nil
}

func parseEPB(body []byte, order binary.ByteOrder, interfaces []InterfaceInfo, idx int) (Packet, error) {
	if len(body) < 20 {
		return Packet{}, fmt.Errorf("body length %d < 20", len(body))
	}
	ifaceID := order.Uint32(body[0:4])
	if int(ifaceID) >= len(interfaces) {
		return Packet{}, fmt.Errorf("interface id %d out of range (%d interfaces)", ifaceID, len(interfaces))
	}
	iface := interfaces[ifaceID]

	tsHigh := order.Uint32(body[4:8])
	tsLow := order.Uint32(body[8:12])
	capLen := order.Uint32(body[12:16])
	origLen := order.Uint32(body[16:20])

	if capLen > MaxPacketSize {
		return Packet{}, fmt.Errorf("captured length %d exceeds max %d", capLen, MaxPacketSize)
	}
	if int(capLen) > len(body)-20 {
		return Packet{}, fmt.Errorf("captured length %d exceeds block payload %d", capLen, len(body)-20)
	}

	data := make([]byte, capLen)
	copy(data, body[20:20+int(capLen)])

	tsRaw := (uint64(tsHigh) << 32) | uint64(tsLow)
	ts := decodePCAPNGTimestamp(tsRaw, iface)

	return Packet{
		Index:       idx,
		Timestamp:   ts,
		CaptureLen:  capLen,
		OrigLen:     origLen,
		LinkType:    iface.LinkType,
		InterfaceID: ifaceID,
		Data:        data,
	}, nil
}

func parseSPB(body []byte, order binary.ByteOrder, interfaces []InterfaceInfo, idx int) (Packet, error) {
	if len(body) < 4 {
		return Packet{}, fmt.Errorf("body length %d < 4", len(body))
	}
	if len(interfaces) == 0 {
		return Packet{}, errors.New("no Interface Description Block defined before Simple Packet Block")
	}
	iface := interfaces[0]
	origLen := order.Uint32(body[0:4])
	avail := uint32(len(body) - 4)
	capLen := origLen
	if iface.SnapLen > 0 && capLen > iface.SnapLen {
		capLen = iface.SnapLen
	}
	if capLen > avail {
		capLen = avail
	}
	if capLen > MaxPacketSize {
		return Packet{}, fmt.Errorf("captured length %d exceeds max %d", capLen, MaxPacketSize)
	}

	data := make([]byte, capLen)
	copy(data, body[4:4+int(capLen)])

	return Packet{
		Index:       idx,
		Timestamp:   time.Time{},
		CaptureLen:  capLen,
		OrigLen:     origLen,
		LinkType:    iface.LinkType,
		InterfaceID: 0,
		Data:        data,
	}, nil
}

func parseObsoletePacketBlock(body []byte, order binary.ByteOrder, interfaces []InterfaceInfo, idx int) (Packet, error) {
	if len(body) < 20 {
		return Packet{}, fmt.Errorf("body length %d < 20", len(body))
	}
	ifaceID := uint32(order.Uint16(body[0:2]))
	if int(ifaceID) >= len(interfaces) {
		return Packet{}, fmt.Errorf("interface id %d out of range (%d interfaces)", ifaceID, len(interfaces))
	}
	iface := interfaces[ifaceID]
	tsHigh := order.Uint32(body[4:8])
	tsLow := order.Uint32(body[8:12])
	capLen := order.Uint32(body[12:16])
	origLen := order.Uint32(body[16:20])

	if capLen > MaxPacketSize || int(capLen) > len(body)-20 {
		return Packet{}, fmt.Errorf("invalid captured length %d", capLen)
	}
	data := make([]byte, capLen)
	copy(data, body[20:20+int(capLen)])
	tsRaw := (uint64(tsHigh) << 32) | uint64(tsLow)
	return Packet{
		Index:       idx,
		Timestamp:   decodePCAPNGTimestamp(tsRaw, iface),
		CaptureLen:  capLen,
		OrigLen:     origLen,
		LinkType:    iface.LinkType,
		InterfaceID: ifaceID,
		Data:        data,
	}, nil
}

func decodePCAPNGTimestamp(raw uint64, iface InterfaceInfo) time.Time {
	resol := byte(6) // default 10^-6 (microseconds)
	if iface.HasTSResol {
		resol = iface.TSResol
	}

	if (resol & 0x80) == 0 {
		exp := int(resol)
		if exp > 18 {
			exp = 18
		}
		// unitsPerSec = 10^exp
		var unitsPerSec uint64 = 1
		for i := 0; i < exp; i++ {
			unitsPerSec *= 10
		}
		sec := raw / unitsPerSec
		rem := raw % unitsPerSec
		var nsec uint64
		if exp <= 9 {
			scale := uint64(1)
			for i := exp; i < 9; i++ {
				scale *= 10
			}
			nsec = rem * scale
		} else {
			scale := uint64(1)
			for i := 9; i < exp; i++ {
				scale *= 10
			}
			nsec = rem / scale
		}
		return time.Unix(int64(sec)+iface.TSOffsetSec, int64(nsec)).UTC()
	}

	// Binary exponent: 2^-(resol & 0x7f) seconds
	binExp := uint(resol & 0x7f)
	if binExp > 63 {
		binExp = 63
	}
	sec := raw >> binExp
	mask := (uint64(1) << binExp) - 1
	frac := raw & mask
	// nsec = (frac * 1e9) >> binExp using math/big to avoid uint64 overflow
	num := new(big.Int).SetUint64(frac)
	num.Mul(num, big.NewInt(1_000_000_000))
	num.Rsh(num, binExp)
	return time.Unix(int64(sec)+iface.TSOffsetSec, num.Int64()).UTC()
}
