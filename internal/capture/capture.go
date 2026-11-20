package capture

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

type Format string

const (
	FormatPCAP   Format = "pcap"
	FormatPCAPNG Format = "pcapng"
)

type LinkType uint32

const (
	LinkTypeNull     LinkType = 0
	LinkTypeEthernet LinkType = 1
	LinkTypeRawIP    LinkType = 101
	LinkTypeLinuxSLL LinkType = 113
	LinkTypeIPv4     LinkType = 228
	LinkTypeIPv6     LinkType = 229
)

func (l LinkType) String() string {
	switch l {
	case LinkTypeNull:
		return "Null/Loopback"
	case LinkTypeEthernet:
		return "Ethernet"
	case LinkTypeRawIP:
		return "RawIP"
	case LinkTypeLinuxSLL:
		return "LinuxSLL"
	case LinkTypeIPv4:
		return "IPv4"
	case LinkTypeIPv6:
		return "IPv6"
	default:
		return fmt.Sprintf("LinkType(%d)", uint32(l))
	}
}

const (
	MaxPacketSize = 16 * 1024 * 1024 // 16 MiB per packet cap
	MaxBlockSize  = 32 * 1024 * 1024 // 32 MiB per pcapng block cap
)

var (
	ErrEmptyCapture   = errors.New("capture: empty input")
	ErrUnknownFormat  = errors.New("capture: unrecognized magic bytes (expected pcap or pcapng)")
	ErrCorruptCapture = errors.New("capture: corrupt capture data")
)

type InterfaceInfo struct {
	ID          uint32
	LinkType    LinkType
	SnapLen     uint32
	Name        string
	Description string
	TSResol     byte // raw if_tsresol byte; 0 means default 10^-6 (6)
	HasTSResol  bool
	TSOffsetSec int64
}

type Packet struct {
	Index       int
	Timestamp   time.Time
	CaptureLen  uint32
	OrigLen     uint32
	LinkType    LinkType
	InterfaceID uint32
	Data        []byte
}

type Capture struct {
	Format     Format
	SnapLen    uint32
	LinkType   LinkType
	Interfaces []InterfaceInfo
	Packets    []Packet
}

// ReadFile opens and parses a pcap or pcapng file from disk.
func ReadFile(path string) (*Capture, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open capture %q: %w", path, err)
	}
	defer f.Close()
	return Read(f)
}

// Read auto-detects pcap vs pcapng from the stream magic bytes and parses all packets.
func Read(r io.Reader) (*Capture, error) {
	br := bufio.NewReaderSize(r, 64*1024)
	magicBytes, err := br.Peek(4)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrEmptyCapture
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("%w: truncated header (%d bytes)", ErrCorruptCapture, len(magicBytes))
		}
		return nil, fmt.Errorf("read capture magic: %w", err)
	}

	magicBE := binary.BigEndian.Uint32(magicBytes)
	switch magicBE {
	case pcapMagicBE, pcapMagicLE, pcapNanoMagicBE, pcapNanoMagicLE:
		return ReadPCAP(br)
	case pcapngSHBType:
		return ReadPCAPNG(br)
	default:
		return nil, fmt.Errorf("%w: 0x%08x", ErrUnknownFormat, magicBE)
	}
}
