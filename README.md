# tracelight

[![CI](https://github.com/rawqubit/tracelight/actions/workflows/ci.yml/badge.svg)](https://github.com/rawqubit/tracelight/actions/workflows/ci.yml) [![release](https://img.shields.io/github/v/release/rawqubit/tracelight?color=ffa53d)](https://github.com/rawqubit/tracelight/releases) [![license](https://img.shields.io/badge/license-MIT-56d3a6)](https://github.com/rawqubit/tracelight/blob/main/LICENSE)

A pure-Go, zero-dependency packet capture reader and flow inspector for `.pcap` and `.pcapng` files.

**What it is and is not:** `tracelight` is a fast offline reader, dissector, and inspector for saved capture files. It is **not** a live packet sniffer (no `libpcap`, no `AF_PACKET`, no cgo, no promiscuous interface capture).

## Install in one line

Prebuilt binaries for Linux, macOS and Windows on amd64 and arm64 — no Go toolchain needed:

```bash
curl -L https://github.com/rawqubit/tracelight/releases/download/v0.1.0/tracelight_v0.1.0_linux_amd64.tar.gz | tar -xz
./tracelight demo
```

macOS: swap `linux_amd64` for `darwin_arm64` (or `darwin_amd64`). Windows: take the `.zip` from [releases](https://github.com/rawqubit/tracelight/releases) and run `tracelight.exe`. Every archive has a SHA-256 in `checksums.txt`. Building from source is one `go build`, and it always works — but it should not be the first thing you have to do.

## Supported Formats and Protocols

**Capture formats**
- Classic `pcap`: little-endian and big-endian, microsecond (`0xa1b2c3d4` / `0xd4c3b2a1`) and nanosecond (`0xa1b23c4d` / `0x4d3cb2a1`) timestamps
- `pcapng`: Section Header Blocks (little-endian and big-endian, multi-section), Interface Description Blocks (with `if_tsresol` decimal/binary resolutions and `if_tsoffset`), Enhanced Packet Blocks, Simple Packet Blocks, and Obsolete Packet Blocks (unknown metadata blocks are skipped cleanly)

**Dissectors**
- **Link layer:** Ethernet II (including stacked 802.1Q and 802.1ad QinQ VLAN tags), Raw IP, BSD Null/Loopback, Linux SLL
- **Network layer:** IPv4 (including options), IPv6 (including Hop-by-Hop, Routing, Fragment, AH, and Destination Options extension headers), ICMP, ICMPv6
- **Transport layer:** TCP (flags, seq/ack, window, options, retransmission detection, handshake RTT estimate) and UDP
- **Application layer:**
  - **DNS** (UDP/TCP port 53, mDNS 5353): query and answer names/types with loop-safe compression pointer decoding
  - **HTTP/1.1:** request line, response status line, headers, and body slice
  - **TLS ClientHello (and record classification):** extracts SNI, effective version (via `supported_versions` extension for TLS 1.3), offered ALPN protocols, and cipher suites

**Not supported (out of scope)**
- Live interface capture (`tcpdump` / `dumpcap` / `tshark` handle capture; `tracelight` inspects the saved file)
- TLS decryption / keylog NSS files, HTTP/2 or QUIC / HTTP/3 framing, TCP stream reassembly across segmented multi-packet HTTP bodies, or IP fragmentation reassembly
- Routing/switching control-plane dissectors beyond basic ARP framing (no BGP, OSPF, STP, SMB, gRPC)

## Install

Requires Go 1.23+ (`CGO_ENABLED=0` supported; zero third-party dependencies):

```sh
git clone https://github.com/rawqubit/tracelight.git
cd tracelight
CGO_ENABLED=0 go build ./cmd/tracelight
```

Or install directly:

```sh
CGO_ENABLED=0 go install github.com/rawqubit/tracelight/cmd/tracelight@latest
```

## Usage

### Run the built-in demo

`tracelight demo` builds a synthetic pcap capture in memory (a DNS query/response, a TLS 1.3 handshake with SNI and ALPN, an HTTP/1.1 request/response, and a TCP retransmission) and runs the full capture -> dissect -> flow pipeline headlessly:

```sh
tracelight demo
```

Real output:

```text
tracelight — synthetic-demo.pcap
format=pcap | packets=16 | flows=3/3 | bytes=1473 | span=105.2ms
ID  PROTO  SOURCE           DESTINATION        HOST / INFO                                                 PKTS  BYTES  DURATION      RTT  RETR
-----------------------------------------------------------------------------------------------------------------------------------------------
1   DNS    10.0.1.42:54321  1.1.1.1:53         DNS query #18971 A api.example.com                             2  166 B    4.20ms        -     0
2   TLS    10.0.1.42:51820  93.184.216.34:443  TLS 1.3 ClientHello sni=api.example.com alpn=[h2,http/1.1]     7  599 B   43.00ms  13.40ms     0
3   HTTP   10.0.1.42:51900  10.0.2.15:8080     HTTP GET internal.example.com/v1/health                        7  708 B   55.20ms   2.10ms     1
```

### Inspect flows in a capture file

```sh
tracelight flows capture.pcap
tracelight flows --filter "proto==tls && host contains example.com" --sort bytes --desc capture.pcapng
tracelight flows -p --color=always testdata/sample.pcapng
tracelight packets --hex -f "retransmit==true" testdata/sample.pcap
```

### Launch the local Web UI

```sh
tracelight --ui :8091 capture.pcap
# or inspect the synthetic demo in the browser:
tracelight demo --ui :8091
```

The embedded single-page app serves on `http://127.0.0.1:8091` with zero external assets or CDNs. It provides:
- A sortable, filterable bidirectional flow table
- A per-flow waterfall timeline with relative timestamps and directional arrows (`->` / `<-`)
- A packet list and structured layer inspector
- A 16-byte hex + ASCII payload pane (toggleable between raw frame bytes and application payload)

### Filter Language

Filters are parsed by a recursive-descent parser with standard boolean precedence (`!` / `NOT` > `&&` / `AND` > `||` / `OR`) and parentheses:

- `ip==1.2.3.4`, `src.ip==10.0.1.0/24`, `dst.ip!=1.1.1.1`
- `port==443`, `src.port>1024`, `dst.port==8080`
- `proto==tls`, `proto==http`, `proto==dns`
- `host contains example.com`, `sni==api.example.com`, `dns contains example`
- `http.method==GET`, `http.status==200`, `vlan==100`, `retransmit==true`, `bytes>=500`
- Combined expressions: `(proto==tls || proto==http) && host contains example.com && !retransmit==true`

## Tests

```sh
CGO_ENABLED=0 go test -v ./...
go test -race ./...
```

The test suite covers classic `pcap` and `pcapng` parsing (synthetic bytes and checked-in fixtures in `testdata/`), corrupt input rejection, every protocol dissector, bidirectional flow assembly, RTT and retransmission tracking, recursive-descent filter precedence and syntax errors, web UI API endpoints, the `demo` command, and 2,000-iteration fuzz-style no-panic tests across the capture, dissector, and filter parsers.

## License

MIT — Copyright (c) 2026 Srinikhil Chakilam
