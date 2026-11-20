package term

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rawqubit/tracelight/internal/flow"
)

const (
	ansiReset   = "\x1b[0m"
	ansiBold    = "\x1b[1m"
	ansiDim     = "\x1b[2m"
	ansiRed     = "\x1b[31m"
	ansiGreen   = "\x1b[32m"
	ansiYellow  = "\x1b[33m"
	ansiBlue    = "\x1b[34m"
	ansiMagenta = "\x1b[35m"
	ansiCyan    = "\x1b[36m"
)

type ColorMode string

const (
	ColorAuto   ColorMode = "auto"
	ColorAlways ColorMode = "always"
	ColorNever  ColorMode = "never"
)

func ShouldColor(mode ColorMode, f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" && mode != ColorAlways {
		return false
	}
	switch mode {
	case ColorAlways:
		return true
	case ColorNever:
		return false
	default:
		if f == nil {
			return false
		}
		info, err := f.Stat()
		if err != nil {
			return false
		}
		return (info.Mode() & os.ModeCharDevice) != 0
	}
}

type TableOptions struct {
	Color   bool
	Top     int
	Title   string
	Summary string
}

func PrintFlowsTable(w io.Writer, flows []*flow.Flow, opts TableOptions) {
	if opts.Title != "" {
		if opts.Color {
			fmt.Fprintf(w, "%s%s%s\n", ansiBold, opts.Title, ansiReset)
		} else {
			fmt.Fprintln(w, opts.Title)
		}
	}
	if opts.Summary != "" {
		if opts.Color {
			fmt.Fprintf(w, "%s%s%s\n", ansiDim, opts.Summary, ansiReset)
		} else {
			fmt.Fprintln(w, opts.Summary)
		}
	}

	display := flows
	if opts.Top > 0 && len(display) > opts.Top {
		display = display[:opts.Top]
	}

	if len(display) == 0 {
		fmt.Fprintln(w, "No flows matched.")
		return
	}

	type row struct {
		id     string
		proto  string
		src    string
		dst    string
		info   string
		pkts   string
		bytes  string
		dur    string
		rtt    string
		retran string
		raw    *flow.Flow
	}

	headers := row{
		id:     "ID",
		proto:  "PROTO",
		src:    "SOURCE",
		dst:    "DESTINATION",
		info:   "HOST / INFO",
		pkts:   "PKTS",
		bytes:  "BYTES",
		dur:    "DURATION",
		rtt:    "RTT",
		retran: "RETR",
	}

	rows := make([]row, 0, len(display))
	for _, fl := range display {
		rtt := "-"
		if fl.HasRTT {
			rtt = formatDuration(fl.RTTEstimate)
		}
		info := fl.Info
		if fl.Host != "" && !strings.Contains(info, fl.Host) {
			info = fl.Host + " | " + info
		}
		if len(fl.ALPN) > 0 && !strings.Contains(info, "alpn=") {
			info += " alpn=" + strings.Join(fl.ALPN, ",")
		}
		info = truncate(info, 62)

		rows = append(rows, row{
			id:     fmt.Sprintf("%d", fl.ID),
			proto:  strings.ToUpper(fl.Protocol),
			src:    (flow.Endpoint{IP: fl.SrcIP, Port: fl.SrcPort}).String(),
			dst:    (flow.Endpoint{IP: fl.DstIP, Port: fl.DstPort}).String(),
			info:   info,
			pkts:   fmt.Sprintf("%d", fl.PacketCount),
			bytes:  formatBytes(fl.ByteCount),
			dur:    formatDuration(fl.Duration),
			rtt:    rtt,
			retran: fmt.Sprintf("%d", fl.Retransmissions),
			raw:    fl,
		})
	}

	widths := [10]int{
		len(headers.id), len(headers.proto), len(headers.src), len(headers.dst),
		len(headers.info), len(headers.pkts), len(headers.bytes), len(headers.dur),
		len(headers.rtt), len(headers.retran),
	}
	for _, r := range rows {
		cols := [10]string{r.id, r.proto, r.src, r.dst, r.info, r.pkts, r.bytes, r.dur, r.rtt, r.retran}
		for i, c := range cols {
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}

	printHeader := func() {
		line := fmt.Sprintf(
			"%-*s  %-*s  %-*s  %-*s  %-*s  %*s  %*s  %*s  %*s  %*s",
			widths[0], headers.id,
			widths[1], headers.proto,
			widths[2], headers.src,
			widths[3], headers.dst,
			widths[4], headers.info,
			widths[5], headers.pkts,
			widths[6], headers.bytes,
			widths[7], headers.dur,
			widths[8], headers.rtt,
			widths[9], headers.retran,
		)
		if opts.Color {
			fmt.Fprintf(w, "%s%s%s\n", ansiBold+ansiDim, line, ansiReset)
		} else {
			fmt.Fprintln(w, line)
		}
		totalW := 0
		for _, cw := range widths {
			totalW += cw
		}
		totalW += 18 // 9 * 2 spaces
		sep := strings.Repeat("-", totalW)
		if opts.Color {
			fmt.Fprintf(w, "%s%s%s\n", ansiDim, sep, ansiReset)
		} else {
			fmt.Fprintln(w, sep)
		}
	}

	printHeader()
	for _, r := range rows {
		protoCell := padRight(r.proto, widths[1])
		retrCell := padLeft(r.retran, widths[9])
		if opts.Color {
			protoCell = colorizeProto(r.raw.Protocol, protoCell)
			if r.raw.Retransmissions > 0 {
				retrCell = ansiRed + ansiBold + retrCell + ansiReset
			}
		}
		fmt.Fprintf(
			w,
			"%s  %s  %s  %s  %s  %s  %s  %s  %s  %s\n",
			padRight(r.id, widths[0]),
			protoCell,
			padRight(r.src, widths[2]),
			padRight(r.dst, widths[3]),
			padRight(r.info, widths[4]),
			padLeft(r.pkts, widths[5]),
			padLeft(r.bytes, widths[6]),
			padLeft(r.dur, widths[7]),
			padLeft(r.rtt, widths[8]),
			retrCell,
		)
	}
}

func PrintPackets(w io.Writer, packets []flow.FlowPacket, useColor bool, showHex bool) {
	for _, pkt := range packets {
		proto := "unknown"
		if pkt.Decoded != nil {
			proto = strings.ToUpper(pkt.Decoded.Protocol())
		}
		rel := formatDuration(pkt.RelCapture)
		line := fmt.Sprintf("#%-4d +%-9s %-4s %-4s %4dB  %s",
			pkt.PacketIndex, rel, pkt.Direction.Arrow(), proto, pkt.Length, pkt.Summary)
		if useColor {
			if pkt.IsRetransmit {
				fmt.Fprintf(w, "%s%s%s\n", ansiRed, line, ansiReset)
			} else {
				fmt.Fprintf(w, "%s#%-4d%s +%-9s %-4s %s %-4dB  %s\n",
					ansiDim, pkt.PacketIndex, ansiReset, rel, pkt.Direction.Arrow(),
					colorizeProto(strings.ToLower(proto), fmt.Sprintf("%-4s", proto)), pkt.Length, pkt.Summary)
			}
		} else {
			fmt.Fprintln(w, line)
		}
		if showHex && len(pkt.Raw) > 0 {
			fmt.Fprintln(w, HexDump(pkt.Raw))
		}
	}
}

func HexDump(data []byte) string {
	var b strings.Builder
	for off := 0; off < len(data); off += 16 {
		end := off + 16
		if end > len(data) {
			end = len(data)
		}
		chunk := data[off:end]
		fmt.Fprintf(&b, "  %04x  ", off)
		for i := 0; i < 16; i++ {
			if i == 8 {
				b.WriteByte(' ')
			}
			if i < len(chunk) {
				fmt.Fprintf(&b, "%02x ", chunk[i])
			} else {
				b.WriteString("   ")
			}
		}
		b.WriteString(" |")
		for _, c := range chunk {
			if c >= 0x20 && c <= 0x7e {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteString("|\n")
	}
	return b.String()
}

func colorizeProto(proto, text string) string {
	switch strings.ToLower(proto) {
	case "tls":
		return ansiMagenta + text + ansiReset
	case "http":
		return ansiGreen + text + ansiReset
	case "dns":
		return ansiCyan + text + ansiReset
	case "tcp":
		return ansiBlue + text + ansiReset
	case "udp":
		return ansiYellow + text + ansiReset
	case "icmp":
		return ansiRed + text + ansiReset
	default:
		return text
	}
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

func padLeft(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return strings.Repeat(" ", width-len(s)) + s
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func formatBytes(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	}
}

func formatDuration(d time.Duration) string {
	if d == 0 {
		return "0ms"
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%.0fus", float64(d)/float64(time.Microsecond))
	}
	if d < time.Second {
		return fmt.Sprintf("%.2fms", float64(d)/float64(time.Millisecond))
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}
