package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rawqubit/tracelight/internal/capture"
	"github.com/rawqubit/tracelight/internal/demo"
	"github.com/rawqubit/tracelight/internal/filter"
	"github.com/rawqubit/tracelight/internal/flow"
	"github.com/rawqubit/tracelight/internal/term"
	"github.com/rawqubit/tracelight/internal/ui"
)

const usageText = `tracelight — offline pcap/pcapng reader, dissector, and flow inspector

Usage:
  tracelight demo [flags]                 Generate synthetic capture in memory and run pipeline
  tracelight flows [flags] <file>         Inspect bidirectional flows as a terminal table (or --ui)
  tracelight packets [flags] <file>       List decoded packets with optional hex+ASCII dump
  tracelight ui [--addr :8091] [file]     Launch local web UI (loads demo if no file is given)
  tracelight --ui :8091 <file|demo>       Shortcut to launch web UI directly

Common flags:
  -f, --filter <expr>   Filter expression (e.g. 'proto==tls && host contains example.com')
  --sort <field>        Sort flows by: start, bytes, packets, duration, rtt, proto, id
  --desc                Sort descending
  -n, --top <N>         Show top N flows (0 = all)
  --packets, -p         Also print packet timeline below flow table
  --hex                 Include hex+ASCII dump (packets command)
  --color <mode>        ANSI colors: auto, always, never (default: auto)
  --json                Output JSON instead of formatted table
  --ui <addr>           Start embedded web UI on address (e.g. :8091)
  -h, --help            Show help
`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "tracelight: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return errors.New("missing command (try 'tracelight demo' or 'tracelight flows <file>')")
	}

	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usageText)
		return nil
	case "demo":
		return runDemo(args[1:], stdout)
	case "flows":
		return runFlows(args[1:], stdout)
	case "packets":
		return runPackets(args[1:], stdout)
	case "ui":
		return runUI(args[1:], stdout)
	default:
		// Support root invocation like: tracelight --ui :8091 capture.pcap
		if strings.HasPrefix(args[0], "-") {
			return runRootFlags(args, stdout)
		}
		// Convenience: tracelight <file.pcap> defaults to flows
		if _, err := os.Stat(args[0]); err == nil {
			return runFlows(args, stdout)
		}
		fmt.Fprint(stderr, usageText)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runRootFlags(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("tracelight", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var uiAddr string
	var filterStr string
	var colorStr string
	fs.StringVar(&uiAddr, "ui", "", "web UI listen address")
	fs.StringVar(&filterStr, "filter", "", "filter expression")
	fs.StringVar(&filterStr, "f", "", "filter expression")
	fs.StringVar(&colorStr, "color", "auto", "color mode")
	if err := fs.Parse(reorderArgs(args, map[string]bool{"--ui": true, "-ui": true, "--filter": true, "-filter": true, "-f": true, "--color": true, "-color": true})); err != nil {
		return err
	}
	rest := fs.Args()
	if uiAddr != "" {
		if len(rest) == 0 || rest[0] == "demo" {
			return serveDemoUI(uiAddr, stdout)
		}
		return serveFileUI(uiAddr, rest[0], stdout)
	}
	if len(rest) == 0 {
		return errors.New("specify a command ('demo', 'flows <file>', 'packets <file>', 'ui') or --ui :8091")
	}
	if rest[0] == "demo" {
		return runDemo(nil, stdout)
	}
	return runFlows(args, stdout)
}

func runDemo(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var filterStr, sortField, colorStr, uiAddr string
	var desc, showPkts, asJSON bool
	var top int
	fs.StringVar(&filterStr, "filter", "", "filter expression")
	fs.StringVar(&filterStr, "f", "", "filter expression")
	fs.StringVar(&sortField, "sort", "start", "sort field")
	fs.BoolVar(&desc, "desc", false, "sort descending")
	fs.IntVar(&top, "top", 0, "limit top N flows")
	fs.IntVar(&top, "n", 0, "limit top N flows")
	fs.BoolVar(&showPkts, "packets", false, "print packet list")
	fs.BoolVar(&showPkts, "p", false, "print packet list")
	fs.StringVar(&colorStr, "color", "auto", "color mode")
	fs.BoolVar(&asJSON, "json", false, "output JSON")
	fs.StringVar(&uiAddr, "ui", "", "web UI listen address")

	valFlags := map[string]bool{"--filter": true, "-filter": true, "-f": true, "--sort": true, "-sort": true, "--top": true, "-top": true, "-n": true, "--color": true, "-color": true, "--ui": true, "-ui": true}
	if err := fs.Parse(reorderArgs(args, valFlags)); err != nil {
		return err
	}

	capData, res, err := demo.Run()
	if err != nil {
		return fmt.Errorf("demo pipeline failed: %w", err)
	}

	if uiAddr != "" {
		return startUIServer(uiAddr, "synthetic-demo.pcap", string(capData.Format), res, stdout)
	}

	return outputFlows(stdout, "synthetic-demo.pcap", capData, res, outputOpts{
		filterStr:   filterStr,
		sortField:   sortField,
		desc:        desc,
		top:         top,
		showPackets: showPkts,
		colorMode:   term.ColorMode(colorStr),
		asJSON:      asJSON,
	})
}

func runFlows(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("flows", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var filterStr, sortField, colorStr, uiAddr string
	var desc, showPkts, asJSON bool
	var top int
	fs.StringVar(&filterStr, "filter", "", "filter expression")
	fs.StringVar(&filterStr, "f", "", "filter expression")
	fs.StringVar(&sortField, "sort", "start", "sort field")
	fs.BoolVar(&desc, "desc", false, "sort descending")
	fs.IntVar(&top, "top", 0, "limit top N flows")
	fs.IntVar(&top, "n", 0, "limit top N flows")
	fs.BoolVar(&showPkts, "packets", false, "print packet list")
	fs.BoolVar(&showPkts, "p", false, "print packet list")
	fs.StringVar(&colorStr, "color", "auto", "color mode")
	fs.BoolVar(&asJSON, "json", false, "output JSON")
	fs.StringVar(&uiAddr, "ui", "", "web UI listen address")

	valFlags := map[string]bool{"--filter": true, "-filter": true, "-f": true, "--sort": true, "-sort": true, "--top": true, "-top": true, "-n": true, "--color": true, "-color": true, "--ui": true, "-ui": true}
	if err := fs.Parse(reorderArgs(args, valFlags)); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("flows requires a capture file path: tracelight flows <file.pcap|file.pcapng>")
	}
	path := fs.Arg(0)

	capData, err := capture.ReadFile(path)
	if err != nil {
		return err
	}
	res := flow.Assemble(capData)

	if uiAddr != "" {
		return startUIServer(uiAddr, path, string(capData.Format), res, stdout)
	}

	return outputFlows(stdout, path, capData, res, outputOpts{
		filterStr:   filterStr,
		sortField:   sortField,
		desc:        desc,
		top:         top,
		showPackets: showPkts,
		colorMode:   term.ColorMode(colorStr),
		asJSON:      asJSON,
	})
}

func runPackets(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("packets", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var filterStr, colorStr string
	var showHex bool
	var limit int
	fs.StringVar(&filterStr, "filter", "", "filter expression")
	fs.StringVar(&filterStr, "f", "", "filter expression")
	fs.BoolVar(&showHex, "hex", false, "include hex+ASCII dump")
	fs.StringVar(&colorStr, "color", "auto", "color mode")
	fs.IntVar(&limit, "limit", 0, "limit number of packets")
	fs.IntVar(&limit, "n", 0, "limit number of packets")

	valFlags := map[string]bool{"--filter": true, "-filter": true, "-f": true, "--color": true, "-color": true, "--limit": true, "-limit": true, "-n": true}
	if err := fs.Parse(reorderArgs(args, valFlags)); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("packets requires a capture file path: tracelight packets <file.pcap|file.pcapng>")
	}
	path := fs.Arg(0)

	var expr filter.Expr
	if strings.TrimSpace(filterStr) != "" {
		var err error
		expr, err = filter.Parse(filterStr)
		if err != nil {
			return err
		}
	}

	capData, err := capture.ReadFile(path)
	if err != nil {
		return err
	}
	res := flow.Assemble(capData)

	var pkts []flow.FlowPacket
	for _, p := range res.AllPackets {
		if expr == nil || expr.MatchPacket(p) {
			pkts = append(pkts, p)
		}
	}
	if limit > 0 && len(pkts) > limit {
		pkts = pkts[:limit]
	}

	useColor := shouldUseColor(term.ColorMode(colorStr), stdout)
	term.PrintPackets(stdout, pkts, useColor, showHex)
	return nil
}

func runUI(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var addr string
	fs.StringVar(&addr, "addr", ":8091", "listen address")
	fs.StringVar(&addr, "ui", ":8091", "listen address")
	valFlags := map[string]bool{"--addr": true, "-addr": true, "--ui": true, "-ui": true}
	if err := fs.Parse(reorderArgs(args, valFlags)); err != nil {
		return err
	}
	if fs.NArg() == 0 || fs.Arg(0) == "demo" {
		return serveDemoUI(addr, stdout)
	}
	return serveFileUI(addr, fs.Arg(0), stdout)
}

func serveDemoUI(addr string, stdout io.Writer) error {
	capData, res, err := demo.Run()
	if err != nil {
		return err
	}
	return startUIServer(addr, "synthetic-demo.pcap", string(capData.Format), res, stdout)
}

func serveFileUI(addr, path string, stdout io.Writer) error {
	capData, err := capture.ReadFile(path)
	if err != nil {
		return err
	}
	res := flow.Assemble(capData)
	return startUIServer(addr, path, string(capData.Format), res, stdout)
}

func startUIServer(addr, sourceName, format string, res *flow.Result, stdout io.Writer) error {
	srv := ui.NewServer(sourceName, format, res)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	displayAddr := ln.Addr().String()
	if strings.HasPrefix(addr, ":") {
		displayAddr = "http://127.0.0.1" + addr
	} else {
		displayAddr = "http://" + displayAddr
	}
	fmt.Fprintf(stdout, "tracelight UI listening on %s (source: %s, %d flows, %d packets)\n",
		displayAddr, sourceName, len(res.Flows), len(res.AllPackets))

	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case err := <-errCh:
		return err
	case <-sigCh:
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return httpSrv.Shutdown(ctx)
	}
}

type outputOpts struct {
	filterStr   string
	sortField   string
	desc        bool
	top         int
	showPackets bool
	colorMode   term.ColorMode
	asJSON      bool
}

func outputFlows(stdout io.Writer, source string, capData *capture.Capture, res *flow.Result, opts outputOpts) error {
	var expr filter.Expr
	if strings.TrimSpace(opts.filterStr) != "" {
		var err error
		expr, err = filter.Parse(opts.filterStr)
		if err != nil {
			return err
		}
	}

	matched := make([]*flow.Flow, 0, len(res.Flows))
	for _, fl := range res.Flows {
		if expr == nil || expr.MatchFlow(fl) {
			matched = append(matched, fl)
		}
	}
	flow.SortFlows(matched, opts.sortField, opts.desc)

	if opts.asJSON {
		type jsonFlow struct {
			ID              int      `json:"id"`
			Protocol        string   `json:"protocol"`
			Source          string   `json:"source"`
			Destination     string   `json:"destination"`
			Host            string   `json:"host,omitempty"`
			Info            string   `json:"info"`
			Packets         int      `json:"packets"`
			Bytes           int64    `json:"bytes"`
			DurationMS      float64  `json:"duration_ms"`
			RTTMS           *float64 `json:"rtt_ms,omitempty"`
			Retransmissions int      `json:"retransmissions"`
		}
		limit := matched
		if opts.top > 0 && len(limit) > opts.top {
			limit = limit[:opts.top]
		}
		out := make([]jsonFlow, 0, len(limit))
		for _, fl := range limit {
			var rttMS *float64
			if fl.HasRTT {
				v := float64(fl.RTTEstimate) / float64(time.Millisecond)
				rttMS = &v
			}
			out = append(out, jsonFlow{
				ID:              fl.ID,
				Protocol:        fl.Protocol,
				Source:          (flow.Endpoint{IP: fl.SrcIP, Port: fl.SrcPort}).String(),
				Destination:     (flow.Endpoint{IP: fl.DstIP, Port: fl.DstPort}).String(),
				Host:            fl.Host,
				Info:            fl.Info,
				Packets:         fl.PacketCount,
				Bytes:           fl.ByteCount,
				DurationMS:      float64(fl.Duration) / float64(time.Millisecond),
				RTTMS:           rttMS,
				Retransmissions: fl.Retransmissions,
			})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	useColor := shouldUseColor(opts.colorMode, stdout)
	summary := fmt.Sprintf("format=%s | packets=%d | flows=%d/%d | bytes=%d | span=%s",
		capData.Format, len(capData.Packets), len(matched), len(res.Flows), res.TotalBytes, res.Duration.Round(time.Microsecond))
	term.PrintFlowsTable(stdout, matched, term.TableOptions{
		Color:   useColor,
		Top:     opts.top,
		Title:   fmt.Sprintf("tracelight — %s", source),
		Summary: summary,
	})

	if opts.showPackets {
		fmt.Fprintln(stdout)
		var pkts []flow.FlowPacket
		for _, fl := range matched {
			pkts = append(pkts, fl.Packets...)
		}
		term.PrintPackets(stdout, pkts, useColor, false)
	}

	return nil
}

func shouldUseColor(mode term.ColorMode, stdout io.Writer) bool {
	if f, ok := stdout.(*os.File); ok {
		return term.ShouldColor(mode, f)
	}
	return mode == term.ColorAlways
}

// reorderArgs moves flags before positional arguments so flags work before or after file paths.
func reorderArgs(args []string, valueFlags map[string]bool) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && valueFlags[a] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}
