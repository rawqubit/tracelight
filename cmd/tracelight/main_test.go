package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDemoCommandOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"demo"}, &stdout, &stderr); err != nil {
		t.Fatalf("tracelight demo failed: %v (stderr: %s)", err, stderr.String())
	}
	out := stdout.String()

	required := []string{
		"synthetic-demo.pcap",
		"flows=3/3",
		"DNS",
		"TLS",
		"api.example.com",
		"h2,http/1.1",
		"HTTP",
		"internal.example.com",
		"13.40ms",
		"2.10ms",
	}
	for _, want := range required {
		if !strings.Contains(out, want) {
			t.Errorf("demo output missing %q:\n%s", want, out)
		}
	}
}

func TestFlowsAndPacketsCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"flows", "--color=always", "--filter", "proto==tls || proto==http", "../../testdata/sample.pcapng"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("tracelight flows failed: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "\x1b[") {
		t.Errorf("expected ANSI color codes with --color=always")
	}
	if !strings.Contains(out, "flows=2/3") || strings.Contains(out, "1.1.1.1:53") {
		t.Errorf("filter did not isolate TLS+HTTP flows:\n%s", out)
	}

	stdout.Reset()
	err = run([]string{"packets", "--hex", "-f", "retransmit==true", "../../testdata/sample.pcap"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("tracelight packets failed: %v", err)
	}
	pktOut := stdout.String()
	if !strings.Contains(pktOut, "[TCP Retransmission]") || !strings.Contains(pktOut, "0000  ") {
		t.Errorf("packets --hex output missing retransmission or hex dump:\n%s", pktOut)
	}
}
