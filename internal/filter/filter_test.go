package filter

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/rawqubit/tracelight/internal/dissect"
	"github.com/rawqubit/tracelight/internal/flow"
)

func sampleFlows() []*flow.Flow {
	tlsFlow := &flow.Flow{
		ID:       1,
		SrcIP:    netip.MustParseAddr("10.0.1.42"),
		SrcPort:  51820,
		DstIP:    netip.MustParseAddr("1.2.3.4"),
		DstPort:  443,
		Protocol: "tls",
		L4Proto:  "tcp",
		Host:     "api.example.com",
		Packets: []flow.FlowPacket{
			{
				PacketIndex: 1,
				Length:      180,
				Decoded: &dissect.DecodedPacket{
					SrcIP:    netip.MustParseAddr("10.0.1.42"),
					DstIP:    netip.MustParseAddr("1.2.3.4"),
					HasIP:    true,
					SrcPort:  51820,
					DstPort:  443,
					HasPorts: true,
					L4Proto:  "tcp",
					AppProto: "tls",
					Host:     "api.example.com",
					TLS:      &dissect.TLSLayer{SNI: "api.example.com", IsClientHello: true},
				},
			},
		},
	}

	httpFlow := &flow.Flow{
		ID:              2,
		SrcIP:           netip.MustParseAddr("10.0.1.42"),
		SrcPort:         51900,
		DstIP:           netip.MustParseAddr("10.0.2.15"),
		DstPort:         8080,
		Protocol:        "http",
		L4Proto:         "tcp",
		Host:            "internal.example.com",
		Retransmissions: 1,
		ByteCount:       708,
	}

	dnsFlow := &flow.Flow{
		ID:       3,
		SrcIP:    netip.MustParseAddr("10.0.1.42"),
		SrcPort:  54321,
		DstIP:    netip.MustParseAddr("1.1.1.1"),
		DstPort:  53,
		Protocol: "dns",
		L4Proto:  "udp",
		Host:     "other.org",
	}
	return []*flow.Flow{tlsFlow, httpFlow, dnsFlow}
}

func TestFilterPrecedenceAndEvaluation(t *testing.T) {
	flows := sampleFlows()

	// Verify AST precedence: a || b && c == a || (b && c)
	expr, err := Parse("proto==tls || proto==http && port==9999")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	// If parsed as (tls || http) && 9999, tlsFlow would NOT match!
	// With proper AND-over-OR precedence, tlsFlow MUST match.
	if !expr.MatchFlow(flows[0]) {
		t.Fatalf("expected AND to bind tighter than OR: AST=%s", expr)
	}
	if expr.MatchFlow(flows[1]) {
		t.Fatalf("httpFlow should not match port==9999")
	}

	// Parentheses override precedence: (proto==tls || proto==http) && host contains example.com
	parenExpr, err := Parse("(proto==tls || proto==http) && host contains example.com")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if !parenExpr.MatchFlow(flows[0]) || !parenExpr.MatchFlow(flows[1]) || parenExpr.MatchFlow(flows[2]) {
		t.Fatalf("unexpected paren match results")
	}

	// Negation binds tighter than AND: !proto==dns && ip==10.0.1.42
	notExpr, err := Parse("!proto==dns && ip==10.0.1.42")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if !notExpr.MatchFlow(flows[0]) || !notExpr.MatchFlow(flows[1]) || notExpr.MatchFlow(flows[2]) {
		t.Fatalf("unexpected NOT precedence results")
	}

	// Specific required predicates
	checks := []struct {
		expr string
		want [3]bool
	}{
		{"ip==1.2.3.4", [3]bool{true, false, false}},
		{"port==443", [3]bool{true, false, false}},
		{"proto==tls", [3]bool{true, false, false}},
		{"host contains example.com", [3]bool{true, true, false}},
		{`host contains "example.com" AND NOT proto==http`, [3]bool{true, false, false}},
		{"ip==10.0.2.0/24", [3]bool{false, true, false}},
		{"retransmit==true", [3]bool{false, true, false}},
	}

	for _, tc := range checks {
		e, err := Parse(tc.expr)
		if err != nil {
			t.Fatalf("Parse(%q) failed: %v", tc.expr, err)
		}
		for i, fl := range flows {
			got := e.MatchFlow(fl)
			if got != tc.want[i] {
				t.Errorf("%q on flow %d (%s): got %v want %v", tc.expr, fl.ID, fl.Protocol, got, tc.want[i])
			}
		}
	}
}

func TestFilterInvalidInputErrors(t *testing.T) {
	badInputs := []string{
		"",
		"   ",
		"ip=1.2.3.4",
		"ip==1.2.3.4 & port==443",
		"ip==1.2.3.4 | port==443",
		"ip==not_an_ip",
		"port==70000",
		"port==abc",
		"port contains 443",
		"unknownfield==foo",
		"(proto==tls",
		"proto==tls)",
		"proto==tls &&",
		"&& proto==tls",
		"!",
		`host contains "unterminated`,
		"proto==tls extra_token",
	}

	for _, in := range badInputs {
		if expr, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) expected error, got %v", in, expr)
		}
	}
}

func TestFilterFuzzNoPanic2000(t *testing.T) {
	rng := rand.New(rand.NewSource(77))
	for i := 0; i < 2000; i++ {
		n := rng.Intn(96)
		buf := make([]byte, n)
		for j := range buf {
			buf[j] = byte(rng.Intn(96) + 32)
		}
		_, _ = Parse(string(buf))
	}
}
