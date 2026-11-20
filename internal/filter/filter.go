package filter

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode"

	"github.com/rawqubit/tracelight/internal/flow"
)

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokIdent
	tokString
	tokLParen
	tokRParen
	tokEq
	tokNeq
	tokGt
	tokGte
	tokLt
	tokLte
	tokAnd
	tokOr
	tokNot
	tokContains
)

type token struct {
	kind tokenKind
	val  string
	pos  int
}

func tokenize(input string) ([]token, error) {
	var tokens []token
	i := 0
	n := len(input)

	for i < n {
		c := input[i]
		if unicode.IsSpace(rune(c)) {
			i++
			continue
		}

		pos := i
		switch c {
		case '(':
			tokens = append(tokens, token{kind: tokLParen, val: "(", pos: pos})
			i++
		case ')':
			tokens = append(tokens, token{kind: tokRParen, val: ")", pos: pos})
			i++
		case '!':
			if i+1 < n && input[i+1] == '=' {
				tokens = append(tokens, token{kind: tokNeq, val: "!=", pos: pos})
				i += 2
			} else {
				tokens = append(tokens, token{kind: tokNot, val: "!", pos: pos})
				i++
			}
		case '=':
			if i+1 < n && input[i+1] == '=' {
				tokens = append(tokens, token{kind: tokEq, val: "==", pos: pos})
				i += 2
			} else {
				return nil, fmt.Errorf("filter syntax error at pos %d: unexpected '=' (use '==' for equality)", pos)
			}
		case '>':
			if i+1 < n && input[i+1] == '=' {
				tokens = append(tokens, token{kind: tokGte, val: ">=", pos: pos})
				i += 2
			} else {
				tokens = append(tokens, token{kind: tokGt, val: ">", pos: pos})
				i++
			}
		case '<':
			if i+1 < n && input[i+1] == '=' {
				tokens = append(tokens, token{kind: tokLte, val: "<=", pos: pos})
				i += 2
			} else {
				tokens = append(tokens, token{kind: tokLt, val: "<", pos: pos})
				i++
			}
		case '&':
			if i+1 < n && input[i+1] == '&' {
				tokens = append(tokens, token{kind: tokAnd, val: "&&", pos: pos})
				i += 2
			} else {
				return nil, fmt.Errorf("filter syntax error at pos %d: unexpected '&' (use '&&' or AND)", pos)
			}
		case '|':
			if i+1 < n && input[i+1] == '|' {
				tokens = append(tokens, token{kind: tokOr, val: "||", pos: pos})
				i += 2
			} else {
				return nil, fmt.Errorf("filter syntax error at pos %d: unexpected '|' (use '||' or OR)", pos)
			}
		case '"', '\'':
			quote := c
			i++
			var sb strings.Builder
			closed := false
			for i < n {
				ch := input[i]
				if ch == '\\' && i+1 < n {
					i++
					sb.WriteByte(input[i])
					i++
					continue
				}
				if ch == quote {
					closed = true
					i++
					break
				}
				sb.WriteByte(ch)
				i++
			}
			if !closed {
				return nil, fmt.Errorf("filter syntax error at pos %d: unterminated string literal", pos)
			}
			tokens = append(tokens, token{kind: tokString, val: sb.String(), pos: pos})
		default:
			if !isIdentChar(c) {
				return nil, fmt.Errorf("filter syntax error at pos %d: unexpected character %q", pos, c)
			}
			start := i
			for i < n && isIdentChar(input[i]) {
				i++
			}
			word := input[start:i]
			switch strings.ToLower(word) {
			case "and":
				tokens = append(tokens, token{kind: tokAnd, val: word, pos: pos})
			case "or":
				tokens = append(tokens, token{kind: tokOr, val: word, pos: pos})
			case "not":
				tokens = append(tokens, token{kind: tokNot, val: word, pos: pos})
			case "contains":
				tokens = append(tokens, token{kind: tokContains, val: word, pos: pos})
			default:
				tokens = append(tokens, token{kind: tokIdent, val: word, pos: pos})
			}
		}
	}

	tokens = append(tokens, token{kind: tokEOF, pos: n})
	return tokens, nil
}

func isIdentChar(c byte) bool {
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
		return true
	}
	switch c {
	case '.', '_', ':', '/', '-', '*':
		return true
	default:
		return false
	}
}

// Expr is a compiled AST node of the tracelight filter language.
type Expr interface {
	MatchFlow(fl *flow.Flow) bool
	MatchPacket(pkt flow.FlowPacket) bool
	String() string
}

type OrExpr struct {
	Left  Expr
	Right Expr
}

func (e *OrExpr) MatchFlow(fl *flow.Flow) bool {
	return e.Left.MatchFlow(fl) || e.Right.MatchFlow(fl)
}
func (e *OrExpr) MatchPacket(pkt flow.FlowPacket) bool {
	return e.Left.MatchPacket(pkt) || e.Right.MatchPacket(pkt)
}
func (e *OrExpr) String() string {
	return fmt.Sprintf("(%s || %s)", e.Left, e.Right)
}

type AndExpr struct {
	Left  Expr
	Right Expr
}

func (e *AndExpr) MatchFlow(fl *flow.Flow) bool {
	return e.Left.MatchFlow(fl) && e.Right.MatchFlow(fl)
}
func (e *AndExpr) MatchPacket(pkt flow.FlowPacket) bool {
	return e.Left.MatchPacket(pkt) && e.Right.MatchPacket(pkt)
}
func (e *AndExpr) String() string {
	return fmt.Sprintf("(%s && %s)", e.Left, e.Right)
}

type NotExpr struct {
	Inner Expr
}

func (e *NotExpr) MatchFlow(fl *flow.Flow) bool {
	return !e.Inner.MatchFlow(fl)
}
func (e *NotExpr) MatchPacket(pkt flow.FlowPacket) bool {
	return !e.Inner.MatchPacket(pkt)
}
func (e *NotExpr) String() string {
	return fmt.Sprintf("!(%s)", e.Inner)
}

type CompareExpr struct {
	Field    string
	Op       string
	RawValue string
	ipAddr   netip.Addr
	ipPrefix netip.Prefix
	isPrefix bool
	numVal   int64
	boolVal  bool
}

func (e *CompareExpr) String() string {
	return fmt.Sprintf("%s %s %s", e.Field, e.Op, e.RawValue)
}

type parser struct {
	tokens []token
	pos    int
}

func (p *parser) peek() token {
	if p.pos >= len(p.tokens) {
		return token{kind: tokEOF}
	}
	return p.tokens[p.pos]
}

func (p *parser) next() token {
	tok := p.peek()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return tok
}

// Parse parses a filter expression using a recursive-descent parser.
// Precedence (lowest to highest): OR -> AND -> NOT -> parentheses / comparison.
func Parse(input string) (Expr, error) {
	if strings.TrimSpace(input) == "" {
		return nil, fmt.Errorf("filter syntax error: empty expression")
	}
	tokens, err := tokenize(input)
	if err != nil {
		return nil, err
	}
	p := &parser{tokens: tokens}
	expr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if tok := p.peek(); tok.kind != tokEOF {
		return nil, fmt.Errorf("filter syntax error at pos %d: unexpected token %q", tok.pos, tok.val)
	}
	return expr, nil
}

func (p *parser) parseOr() (Expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokOr {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &OrExpr{Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (Expr, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokAnd {
		p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &AndExpr{Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseUnary() (Expr, error) {
	if p.peek().kind == tokNot {
		p.next()
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &NotExpr{Inner: inner}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (Expr, error) {
	tok := p.peek()
	switch tok.kind {
	case tokLParen:
		p.next()
		expr, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tokRParen {
			return nil, fmt.Errorf("filter syntax error at pos %d: expected ')'", p.peek().pos)
		}
		p.next()
		return expr, nil
	case tokIdent:
		return p.parseComparison()
	case tokEOF:
		return nil, fmt.Errorf("filter syntax error at pos %d: unexpected end of expression", tok.pos)
	default:
		return nil, fmt.Errorf("filter syntax error at pos %d: unexpected token %q", tok.pos, tok.val)
	}
}

func (p *parser) parseComparison() (Expr, error) {
	fieldTok := p.next()
	field := strings.ToLower(fieldTok.val)

	opTok := p.peek()
	var op string
	switch opTok.kind {
	case tokEq:
		op = "=="
	case tokNeq:
		op = "!="
	case tokGt:
		op = ">"
	case tokGte:
		op = ">="
	case tokLt:
		op = "<"
	case tokLte:
		op = "<="
	case tokContains:
		op = "contains"
	default:
		return nil, fmt.Errorf("filter syntax error at pos %d: expected comparison operator after %q, got %q", opTok.pos, fieldTok.val, opTok.val)
	}
	p.next()

	valTok := p.peek()
	if valTok.kind != tokIdent && valTok.kind != tokString {
		return nil, fmt.Errorf("filter syntax error at pos %d: expected value after %q", valTok.pos, op)
	}
	p.next()

	return buildCompareExpr(field, op, valTok.val, fieldTok.pos, opTok.pos, valTok.pos)
}

func buildCompareExpr(field, op, val string, fieldPos, opPos, valPos int) (*CompareExpr, error) {
	expr := &CompareExpr{
		Field:    field,
		Op:       op,
		RawValue: val,
	}

	switch field {
	case "ip", "src.ip", "dst.ip":
		if op != "==" && op != "!=" && op != "contains" {
			return nil, fmt.Errorf("filter error at pos %d: operator %q not supported for %q", opPos, op, field)
		}
		if op == "==" || op == "!=" {
			if pfx, err := netip.ParsePrefix(val); err == nil {
				expr.ipPrefix = pfx
				expr.isPrefix = true
			} else if addr, err := netip.ParseAddr(val); err == nil {
				expr.ipAddr = addr
			} else {
				return nil, fmt.Errorf("filter error at pos %d: invalid IP or CIDR %q", valPos, val)
			}
		}

	case "port", "src.port", "dst.port":
		if op == "contains" {
			return nil, fmt.Errorf("filter error at pos %d: operator 'contains' not supported for %q", opPos, field)
		}
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 || n > 65535 {
			return nil, fmt.Errorf("filter error at pos %d: invalid port %q (expected 0-65535)", valPos, val)
		}
		expr.numVal = int64(n)

	case "proto", "protocol", "host", "sni", "dns", "method", "http.method", "path", "http.path":
		if op != "==" && op != "!=" && op != "contains" {
			return nil, fmt.Errorf("filter error at pos %d: operator %q not supported for %q", opPos, op, field)
		}

	case "status", "http.status":
		if op == "contains" {
			return nil, fmt.Errorf("filter error at pos %d: operator 'contains' not supported for %q", opPos, field)
		}
		n, err := strconv.Atoi(val)
		if err != nil || n < 100 || n > 599 {
			return nil, fmt.Errorf("filter error at pos %d: invalid HTTP status %q (expected 100-599)", valPos, val)
		}
		expr.numVal = int64(n)

	case "bytes", "len":
		if op == "contains" {
			return nil, fmt.Errorf("filter error at pos %d: operator 'contains' not supported for %q", opPos, field)
		}
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("filter error at pos %d: invalid byte count %q", valPos, val)
		}
		expr.numVal = n

	case "vlan":
		if op != "==" && op != "!=" {
			return nil, fmt.Errorf("filter error at pos %d: operator %q not supported for %q", opPos, op, field)
		}
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 || n > 4095 {
			return nil, fmt.Errorf("filter error at pos %d: invalid VLAN ID %q (expected 0-4095)", valPos, val)
		}
		expr.numVal = int64(n)

	case "retransmit":
		if op != "==" && op != "!=" {
			return nil, fmt.Errorf("filter error at pos %d: operator %q not supported for %q", opPos, op, field)
		}
		b, err := strconv.ParseBool(val)
		if err != nil {
			return nil, fmt.Errorf("filter error at pos %d: invalid boolean %q", valPos, val)
		}
		expr.boolVal = b

	default:
		return nil, fmt.Errorf("filter error at pos %d: unknown field %q", fieldPos, field)
	}

	return expr, nil
}

func (e *CompareExpr) matchIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	switch e.Op {
	case "contains":
		return strings.Contains(strings.ToLower(addr.String()), strings.ToLower(e.RawValue))
	case "==":
		if e.isPrefix {
			return e.ipPrefix.Contains(addr)
		}
		return addr == e.ipAddr
	case "!=":
		if e.isPrefix {
			return !e.ipPrefix.Contains(addr)
		}
		return addr != e.ipAddr
	}
	return false
}

func (e *CompareExpr) matchNum(actual int64) bool {
	switch e.Op {
	case "==":
		return actual == e.numVal
	case "!=":
		return actual != e.numVal
	case ">":
		return actual > e.numVal
	case ">=":
		return actual >= e.numVal
	case "<":
		return actual < e.numVal
	case "<=":
		return actual <= e.numVal
	}
	return false
}

func (e *CompareExpr) matchStr(actual string) bool {
	a := strings.ToLower(actual)
	v := strings.ToLower(e.RawValue)
	switch e.Op {
	case "==":
		return a == v
	case "!=":
		return a != v
	case "contains":
		return strings.Contains(a, v)
	}
	return false
}

func (e *CompareExpr) matchStrAny(vals []string) bool {
	if e.Op == "!=" {
		v := strings.ToLower(e.RawValue)
		for _, actual := range vals {
			if strings.ToLower(actual) == v {
				return false
			}
		}
		return true
	}
	for _, actual := range vals {
		if e.matchStr(actual) {
			return true
		}
	}
	return false
}

func (e *CompareExpr) MatchFlow(fl *flow.Flow) bool {
	if fl == nil {
		return false
	}
	switch e.Field {
	case "ip":
		if e.Op == "!=" {
			return e.matchIP(fl.SrcIP) && e.matchIP(fl.DstIP)
		}
		return e.matchIP(fl.SrcIP) || e.matchIP(fl.DstIP)
	case "src.ip":
		return e.matchIP(fl.SrcIP)
	case "dst.ip":
		return e.matchIP(fl.DstIP)
	case "port":
		if e.Op == "!=" {
			return e.matchNum(int64(fl.SrcPort)) && e.matchNum(int64(fl.DstPort))
		}
		return e.matchNum(int64(fl.SrcPort)) || e.matchNum(int64(fl.DstPort))
	case "src.port":
		return e.matchNum(int64(fl.SrcPort))
	case "dst.port":
		return e.matchNum(int64(fl.DstPort))
	case "proto", "protocol":
		if e.Op == "!=" {
			return !strings.EqualFold(fl.Protocol, e.RawValue) && !strings.EqualFold(fl.L4Proto, e.RawValue)
		}
		return e.matchStr(fl.Protocol) || (fl.L4Proto != "" && e.matchStr(fl.L4Proto))
	case "host":
		return e.matchStr(fl.Host)
	case "sni":
		var vals []string
		for _, p := range fl.Packets {
			if p.Decoded != nil && p.Decoded.TLS != nil && p.Decoded.TLS.SNI != "" {
				vals = append(vals, p.Decoded.TLS.SNI)
			}
		}
		return e.matchStrAny(vals)
	case "dns":
		var vals []string
		for _, p := range fl.Packets {
			if p.Decoded != nil && p.Decoded.DNS != nil {
				if name := p.Decoded.DNS.PrimaryName(); name != "" {
					vals = append(vals, name)
				}
			}
		}
		return e.matchStrAny(vals)
	case "method", "http.method":
		var vals []string
		for _, p := range fl.Packets {
			if p.Decoded != nil && p.Decoded.HTTP != nil && !p.Decoded.HTTP.IsResponse {
				vals = append(vals, p.Decoded.HTTP.Method)
			}
		}
		return e.matchStrAny(vals)
	case "path", "http.path":
		var vals []string
		for _, p := range fl.Packets {
			if p.Decoded != nil && p.Decoded.HTTP != nil && !p.Decoded.HTTP.IsResponse {
				vals = append(vals, p.Decoded.HTTP.Target)
			}
		}
		return e.matchStrAny(vals)
	case "status", "http.status":
		matched := false
		for _, p := range fl.Packets {
			if p.Decoded != nil && p.Decoded.HTTP != nil && p.Decoded.HTTP.IsResponse {
				if e.Op == "!=" {
					if int64(p.Decoded.HTTP.StatusCode) == e.numVal {
						return false
					}
				} else if e.matchNum(int64(p.Decoded.HTTP.StatusCode)) {
					matched = true
				}
			}
		}
		if e.Op == "!=" {
			return true
		}
		return matched
	case "bytes", "len":
		return e.matchNum(fl.ByteCount)
	case "vlan":
		for _, p := range fl.Packets {
			if p.Decoded != nil && p.Decoded.Ethernet != nil {
				for _, v := range p.Decoded.Ethernet.VLANs {
					if e.Op == "!=" {
						if int64(v.VID) == e.numVal {
							return false
						}
					} else if e.matchNum(int64(v.VID)) {
						return true
					}
				}
			}
		}
		return e.Op == "!="
	case "retransmit":
		hasRetrans := fl.Retransmissions > 0
		if e.Op == "!=" {
			return hasRetrans != e.boolVal
		}
		return hasRetrans == e.boolVal
	}
	return false
}

func (e *CompareExpr) MatchPacket(pkt flow.FlowPacket) bool {
	dec := pkt.Decoded
	if dec == nil {
		return false
	}
	switch e.Field {
	case "ip":
		if e.Op == "!=" {
			return e.matchIP(dec.SrcIP) && e.matchIP(dec.DstIP)
		}
		return e.matchIP(dec.SrcIP) || e.matchIP(dec.DstIP)
	case "src.ip":
		return e.matchIP(dec.SrcIP)
	case "dst.ip":
		return e.matchIP(dec.DstIP)
	case "port":
		if e.Op == "!=" {
			return e.matchNum(int64(dec.SrcPort)) && e.matchNum(int64(dec.DstPort))
		}
		return e.matchNum(int64(dec.SrcPort)) || e.matchNum(int64(dec.DstPort))
	case "src.port":
		return e.matchNum(int64(dec.SrcPort))
	case "dst.port":
		return e.matchNum(int64(dec.DstPort))
	case "proto", "protocol":
		if e.Op == "!=" {
			return !strings.EqualFold(dec.Protocol(), e.RawValue) && !strings.EqualFold(dec.L4Proto, e.RawValue)
		}
		return e.matchStr(dec.Protocol()) || (dec.L4Proto != "" && e.matchStr(dec.L4Proto))
	case "host":
		return e.matchStr(dec.Host)
	case "sni":
		if dec.TLS != nil {
			return e.matchStr(dec.TLS.SNI)
		}
		return e.Op == "!="
	case "dns":
		if dec.DNS != nil {
			return e.matchStr(dec.DNS.PrimaryName())
		}
		return e.Op == "!="
	case "method", "http.method":
		if dec.HTTP != nil && !dec.HTTP.IsResponse {
			return e.matchStr(dec.HTTP.Method)
		}
		return false
	case "path", "http.path":
		if dec.HTTP != nil && !dec.HTTP.IsResponse {
			return e.matchStr(dec.HTTP.Target)
		}
		return false
	case "status", "http.status":
		if dec.HTTP != nil && dec.HTTP.IsResponse {
			return e.matchNum(int64(dec.HTTP.StatusCode))
		}
		return false
	case "bytes", "len":
		return e.matchNum(int64(pkt.Length))
	case "vlan":
		if dec.Ethernet != nil {
			for _, v := range dec.Ethernet.VLANs {
				if e.matchNum(int64(v.VID)) {
					return true
				}
			}
		}
		return false
	case "retransmit":
		if e.Op == "!=" {
			return pkt.IsRetransmit != e.boolVal
		}
		return pkt.IsRetransmit == e.boolVal
	}
	return false
}
