package ui

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/rawqubit/tracelight/internal/capture"
	"github.com/rawqubit/tracelight/internal/dissect"
	"github.com/rawqubit/tracelight/internal/filter"
	"github.com/rawqubit/tracelight/internal/flow"
)

//go:embed index.html
var indexHTML []byte

type Server struct {
	mu         sync.RWMutex
	sourceName string
	format     string
	result     *flow.Result
}

func NewServer(sourceName, format string, res *flow.Result) *Server {
	if res == nil {
		res = &flow.Result{ProtoCounts: map[string]int{}}
	}
	return &Server{
		sourceName: sourceName,
		format:     format,
		result:     res,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/summary", s.handleSummary)
	mux.HandleFunc("/api/flows", s.handleFlows)
	mux.HandleFunc("/api/flows/", s.handleFlowDetail)
	mux.HandleFunc("/api/upload", s.handleUpload)
	return mux
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

type summaryResponse struct {
	Source       string         `json:"source"`
	Format       string         `json:"format"`
	TotalFlows   int            `json:"total_flows"`
	TotalPackets int            `json:"total_packets"`
	TotalBytes   int64          `json:"total_bytes"`
	DurationNS   int64          `json:"duration_ns"`
	ProtoCounts  map[string]int `json:"proto_counts"`
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	resp := summaryResponse{
		Source:       s.sourceName,
		Format:       s.format,
		TotalFlows:   len(s.result.Flows),
		TotalPackets: len(s.result.AllPackets),
		TotalBytes:   s.result.TotalBytes,
		DurationNS:   s.result.Duration.Nanoseconds(),
		ProtoCounts:  s.result.ProtoCounts,
	}
	writeJSON(w, http.StatusOK, resp)
}

type flowDTO struct {
	ID              int      `json:"id"`
	Protocol        string   `json:"protocol"`
	L4Proto         string   `json:"l4_proto"`
	Source          string   `json:"source"`
	Destination     string   `json:"destination"`
	SrcIP           string   `json:"src_ip"`
	SrcPort         uint16   `json:"src_port"`
	DstIP           string   `json:"dst_ip"`
	DstPort         uint16   `json:"dst_port"`
	Host            string   `json:"host"`
	TLSVersion      string   `json:"tls_version,omitempty"`
	ALPN            []string `json:"alpn,omitempty"`
	Info            string   `json:"info"`
	PacketCount     int      `json:"packet_count"`
	ByteCount       int64    `json:"byte_count"`
	FwdPackets      int      `json:"fwd_packets"`
	RevPackets      int      `json:"rev_packets"`
	Retransmissions int      `json:"retransmissions"`
	DurationNS      int64    `json:"duration_ns"`
	RTTNS           *int64   `json:"rtt_ns,omitempty"`
}

func toFlowDTO(fl *flow.Flow) flowDTO {
	var rtt *int64
	if fl.HasRTT {
		v := fl.RTTEstimate.Nanoseconds()
		rtt = &v
	}
	return flowDTO{
		ID:              fl.ID,
		Protocol:        fl.Protocol,
		L4Proto:         fl.L4Proto,
		Source:          (flow.Endpoint{IP: fl.SrcIP, Port: fl.SrcPort}).String(),
		Destination:     (flow.Endpoint{IP: fl.DstIP, Port: fl.DstPort}).String(),
		SrcIP:           fl.SrcIP.String(),
		SrcPort:         fl.SrcPort,
		DstIP:           fl.DstIP.String(),
		DstPort:         fl.DstPort,
		Host:            fl.Host,
		TLSVersion:      fl.TLSVersion,
		ALPN:            fl.ALPN,
		Info:            fl.Info,
		PacketCount:     fl.PacketCount,
		ByteCount:       fl.ByteCount,
		FwdPackets:      fl.FwdPackets,
		RevPackets:      fl.RevPackets,
		Retransmissions: fl.Retransmissions,
		DurationNS:      fl.Duration.Nanoseconds(),
		RTTNS:           rtt,
	}
}

func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	filterStr := strings.TrimSpace(q.Get("filter"))
	var expr filter.Expr
	if filterStr != "" {
		var err error
		expr, err = filter.Parse(filterStr)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}

	s.mu.RLock()
	matched := make([]*flow.Flow, 0, len(s.result.Flows))
	for _, fl := range s.result.Flows {
		if expr == nil || expr.MatchFlow(fl) {
			matched = append(matched, fl)
		}
	}
	s.mu.RUnlock()

	sortField := q.Get("sort")
	if sortField == "" {
		sortField = "start"
	}
	desc := strings.EqualFold(q.Get("order"), "desc")
	flow.SortFlows(matched, sortField, desc)

	out := make([]flowDTO, 0, len(matched))
	for _, fl := range matched {
		out = append(out, toFlowDTO(fl))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"flows": out,
		"total": len(out),
	})
}

type layerField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type layerInfo struct {
	Title   string       `json:"title"`
	Summary string       `json:"summary"`
	Fields  []layerField `json:"fields,omitempty"`
}

type packetDTO struct {
	Index        int         `json:"index"`
	RelCaptureNS int64       `json:"rel_capture_ns"`
	RelFlowNS    int64       `json:"rel_flow_ns"`
	Direction    string      `json:"direction"`
	Arrow        string      `json:"arrow"`
	Length       int         `json:"length"`
	Protocol     string      `json:"protocol"`
	Summary      string      `json:"summary"`
	IsRetransmit bool        `json:"is_retransmit"`
	TCPFlags     string      `json:"tcp_flags,omitempty"`
	Layers       []layerInfo `json:"layers"`
	RawBytes     []byte      `json:"raw_bytes"`
	AppBytes     []byte      `json:"app_bytes,omitempty"`
}

func (s *Server) handleFlowDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/flows/")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid flow id"})
		return
	}

	s.mu.RLock()
	var target *flow.Flow
	for _, fl := range s.result.Flows {
		if fl.ID == id {
			target = fl
			break
		}
	}
	s.mu.RUnlock()

	if target == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("flow %d not found", id)})
		return
	}

	pkts := make([]packetDTO, 0, len(target.Packets))
	for _, p := range target.Packets {
		proto := "unknown"
		var tcpFlags string
		var appBytes []byte
		if p.Decoded != nil {
			proto = p.Decoded.Protocol()
			if p.Decoded.TCP != nil {
				tcpFlags = p.Decoded.TCP.Flags.String()
			}
			appBytes = p.Decoded.AppPayload
		}
		pkts = append(pkts, packetDTO{
			Index:        p.PacketIndex,
			RelCaptureNS: p.RelCapture.Nanoseconds(),
			RelFlowNS:    p.RelFlow.Nanoseconds(),
			Direction:    string(p.Direction),
			Arrow:        p.Direction.Arrow(),
			Length:       p.Length,
			Protocol:     proto,
			Summary:      p.Summary,
			IsRetransmit: p.IsRetransmit,
			TCPFlags:     tcpFlags,
			Layers:       buildLayers(p.Decoded),
			RawBytes:     p.Raw,
			AppBytes:     appBytes,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"flow":    toFlowDTO(target),
		"packets": pkts,
	})
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	const maxUpload = 32 * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(r.Body, maxUpload+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(body) > maxUpload {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "capture exceeds 32 MiB limit"})
		return
	}
	capData, err := capture.Read(bytes.NewReader(body))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	name := r.Header.Get("X-File-Name")
	if name == "" {
		name = "uploaded.pcap"
	}
	res := flow.Assemble(capData)

	s.mu.Lock()
	s.sourceName = name
	s.format = string(capData.Format)
	s.result = res
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, summaryResponse{
		Source:       name,
		Format:       string(capData.Format),
		TotalFlows:   len(res.Flows),
		TotalPackets: len(res.AllPackets),
		TotalBytes:   res.TotalBytes,
		DurationNS:   res.Duration.Nanoseconds(),
		ProtoCounts:  res.ProtoCounts,
	})
}

func buildLayers(d *dissect.DecodedPacket) []layerInfo {
	if d == nil {
		return nil
	}
	var layers []layerInfo
	if d.Ethernet != nil {
		fields := []layerField{
			{Name: "Src MAC", Value: d.Ethernet.SrcMAC.String()},
			{Name: "Dst MAC", Value: d.Ethernet.DstMAC.String()},
			{Name: "EtherType", Value: fmt.Sprintf("0x%04x", d.Ethernet.EtherType)},
		}
		for i, v := range d.Ethernet.VLANs {
			fields = append(fields, layerField{
				Name:  fmt.Sprintf("VLAN %d", i+1),
				Value: fmt.Sprintf("VID=%d PCP=%d DEI=%v", v.VID, v.PCP, v.DEI),
			})
		}
		layers = append(layers, layerInfo{Title: "Ethernet", Summary: d.Ethernet.Summary(), Fields: fields})
	}
	if d.IPv4 != nil {
		layers = append(layers, layerInfo{
			Title:   "IPv4",
			Summary: d.IPv4.Summary(),
			Fields: []layerField{
				{Name: "Src IP", Value: d.IPv4.SrcIP.String()},
				{Name: "Dst IP", Value: d.IPv4.DstIP.String()},
				{Name: "TTL", Value: strconv.Itoa(int(d.IPv4.TTL))},
				{Name: "Total Len", Value: strconv.Itoa(int(d.IPv4.TotalLen))},
				{Name: "ID", Value: fmt.Sprintf("0x%04x", d.IPv4.ID)},
			},
		})
	}
	if d.IPv6 != nil {
		layers = append(layers, layerInfo{
			Title:   "IPv6",
			Summary: d.IPv6.Summary(),
			Fields: []layerField{
				{Name: "Src IP", Value: d.IPv6.SrcIP.String()},
				{Name: "Dst IP", Value: d.IPv6.DstIP.String()},
				{Name: "Hop Limit", Value: strconv.Itoa(int(d.IPv6.HopLimit))},
				{Name: "Payload Len", Value: strconv.Itoa(int(d.IPv6.PayloadLen))},
			},
		})
	}
	if d.ICMP != nil {
		layers = append(layers, layerInfo{
			Title:   "ICMP",
			Summary: d.ICMP.Summary(),
			Fields: []layerField{
				{Name: "Type", Value: strconv.Itoa(int(d.ICMP.Type))},
				{Name: "Code", Value: strconv.Itoa(int(d.ICMP.Code))},
			},
		})
	}
	if d.TCP != nil {
		layers = append(layers, layerInfo{
			Title:   "TCP",
			Summary: d.TCP.Summary(),
			Fields: []layerField{
				{Name: "Ports", Value: fmt.Sprintf("%d -> %d", d.TCP.SrcPort, d.TCP.DstPort)},
				{Name: "Flags", Value: d.TCP.Flags.String()},
				{Name: "Seq", Value: strconv.FormatUint(uint64(d.TCP.Seq), 10)},
				{Name: "Ack", Value: strconv.FormatUint(uint64(d.TCP.Ack), 10)},
				{Name: "Window", Value: strconv.Itoa(int(d.TCP.Window))},
				{Name: "Payload", Value: fmt.Sprintf("%d B", len(d.TCP.Payload))},
			},
		})
	}
	if d.UDP != nil {
		layers = append(layers, layerInfo{
			Title:   "UDP",
			Summary: d.UDP.Summary(),
			Fields: []layerField{
				{Name: "Ports", Value: fmt.Sprintf("%d -> %d", d.UDP.SrcPort, d.UDP.DstPort)},
				{Name: "Length", Value: strconv.Itoa(int(d.UDP.Length))},
				{Name: "Payload", Value: fmt.Sprintf("%d B", len(d.UDP.Payload))},
			},
		})
	}
	if d.DNS != nil {
		fields := []layerField{
			{Name: "TxID", Value: fmt.Sprintf("0x%04x", d.DNS.ID)},
			{Name: "Kind", Value: map[bool]string{true: "Response", false: "Query"}[d.DNS.IsResponse]},
		}
		for _, q := range d.DNS.Questions {
			fields = append(fields, layerField{Name: "Query", Value: fmt.Sprintf("%s (%s)", q.Name, dissect.DNSTypeName(q.Type))})
		}
		for _, a := range d.DNS.Answers {
			fields = append(fields, layerField{Name: "Answer", Value: fmt.Sprintf("%s %s -> %s (TTL %ds)", a.Name, dissect.DNSTypeName(a.Type), a.Data, a.TTL)})
		}
		layers = append(layers, layerInfo{Title: "DNS", Summary: d.DNS.Summary(), Fields: fields})
	}
	if d.HTTP != nil {
		var fields []layerField
		if d.HTTP.IsResponse {
			fields = append(fields, layerField{Name: "Status", Value: fmt.Sprintf("%s %d %s", d.HTTP.Version, d.HTTP.StatusCode, d.HTTP.Reason)})
		} else {
			fields = append(fields, layerField{Name: "Request", Value: fmt.Sprintf("%s %s %s", d.HTTP.Method, d.HTTP.Target, d.HTTP.Version)})
		}
		for _, h := range d.HTTP.Headers {
			fields = append(fields, layerField{Name: h.Name, Value: h.Value})
		}
		layers = append(layers, layerInfo{Title: "HTTP/1.1", Summary: d.HTTP.Summary(), Fields: fields})
	}
	if d.TLS != nil {
		fields := []layerField{
			{Name: "Version", Value: d.TLS.VersionName},
		}
		if d.TLS.SNI != "" {
			fields = append(fields, layerField{Name: "SNI", Value: d.TLS.SNI})
		}
		if len(d.TLS.ALPN) > 0 {
			fields = append(fields, layerField{Name: "ALPN", Value: strings.Join(d.TLS.ALPN, ", ")})
		}
		if len(d.TLS.CipherSuites) > 0 {
			fields = append(fields, layerField{Name: "Cipher Suites", Value: fmt.Sprintf("%d offered", len(d.TLS.CipherSuites))})
		}
		layers = append(layers, layerInfo{Title: "TLS", Summary: d.TLS.Summary(), Fields: fields})
	}
	return layers
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}
