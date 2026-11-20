package ui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/rawqubit/tracelight/internal/demo"
)

func TestUIServerEndpoints(t *testing.T) {
	capData, res, err := demo.Run()
	if err != nil {
		t.Fatalf("demo.Run: %v", err)
	}
	srv := NewServer("demo.pcap", string(capData.Format), res)
	h := srv.Handler()

	// 1. Index HTML
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "tracelight") {
		t.Fatalf("GET / unexpected: code=%d", rec.Code)
	}

	// 2. Summary
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/summary", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/summary code=%d", rec.Code)
	}
	var sum summaryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &sum); err != nil {
		t.Fatalf("unmarshal summary: %v", err)
	}
	if sum.TotalFlows != 3 || sum.TotalPackets != 16 {
		t.Fatalf("unexpected summary: %+v", sum)
	}

	// 3. Filtered flows
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/flows?filter=proto%3D%3Dtls&sort=bytes&order=desc", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/flows filtered code=%d body=%s", rec.Code, rec.Body.String())
	}
	var flowsResp struct {
		Flows []flowDTO `json:"flows"`
		Total int       `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &flowsResp); err != nil {
		t.Fatalf("unmarshal flows: %v", err)
	}
	if flowsResp.Total != 1 || flowsResp.Flows[0].Protocol != "tls" {
		t.Fatalf("unexpected filtered flows: %+v", flowsResp)
	}

	// 4. Invalid filter -> 400
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/flows?filter=port%3D%3D99999", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid filter, got %d", rec.Code)
	}

	// 5. Flow detail (waterfall + layers + bytes)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/flows/2", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/flows/2 code=%d", rec.Code)
	}
	var detail struct {
		Flow    flowDTO     `json:"flow"`
		Packets []packetDTO `json:"packets"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("unmarshal detail: %v", err)
	}
	if len(detail.Packets) != 7 || detail.Flow.Host != "api.example.com" {
		t.Fatalf("unexpected flow 2 detail: pkts=%d host=%q", len(detail.Packets), detail.Flow.Host)
	}

	// 6. Missing flow -> 404
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/flows/999", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	// 7. Upload fixture pcapng
	ngBytes, err := os.ReadFile("../../testdata/sample.pcapng")
	if err != nil {
		t.Fatalf("read sample.pcapng: %v", err)
	}
	upReq := httptest.NewRequest(http.MethodPost, "/api/upload", bytes.NewReader(ngBytes))
	upReq.Header.Set("X-File-Name", "sample.pcapng")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, upReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/upload code=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sum); err != nil {
		t.Fatalf("unmarshal upload summary: %v", err)
	}
	if sum.Format != "pcapng" || sum.TotalFlows != 3 {
		t.Fatalf("unexpected upload summary: %+v", sum)
	}
}
