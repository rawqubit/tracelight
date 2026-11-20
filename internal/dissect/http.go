package dissect

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

type HTTPHeader struct {
	Name  string
	Value string
}

type HTTPLayer struct {
	IsResponse  bool
	Method      string
	Target      string
	Version     string
	StatusCode  int
	Reason      string
	Headers     []HTTPHeader
	Host        string
	ContentType string
	Body        []byte
}

func (h *HTTPLayer) Header(name string) string {
	for _, hdr := range h.Headers {
		if strings.EqualFold(hdr.Name, name) {
			return hdr.Value
		}
	}
	return ""
}

func (h *HTTPLayer) Summary() string {
	if h.IsResponse {
		if h.ContentType != "" {
			return fmt.Sprintf("HTTP %d %s (%s, %d B)", h.StatusCode, h.Reason, h.ContentType, len(h.Body))
		}
		if len(h.Body) > 0 {
			return fmt.Sprintf("HTTP %d %s (%d B)", h.StatusCode, h.Reason, len(h.Body))
		}
		return fmt.Sprintf("HTTP %d %s", h.StatusCode, h.Reason)
	}
	if h.Host != "" {
		return fmt.Sprintf("HTTP %s %s%s", h.Method, h.Host, h.Target)
	}
	return fmt.Sprintf("HTTP %s %s %s", h.Method, h.Target, h.Version)
}

var httpMethods = map[string]bool{
	"GET":     true,
	"HEAD":    true,
	"POST":    true,
	"PUT":     true,
	"DELETE":  true,
	"CONNECT": true,
	"OPTIONS": true,
	"TRACE":   true,
	"PATCH":   true,
}

func DecodeHTTP(data []byte) (*HTTPLayer, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("http: payload too short (%d B)", len(data))
	}

	var headBytes, body []byte
	if idx := bytes.Index(data, []byte("\r\n\r\n")); idx >= 0 {
		headBytes = data[:idx]
		body = data[idx+4:]
	} else if idx := bytes.Index(data, []byte("\n\n")); idx >= 0 {
		headBytes = data[:idx]
		body = data[idx+2:]
	} else {
		headBytes = data
	}

	raw := strings.ReplaceAll(string(headBytes), "\r\n", "\n")
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil, fmt.Errorf("http: missing start line")
	}

	startLine := lines[0]
	if !isPrintableASCII(startLine) {
		return nil, fmt.Errorf("http: non-printable start line")
	}

	layer := &HTTPLayer{
		Body: body,
	}

	if strings.HasPrefix(startLine, "HTTP/1.") {
		parts := strings.SplitN(startLine, " ", 3)
		if len(parts) < 2 {
			return nil, fmt.Errorf("http: malformed status line")
		}
		if parts[0] != "HTTP/1.0" && parts[0] != "HTTP/1.1" {
			return nil, fmt.Errorf("http: unsupported version %q", parts[0])
		}
		code, err := strconv.Atoi(parts[1])
		if err != nil || code < 100 || code > 599 {
			return nil, fmt.Errorf("http: invalid status code %q", parts[1])
		}
		layer.IsResponse = true
		layer.Version = parts[0]
		layer.StatusCode = code
		if len(parts) == 3 {
			layer.Reason = parts[2]
		}
	} else {
		parts := strings.Split(startLine, " ")
		if len(parts) != 3 {
			return nil, fmt.Errorf("http: malformed request line")
		}
		if !httpMethods[parts[0]] {
			return nil, fmt.Errorf("http: unknown method %q", parts[0])
		}
		if parts[1] == "" {
			return nil, fmt.Errorf("http: empty request target")
		}
		if parts[2] != "HTTP/1.0" && parts[2] != "HTTP/1.1" {
			return nil, fmt.Errorf("http: unsupported version %q", parts[2])
		}
		layer.Method = parts[0]
		layer.Target = parts[1]
		layer.Version = parts[2]
	}

	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		if !isPrintableASCII(line) {
			return nil, fmt.Errorf("http: non-printable header line")
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			return nil, fmt.Errorf("http: malformed header %q", line)
		}
		name := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])
		layer.Headers = append(layer.Headers, HTTPHeader{Name: name, Value: val})
		if strings.EqualFold(name, "Host") {
			layer.Host = val
		} else if strings.EqualFold(name, "Content-Type") {
			if semi := strings.IndexByte(val, ';'); semi >= 0 {
				layer.ContentType = strings.TrimSpace(val[:semi])
			} else {
				layer.ContentType = val
			}
		}
	}

	return layer, nil
}

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 && b != '\t' {
			return false
		}
		if b > 0x7e {
			return false
		}
	}
	return true
}
