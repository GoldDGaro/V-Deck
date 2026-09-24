package main

import (
	"context"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Public catalogue locations from the signed official AmneziaVPN 5.0.1.5
// executable; see README.md. No subscription key is sent to these hosts.
var catalogueBases = []string{
	"https://storage.googleapis.com/lambda-list/",
	"https://s3.eu-north-1.amazonaws.com/amnezia/",
	"https://storage.mwsapis.ru/lambda-list/",
	"https://objectstorage.eu-zurich-1.oraclecloud.com/n/zrhfyaq6qxvh/b/lambda-list/o/",
}

type attempt struct {
	Route     string `json:"route"`
	Host      string `json:"host"`
	Stage     string `json:"stage"`
	Code      string `json:"code"`
	ElapsedMS int64  `json:"elapsed_ms"`
	DNSMS     int64  `json:"dns_ms"`
	TCPMS     int64  `json:"tcp_ms"`
	TLSMS     int64  `json:"tls_ms"`
	Family    string `json:"family,omitempty"`
	Written   bool   `json:"written"`
	Status    int    `json:"status,omitempty"`
}

type requestTrace struct {
	mu                                  sync.Mutex
	a                                   attempt
	start, dnsStart, tcpStart, tlsStart time.Time
}

func (t *requestTrace) update(fn func()) { t.mu.Lock(); defer t.mu.Unlock(); fn() }

func (t *requestTrace) hooks() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { t.update(func() { t.a.Stage = "DNS"; t.dnsStart = time.Now() }) },
		DNSDone:           func(httptrace.DNSDoneInfo) { t.update(func() { t.a.DNSMS = time.Since(t.dnsStart).Milliseconds() }) },
		ConnectStart:      func(_, _ string) { t.update(func() { t.a.Stage = "TCP"; t.tcpStart = time.Now() }) },
		ConnectDone:       func(_, _ string, _ error) { t.update(func() { t.a.TCPMS = time.Since(t.tcpStart).Milliseconds() }) },
		TLSHandshakeStart: func() { t.update(func() { t.a.Stage = "TLS"; t.tlsStart = time.Now() }) },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			t.update(func() { t.a.TLSMS = time.Since(t.tlsStart).Milliseconds() })
		},
		GotConn: func(info httptrace.GotConnInfo) {
			t.update(func() {
				t.a.Stage = "REQUEST"
				host, _, _ := net.SplitHostPort(info.Conn.RemoteAddr().String())
				if ip, err := netip.ParseAddr(host); err == nil {
					if ip.Unmap().Is4() {
						t.a.Family = "IPv4"
					} else {
						t.a.Family = "IPv6"
					}
				}
			})
		},
		WroteHeaders: func() { t.update(func() { t.a.Written = true; t.a.Stage = "RESPONSE_HEADERS" }) },
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			t.update(func() { t.a.Written = true; t.a.Stage = "RESPONSE_HEADERS" })
		},
		GotFirstResponseByte: func() { t.update(func() { t.a.Stage = "RESPONSE_HEADERS" }) },
	}
}

func classify(err error, stage string) string {
	var certificate *tls.CertificateVerificationError
	var dns *net.DNSError
	var timeout net.Error
	if errors.Is(err, errPrivateAddress) {
		return "PREMIUM_ADDRESS_REJECTED"
	}
	if errors.As(err, &certificate) {
		return "PREMIUM_TLS_CERTIFICATE_FAILED"
	}
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		switch stage {
		case "DNS":
			return "PREMIUM_DNS_TIMEOUT"
		case "TCP":
			return "PREMIUM_TCP_TIMEOUT"
		case "TLS":
			return "PREMIUM_TLS_TIMEOUT"
		case "RESPONSE_HEADERS", "RESPONSE_BODY":
			return "PREMIUM_RESPONSE_TIMEOUT"
		default:
			return "PREMIUM_TIMEOUT"
		}
	}
	if errors.As(err, &dns) {
		return "PREMIUM_DNS_FAILED"
	}
	if stage == "TLS" {
		return "PREMIUM_TLS_FAILED"
	}
	if stage == "TCP" {
		return "PREMIUM_TCP_FAILED"
	}
	return "PREMIUM_NETWORK_FAILED"
}

// Trace fields are allowlisted summaries only: never errors, paths, query
// strings, payloads, keys or HTTP response bodies.
func tracedDo(client *http.Client, req *http.Request, route string) (*http.Response, error, attempt) {
	t := &requestTrace{a: attempt{Route: route, Host: req.URL.Hostname(), Stage: "DNS"}, start: time.Now()}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), t.hooks()))
	response, err := client.Do(req)
	var summary attempt
	t.update(func() {
		t.a.ElapsedMS = time.Since(t.start).Milliseconds()
		if err != nil {
			t.a.Code = classify(err, t.a.Stage)
		} else {
			t.a.Code = "OK"
			t.a.Status = response.StatusCode
			t.a.Stage = "RESPONSE_BODY"
		}
		summary = t.a
	})
	return response, err, summary
}

var errPrivateAddress = errors.New("non-public destination")

func publicAddress(host string) bool {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
		return false
	}
	for _, blocked := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "64:ff9b::/96", "2002::/16"} {
		if netip.MustParsePrefix(blocked).Contains(ip) {
			return false
		}
	}
	return true
}

func newClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 7 * time.Second, FallbackDelay: 250 * time.Millisecond, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil || !publicAddress(host) {
			return errPrivateAddress
		}
		return nil
	}}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext: dialer.DialContext, TLSHandshakeTimeout: 7 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		// Go 1.24+ hybrid ML-KEM ClientHello can stall on middleboxes. Use
		// standard X25519/P256 without weakening certificate/TLS validation.
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}},
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func safeMirror(raw string) (string, bool) {
	if len(raw) > 2048 {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Hostname() == "" || (u.Port() != "" && u.Port() != "443") {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if net.ParseIP(host) != nil || !strings.Contains(host, ".") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".localhost") {
		return "", false
	}
	for _, ch := range host {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '.' || ch == '-') {
			return "", false
		}
	}
	if strings.Contains(u.Path, "..") {
		return "", false
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/"
	return u.String(), true
}

func decodeCatalogue(body []byte, publicPEM string) []string {
	if len(body) > 256*1024 {
		return nil
	}
	encrypted, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		return nil
	}
	// PEM whitespace affects upstream SHA512 derivation. The official build
	// can include a trailing newline; accept both public representations.
	for _, key := range []string{publicPEM, publicPEM + "\n"} {
		digest := sha512.Sum512([]byte(key))
		plain, err := decrypt(encrypted, digest[:32], digest[32:48])
		if err != nil {
			continue
		}
		var values []string
		if json.Unmarshal(plain, &values) != nil || len(values) > 256 {
			continue
		}
		result := []string{}
		seen := map[string]bool{}
		for _, raw := range values {
			if value, ok := safeMirror(raw); ok && !seen[value] {
				result = append(result, value)
				seen[value] = true
			}
		}
		return result
	}
	return nil
}

type discovery func(context.Context) ([]string, []attempt)

func discoverMirrors(client *http.Client, input request, bases []string) discovery {
	return func(ctx context.Context) ([]string, []attempt) {
		paths := []string{}
		service, sok := input.Payload["service_type"].(string)
		country, cok := input.Payload["user_country_code"].(string)
		if sok && cok && len(service) < 80 && len(country) < 32 {
			paths = append(paths, base64.RawURLEncoding.EncodeToString([]byte("endpoints-"+service+"-"+country))+".json")
		}
		paths = append(paths, "endpoints.json")
		traces := []attempt{}
		// Try all primary catalogues for the service before generic catalogues.
		for _, path := range paths {
			for _, base := range bases {
				if ctx.Err() != nil {
					return nil, traces
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
				if err != nil {
					continue
				}
				response, err, a := tracedDo(client, req, "catalogue")
				if err != nil {
					traces = append(traces, a)
					continue
				}
				body, readErr := io.ReadAll(io.LimitReader(response.Body, 256*1024+1))
				response.Body.Close()
				if readErr != nil || len(body) > 256*1024 || response.StatusCode != 200 {
					a.Code = "PREMIUM_CATALOGUE_FAILED"
					traces = append(traces, a)
					continue
				}
				values := decodeCatalogue(body, gatewayKey)
				if len(values) == 0 {
					a.Code = "PREMIUM_CATALOGUE_INVALID"
				}
				traces = append(traces, a)
				if len(values) > 0 {
					rand.Shuffle(len(values), func(i, j int) { values[i], values[j] = values[j], values[i] })
					return values, traces
				}
			}
		}
		return nil, traces
	}
}

func sendGateway(client *http.Client, req *http.Request, find discovery) (*http.Response, error, []attempt) {
	response, err, a := tracedDo(client, req, "direct")
	attempts := []attempt{a}
	// A config POST may issue a key. Never blindly replay after bytes were
	// written: timeout does not imply the server did not process the request.
	issuing := strings.HasSuffix(req.URL.Path, "/config")
	if err == nil || find == nil || (issuing && a.Written) || req.Context().Err() != nil {
		return response, err, attempts
	}
	mirrors, events := find(req.Context())
	attempts = append(attempts, events...)
	for index, base := range mirrors {
		if index >= 3 || req.Context().Err() != nil {
			break
		}
		validated, ok := safeMirror(base)
		if !ok {
			continue
		}
		operation := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
		target, parseErr := url.Parse(validated + "v1/" + operation)
		if parseErr != nil {
			continue
		}
		retry := req.Clone(req.Context())
		retry.URL = target
		retry.Host = ""
		if req.GetBody == nil {
			break
		}
		retry.Body, parseErr = req.GetBody()
		if parseErr != nil {
			break
		}
		response, err, a = tracedDo(client, retry, "mirror")
		attempts = append(attempts, a)
		if err == nil || (issuing && a.Written) {
			return response, err, attempts
		}
	}
	return response, err, attempts
}
