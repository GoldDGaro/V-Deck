package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

type timeoutError struct{}

func (timeoutError) Error() string   { return "sensitive provider error MUST NOT escape" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestTLSCompatibilityPolicy(t *testing.T) {
	client := newClient(time.Second)
	transport := client.Transport.(*http.Transport)
	config := transport.TLSClientConfig
	if config.InsecureSkipVerify || config.MinVersion < tls.VersionTLS12 || transport.Proxy != nil {
		t.Fatal("unsafe transport")
	}
	if len(config.CurvePreferences) != 2 || config.CurvePreferences[0] != tls.X25519 || config.CurvePreferences[1] != tls.CurveP256 {
		t.Fatal("oversized default ClientHello returned")
	}
	if client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects must not forward payload")
	}
}

func TestTLSHandshakeTimeoutStage(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			<-done
		}
	}()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSHandshakeTimeout: 30 * time.Millisecond}}
	req, _ := http.NewRequest(http.MethodPost, "https://"+listener.Addr().String()+"/v1/account_info", strings.NewReader("secret-not-sent"))
	_, err, a := tracedDo(client, req, "direct")
	if err == nil || a.Code != "PREMIUM_TLS_TIMEOUT" || a.Stage != "TLS" || a.Written {
		t.Fatalf("unexpected trace: %+v", a)
	}
	encoded, _ := json.Marshal(a)
	if bytes.Contains(encoded, []byte("secret")) {
		t.Fatal("secret in trace")
	}
}

func TestFallbackReplaysIdenticalEncryptedBodyBeforeWrite(t *testing.T) {
	var bodies [][]byte
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		req.Body.Close()
		bodies = append(bodies, body)
		trace := httptrace.ContextClientTrace(req.Context())
		if req.URL.Host == "gw.amnezia.org" {
			trace.TLSHandshakeStart()
			return nil, timeoutError{}
		}
		if req.URL.String() != "https://mirror.example/api/v1/config" {
			t.Fatal("wrong mirror path")
		}
		trace.WroteHeaders()
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("encrypted-response")), Header: make(http.Header)}, nil
	})}
	req, _ := http.NewRequest(http.MethodPost, gateway+"config", strings.NewReader("identical-envelope"))
	response, err, traces := sendGateway(client, req, func(context.Context) ([]string, []attempt) { return []string{"https://mirror.example/api/"}, nil })
	if err != nil || response == nil || len(traces) != 2 || len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("fallback failed")
	}
	response.Body.Close()
	if traces[0].Code != "PREMIUM_TLS_TIMEOUT" || traces[1].Route != "mirror" {
		t.Fatal("missing evidence")
	}
}

func TestConfigIsNotReplayedAfterRequestWrite(t *testing.T) {
	for _, operation := range []string{"config", "account_info"} {
		t.Run(operation, func(t *testing.T) {
			calls, discoveries := 0, 0
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				httptrace.ContextClientTrace(req.Context()).WroteHeaders()
				return nil, timeoutError{}
			})}
			req, _ := http.NewRequest(http.MethodPost, gateway+operation, strings.NewReader("encrypted"))
			_, _, traces := sendGateway(client, req, func(context.Context) ([]string, []attempt) {
				discoveries++
				return []string{"https://mirror.example/"}, nil
			})
			if operation == "config" && (calls != 1 || discoveries != 0) {
				t.Fatal("config reissued")
			}
			if operation == "account_info" && calls != 2 {
				t.Fatal("read-only retry missing")
			}
			if traces[0].Code != "PREMIUM_RESPONSE_TIMEOUT" {
				t.Fatal("wrong response stage")
			}
		})
	}
}

func TestMirrorTrustBoundary(t *testing.T) {
	for _, value := range []string{"http://example.org/", "https://127.0.0.1/", "https://[::1]/", "https://user:pass@example.org/", "https://example.org/?secret=x", "https://example.org:444/", "https://example.local/", "https://example.org/../admin"} {
		if _, ok := safeMirror(value); ok {
			t.Fatal("unsafe URL accepted", value)
		}
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "100.64.0.1", "fe80::1", "fc00::1", "224.0.0.1"} {
		if publicAddress(ip) {
			t.Fatal("non-public address", ip)
		}
	}
	if !publicAddress("1.1.1.1") || !publicAddress("2606:4700:4700::1111") {
		t.Fatal("public address rejected")
	}
}

func TestCatalogueWireFormatAndFiltering(t *testing.T) {
	for _, key := range []string{gatewayKey, gatewayKey + "\n"} {
		digest := sha512.Sum512([]byte(key))
		body, _ := encrypt([]byte(`["https://mirror.example/","http://unsafe.example/","https://mirror.example/"]`), digest[:32], digest[32:48])
		urls := decodeCatalogue([]byte(base64.StdEncoding.EncodeToString(body)), gatewayKey)
		if len(urls) != 1 || urls[0] != "https://mirror.example/" {
			t.Fatal("catalogue rejected or unfiltered")
		}
	}
	if len(decodeCatalogue([]byte("invalid"), gatewayKey)) != 0 {
		t.Fatal("invalid catalogue accepted")
	}
}

func TestNetworkErrorClassificationAndRedaction(t *testing.T) {
	for _, stage := range []string{"DNS", "TCP", "TLS", "RESPONSE_HEADERS"} {
		code := classify(timeoutError{}, stage)
		if !strings.HasPrefix(code, "PREMIUM_") || strings.Contains(code, "sensitive") {
			t.Fatal(code)
		}
	}
	if classify(&tls.CertificateVerificationError{Err: errors.New("secret")}, "TLS") != "PREMIUM_TLS_CERTIFICATE_FAILED" {
		t.Fatal("certificate")
	}
	if classify(errPrivateAddress, "TCP") != "PREMIUM_ADDRESS_REJECTED" {
		t.Fatal("private network")
	}
	if classify(&net.DNSError{IsTimeout: true}, "DNS") != "PREMIUM_DNS_TIMEOUT" {
		t.Fatal("DNS timeout misclassified")
	}
}

type failedBody struct{}

func (failedBody) Read([]byte) (int, error) { return 0, timeoutError{} }
func (failedBody) Close() error             { return nil }

func TestUncertainConfigAndBodyTimeoutCodes(t *testing.T) {
	for _, operation := range []string{"account_info", "config"} {
		for _, bodyTimeout := range []bool{false, true} {
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				req.Body.Close()
				httptrace.ContextClientTrace(req.Context()).WroteHeaders()
				if bodyTimeout {
					return &http.Response{StatusCode: 200, Body: failedBody{}, Header: make(http.Header)}, nil
				}
				return nil, timeoutError{}
			})}
			output := exchangeWithFallback(request{operation, map[string]any{"service_protocol": "awg"}}, client, gateway, gatewayKey, func(context.Context) ([]string, []attempt) {
				if operation == "config" {
					t.Fatal("must not discover/replay issued config")
				}
				return nil, nil
			})
			want := "PREMIUM_RESPONSE_TIMEOUT"
			if operation == "config" {
				want = "PREMIUM_REQUEST_UNCERTAIN"
			}
			if output.Code != want || calls != 1 || len(output.Attempts) != 1 || output.Attempts[0].Code != "PREMIUM_RESPONSE_TIMEOUT" || output.PrivateKey != "" || output.Data != nil {
				t.Fatalf("unexpected result: code=%s calls=%d traces=%+v", output.Code, calls, output.Attempts)
			}
		}
	}
}

func TestProductionDialBlocksPrivateDestinations(t *testing.T) {
	client := newClient(time.Second)
	req, _ := http.NewRequest(http.MethodGet, "https://127.0.0.1:443/", nil)
	_, err, trace := tracedDo(client, req, "mirror")
	if err == nil || trace.Code != "PREMIUM_ADDRESS_REJECTED" {
		t.Fatalf("unsafe dial: %+v", trace)
	}
}
