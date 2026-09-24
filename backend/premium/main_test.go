package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}))
	var sentPublic string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/config" || r.Method != "POST" {
			t.Error("unexpected request")
		}
		var envelope map[string][]byte
		if json.NewDecoder(r.Body).Decode(&envelope) != nil {
			t.Error("invalid envelope")
			return
		}
		plain, err := rsa.DecryptPKCS1v15(rand.Reader, serverKey, envelope["key_payload"])
		if err != nil {
			t.Error(err)
			return
		}
		var keys map[string][]byte
		_ = json.Unmarshal(plain, &keys)
		payload, err := decrypt(envelope["api_payload"], keys["aes_key"], keys["aes_iv"])
		if err != nil {
			t.Error(err)
			return
		}
		var data map[string]any
		_ = json.Unmarshal(payload, &data)
		sentPublic, _ = data["public_key"].(string)
		if data["auth_data"].(map[string]any)["api_key"] != "test-only" {
			t.Error("missing auth")
		}
		body, _ := encrypt([]byte(`{"config":"synthetic-only"}`), keys["aes_key"], keys["aes_iv"])
		_, _ = w.Write(body)
	}))
	defer server.Close()
	result := exchange(request{"config", map[string]any{"service_protocol": "awg", "auth_data": map[string]string{"api_key": "test-only"}}}, server.Client(), server.URL+"/", pub)
	if result.Code != "OK" || string(result.Data) != `{"config":"synthetic-only"}` {
		t.Fatal("exchange failed", result.Code)
	}
	private, _ := base64.StdEncoding.DecodeString(result.PrivateKey)
	pair, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil || base64.StdEncoding.EncodeToString(pair.PublicKey().Bytes()) != sentPublic {
		t.Fatal("public/private mismatch")
	}
}

func TestRejectInvalidPadding(t *testing.T) {
	key, iv := make([]byte, 32), make([]byte, 32)
	for _, plain := range [][]byte{nil, []byte("short"), bytes.Repeat([]byte{1}, 32)} {
		ciphertext, err := encrypt(plain, key, iv)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decrypt(ciphertext, key, iv)
		if err != nil || !bytes.Equal(decoded, plain) {
			t.Fatal("roundtrip")
		}
	}
	for _, bad := range [][]byte{nil, []byte{1}, make([]byte, 16)} {
		if _, err := decrypt(bad, key, iv); err == nil {
			t.Fatal("accepted invalid ciphertext")
		}
	}
}

func TestHTTPErrorDoesNotExposeBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = io.WriteString(w, "sensitive response must not escape")
	}))
	defer server.Close()
	result := exchange(request{"account_info", map[string]any{}}, server.Client(), server.URL+"/", gatewayKey)
	if result.Code != "PREMIUM_AUTH_FAILED" || result.Data != nil || result.PrivateKey != "" {
		t.Fatal("unsafe error")
	}
}

func TestOperationAllowlist(t *testing.T) {
	for _, operation := range []string{"revoke_config", "../config", "https://attacker.invalid/"} {
		if exchange(request{operation, map[string]any{}}, nil, "", gatewayKey).Code != "PREMIUM_REQUEST_INVALID" {
			t.Fatal(operation)
		}
	}
}
