// V-Deck's independent implementation of the Amnezia gateway wire format.
// Secrets travel on stdin/stdout pipes, never arguments, environment or stderr.
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"time"
)

const maxBytes = 4 << 20
const gateway = "https://gw.amnezia.org/v1/"

// Public encryption key extracted from an Authenticode-verified AmneziaVPN
// release signed by Privacy Technologies OU. This is NOT a subscription key.
const gatewayKey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAj5mxl/4DL3Sk89ntxs5G
X3JawGQWIoq6rvNkOzNGuNgedNS2+pi6hZl3Izl1Io9om4KiUlMT6mgLO1hTr9q+
s7CYhlvroFA7ErucF+9L+7FCt0Igi0kIK/R2/vxd/2HaUrorn/aSvvutkYwbfxqW
SwtzE+RuBeDWGvEt937OW0oqYONPYv9E4T56Dz/EZ6v2t8ejAnKLbGD/GocMmipK
7etFSiSMAB2RmaztqTq4NleBepfO80XpYlW9pCSXuHcE8wxHczkzxsbyMAMsG/K3
vUQY6qPtohqqzSSBwa/8u2ptNHBeor7l7DdYXeR/Nqcc4z92VUkZ5lOVR4evkS5V
/wQqp5tnOJEj3NjUhEhXFoNEapbZd1bh6iQoUk7jC1TdvKJ/nPKGZAsHRpr0rNKz
fx/N/Oo6lr2yh/+ps6VxTkbPmB6E85WOO3UvjImZUY0XQdBjWle/4iJLdEC77Nr0
jXhdgeypucy6jkB6iBHMeVMlrNMEV7UxoBR/cCNx55zu/8sml5ByiDvCDT7sRomN
NgVt5S/FaVjYuzFUifJ12ToChXFgESKFmuso7WluEaWvMIGREdrMrKQKHfYLOzWF
2B5ZJDqw4o03fU4J/6rw61M1b+rjVpXMjPnzc2A+RgcjTvXv955gfZkwe4lt5wk/
3j8zMVo3+zLrMTAaEeIUM0UCAwEAAQ==
-----END PUBLIC KEY-----`

type request struct {
	Operation string         `json:"operation"`
	Payload   map[string]any `json:"payload"`
}
type result struct {
	Code       string          `json:"code"`
	Status     int             `json:"status,omitempty"`
	Data       json.RawMessage `json:"data,omitempty"`
	PrivateKey string          `json:"private_key,omitempty"`
	Attempts   []attempt       `json:"attempts,omitempty"`
}

func encrypt(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil || len(iv) < aes.BlockSize {
		return nil, errors.New("encryption")
	}
	pad := aes.BlockSize - len(data)%aes.BlockSize
	plain := append(append([]byte{}, data...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv[:aes.BlockSize]).CryptBlocks(out, plain)
	return out, nil
}

func decrypt(data, key, iv []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 || len(iv) < aes.BlockSize {
		return nil, errors.New("response")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("response")
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv[:aes.BlockSize]).CryptBlocks(out, data)
	pad := int(out[len(out)-1])
	if pad < 1 || pad > aes.BlockSize || !bytes.Equal(out[len(out)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return nil, errors.New("response")
	}
	return out[:len(out)-pad], nil
}

func exchange(input request, client *http.Client, endpoint, publicPEM string) result {
	return exchangeWithFallback(input, client, endpoint, publicPEM, nil)
}

func exchangeWithFallback(input request, client *http.Client, endpoint, publicPEM string, find discovery) (output result) {
	if input.Payload == nil || (input.Operation != "services" && input.Operation != "account_info" && input.Operation != "config") {
		return result{Code: "PREMIUM_REQUEST_INVALID"}
	}
	key, iv, salt := make([]byte, 32), make([]byte, 32), make([]byte, 8)
	for _, value := range [][]byte{key, iv, salt} {
		if _, err := rand.Read(value); err != nil {
			return result{Code: "PREMIUM_CRYPTO_FAILED"}
		}
	}
	private := ""
	if input.Operation == "config" {
		if input.Payload["service_protocol"] != "awg" {
			return result{Code: "PREMIUM_PROTOCOL_UNSUPPORTED"}
		}
		pair, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return result{Code: "PREMIUM_CRYPTO_FAILED"}
		}
		private = base64.StdEncoding.EncodeToString(pair.Bytes())
		input.Payload["public_key"] = base64.StdEncoding.EncodeToString(pair.PublicKey().Bytes())
	}
	block, _ := pem.Decode([]byte(publicPEM))
	if block == nil {
		return result{Code: "PREMIUM_CRYPTO_FAILED"}
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return result{Code: "PREMIUM_CRYPTO_FAILED"}
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return result{Code: "PREMIUM_CRYPTO_FAILED"}
	}
	keyJSON, _ := json.Marshal(map[string][]byte{"aes_key": key, "aes_iv": iv, "aes_salt": salt})
	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, pub, keyJSON)
	if err != nil {
		return result{Code: "PREMIUM_CRYPTO_FAILED"}
	}
	payload, err := json.Marshal(input.Payload)
	if err != nil {
		return result{Code: "PREMIUM_REQUEST_INVALID"}
	}
	encrypted, err := encrypt(payload, key, iv)
	if err != nil {
		return result{Code: "PREMIUM_CRYPTO_FAILED"}
	}
	body, _ := json.Marshal(map[string][]byte{"key_payload": wrapped, "api_payload": encrypted})
	req, err := http.NewRequest(http.MethodPost, endpoint+input.Operation, bytes.NewReader(body))
	if err != nil {
		return result{Code: "PREMIUM_REQUEST_INVALID"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "V-Deck/0.1.0")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	req = req.WithContext(ctx)
	response, err, attempts := sendGateway(client, req, find)
	defer func() { output.Attempts = attempts }()
	if err != nil {
		for index := len(attempts) - 1; index >= 0; index-- {
			a := attempts[index]
			if a.Route == "catalogue" {
				continue
			}
			if input.Operation == "config" && a.Written {
				return result{Code: "PREMIUM_REQUEST_UNCERTAIN"}
			}
			return result{Code: a.Code}
		}
		return result{Code: "PREMIUM_NETWORK_FAILED"}
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		code := classify(err, "RESPONSE_BODY")
		attempts[len(attempts)-1].Code = code
		if input.Operation == "config" {
			code = "PREMIUM_REQUEST_UNCERTAIN"
		}
		return result{Code: code, Status: response.StatusCode}
	}
	if len(data) > maxBytes {
		attempts[len(attempts)-1].Code = "PREMIUM_RESPONSE_INVALID"
		return result{Code: "PREMIUM_RESPONSE_INVALID", Status: response.StatusCode}
	}
	if response.StatusCode != http.StatusOK {
		codes := map[int]string{401: "PREMIUM_AUTH_FAILED", 403: "PREMIUM_AUTH_FAILED", 402: "PREMIUM_SUBSCRIPTION_EXPIRED", 409: "PREMIUM_API_CONFLICT", 429: "PREMIUM_RATE_LIMITED", 451: "PREMIUM_REGION_RESTRICTED", 501: "PREMIUM_CLIENT_UPDATE_REQUIRED"}
		code := codes[response.StatusCode]
		if code == "" {
			code = "PREMIUM_API_FAILED"
		}
		return result{Code: code, Status: response.StatusCode}
	}
	plain, err := decrypt(data, key, iv)
	if err != nil || !json.Valid(plain) {
		return result{Code: "PREMIUM_RESPONSE_INVALID", Status: response.StatusCode}
	}
	return result{Code: "OK", Status: response.StatusCode, Data: plain, PrivateKey: private}
}

func main() {
	// No proxy inherited from Decky; no cross-host redirects; HTTPS verification
	// is mandatory, since the gateway's CBC envelope is not authenticated.
	client := newClient(12 * time.Second)
	inputBytes, err := io.ReadAll(io.LimitReader(os.Stdin, maxBytes+1))
	var input request
	output := result{Code: "PREMIUM_REQUEST_INVALID"}
	if err == nil && len(inputBytes) <= maxBytes && json.Unmarshal(inputBytes, &input) == nil {
		output = exchangeWithFallback(input, client, gateway, gatewayKey, discoverMirrors(newClient(4*time.Second), input, catalogueBases))
	}
	_ = json.NewEncoder(os.Stdout).Encode(output)
}
