// GCP REST access: metadata access token, KMS encrypt/decrypt, Secret Manager.

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Google endpoints. Variables only so tests can point them at fakes.
var (
	metadataTokenURL     = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
	kmsBaseURL           = "https://cloudkms.googleapis.com/v1/"
	secretManagerBaseURL = "https://secretmanager.googleapis.com/v1/"
)

const (
	maxGCPResponse = 64 << 10 // metadata, KMS and Secret Manager responses are tiny
	tokenMargin    = 60 * time.Second
)

// gcpCall sends req with c and decodes a 200 JSON response into out. Errors carry only a status
// code or a fixed phrase: never a URL, a response body, or a transport error (which names hosts).
// requireFlavor additionally demands the metadata server's "Metadata-Flavor: Google" header.
func gcpCall(c *http.Client, req *http.Request, requireFlavor bool, out any) error {
	if c == nil {
		return errors.New("no HTTP client")
	}
	resp, err := c.Do(req)
	if err != nil {
		return errors.New("request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	if requireFlavor && resp.Header.Get("Metadata-Flavor") != "Google" {
		return errors.New("response is not from the metadata server")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGCPResponse+1))
	defer zero(body) // may hold secret material; best effort
	if err != nil {
		return errors.New("reading response failed")
	}
	if len(body) > maxGCPResponse {
		return errors.New("response too large")
	}
	if err := json.Unmarshal(body, out); err != nil {
		return errors.New("malformed response")
	}
	return nil
}

// tokenSource fetches the service account's access token from the metadata server
// and caches it until 60s before it expires.
type tokenSource struct {
	client *http.Client
	mu     sync.Mutex
	tok    string
	exp    time.Time
}

// token returns a cached or freshly fetched access token.
// The token must be 1–4096 printable non-space ASCII chars (it goes into an
// Authorization header and a DB password) and expires_in must be positive.
func (ts *tokenSource) token(ctx context.Context) (string, error) {
	if ts == nil {
		return "", errors.New("metadata token: no token source")
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.tok != "" && time.Now().Before(ts.exp.Add(-tokenMargin)) {
		return ts.tok, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataTokenURL, nil)
	if err != nil {
		return "", errors.New("metadata token: invalid request")
	}
	req.Header.Set("Metadata-Flavor", "Google")
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := gcpCall(ts.client, req, true, &out); err != nil {
		return "", errors.New("metadata token: " + err.Error())
	}
	if out.ExpiresIn <= 0 || out.ExpiresIn > 86400 || out.AccessToken == "" || len(out.AccessToken) > 4096 {
		return "", errors.New("metadata token: invalid token response")
	}
	for i := 0; i < len(out.AccessToken); i++ {
		if c := out.AccessToken[i]; c < 0x21 || c > 0x7e {
			return "", errors.New("metadata token: invalid token response")
		}
	}
	ts.tok = out.AccessToken
	ts.exp = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return ts.tok, nil
}

// kmsResponse covers both encrypt ({ciphertext}) and decrypt ({plaintext}) responses.
type kmsResponse struct {
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

// kmsPost calls POST {kmsBaseURL}{key}:{verb} with {field: base64(data)}.
func kmsPost(ctx context.Context, c *http.Client, ts *tokenSource, key, verb, field string, data []byte) (kmsResponse, error) {
	var out kmsResponse
	if !kmsKeyRe.MatchString(key) {
		return out, errors.New("kms " + verb + ": invalid key name")
	}
	tok, err := ts.token(ctx)
	if err != nil {
		return out, err
	}
	// The encrypt body carries the plaintext DEK. The base64 string cannot be zeroed; the
	// marshalled body is zeroed best effort.
	body, err := json.Marshal(map[string]string{field: base64.StdEncoding.EncodeToString(data)})
	defer zero(body)
	if err != nil {
		return out, errors.New("kms " + verb + ": encoding failed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, kmsBaseURL+key+":"+verb, bytes.NewReader(body))
	if err != nil {
		return out, errors.New("kms " + verb + ": invalid request")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	if err := gcpCall(c, req, false, &out); err != nil {
		return out, errors.New("kms " + verb + ": " + err.Error())
	}
	return out, nil
}

// kmsDecrypt unwraps a DEK via KMS decrypt. The plaintext must be exactly 32 bytes.
func kmsDecrypt(ctx context.Context, c *http.Client, ts *tokenSource, key string, wrapped []byte) ([]byte, error) {
	out, err := kmsPost(ctx, c, ts, key, "decrypt", "ciphertext", wrapped)
	if err != nil {
		return nil, err
	}
	pt, err := base64.StdEncoding.DecodeString(out.Plaintext)
	if err != nil || len(pt) != dekSize {
		zero(pt)
		return nil, errors.New("kms decrypt: plaintext is not a 32-byte DEK")
	}
	return pt, nil
}

// kmsEncrypt wraps plaintext via KMS encrypt and returns the ciphertext.
func kmsEncrypt(ctx context.Context, c *http.Client, ts *tokenSource, key string, plaintext []byte) ([]byte, error) {
	out, err := kmsPost(ctx, c, ts, key, "encrypt", "plaintext", plaintext)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(out.Ciphertext)
	if err != nil || len(ct) == 0 {
		return nil, errors.New("kms encrypt: malformed ciphertext")
	}
	return ct, nil
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// accessSecret reads the latest version of a Secret Manager secret:
// GET {secretManagerBaseURL}{name}/versions/latest:access → payload.data (base64).
// When the response carries payload.dataCrc32c it must match the data.
func accessSecret(ctx context.Context, c *http.Client, ts *tokenSource, name string) ([]byte, error) {
	if !secretNameRe.MatchString(name) {
		return nil, errors.New("secret manager: invalid secret name")
	}
	tok, err := ts.token(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, secretManagerBaseURL+name+"/versions/latest:access", nil)
	if err != nil {
		return nil, errors.New("secret manager: invalid request")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	var out struct {
		Payload struct {
			Data       string      `json:"data"`
			DataCrc32c json.Number `json:"dataCrc32c"`
		} `json:"payload"`
	}
	if err := gcpCall(c, req, false, &out); err != nil {
		return nil, errors.New("secret manager: " + err.Error())
	}
	data, err := base64.StdEncoding.DecodeString(out.Payload.Data)
	if err != nil {
		return nil, errors.New("secret manager: malformed payload")
	}
	if out.Payload.DataCrc32c != "" {
		want, err := strconv.ParseUint(string(out.Payload.DataCrc32c), 10, 32)
		if err != nil || uint32(want) != crc32.Checksum(data, castagnoli) {
			zero(data)
			return nil, errors.New("secret manager: payload checksum mismatch")
		}
	}
	return data, nil
}
