package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// ---------------------------------------------------------------------------
// Boot: config, GCP REST access, secrets, DB pool, client CA, servers
// These tests replace package-level base URLs and must not call t.Parallel.
// ---------------------------------------------------------------------------

// pointURL sets *p to v for the duration of the test.
func pointURL(t *testing.T, p *string, v string) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

func testDevEnv() map[string]string {
	return map[string]string{
		"VAULT_ENV":                  "dev",
		"VAULT_CERT":                 "/etc/vault/srv-cert.pem",
		"VAULT_KEY":                  "/etc/vault/srv-key.pem",
		"VAULT_CLIENT_CA":            "/etc/vault/client-ca.pem",
		"VAULT_ALLOW_ORIGIN":         testOrigin,
		"VAULT_DB_URL":               "postgres://vault_app:pw-x9q@db.internal/vault",
		"VAULT_DEV_DEK_HEX":          strings.Repeat("ab", 32),
		"VAULT_DEV_SESSION_HMAC_HEX": strings.Repeat("cd", 32),
		// The embedded catalog's one dev account secret (stripe_test/secretKey).
		"VAULT_DEV_SECRET_STRIPE_TEST_SECRETKEY": testSecret,
	}
}

func testProdEnv() map[string]string {
	return map[string]string{
		"VAULT_ENV":                 "prod",
		"VAULT_CERT":                "/etc/vault/srv-cert.pem",
		"VAULT_KEY":                 "/etc/vault/srv-key.pem",
		"VAULT_CLIENT_CA":           "/etc/vault/client-ca.pem",
		"VAULT_ALLOW_ORIGIN":        testOrigin,
		"VAULT_DB_URL":              "postgres://vault_app@10.1.2.3/vault?sslmode=verify-full",
		"VAULT_KMS_KEY":             testKMSKey,
		"VAULT_SESSION_HMAC_SECRET": testHMACName,
	}
}

// envWith copies base and applies over; a value of omit deletes the key.
func envWith(base, over map[string]string) map[string]string {
	m := maps.Clone(base)
	for k, v := range over {
		if v == omit {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return m
}

func TestLoadConfig(t *testing.T) {
	rotEnv := map[string]string{"VAULT_ENV": "prod", "VAULT_DB_URL": "postgres://vault_rotator@10.1.2.3/vault?sslmode=verify-full", "VAULT_KMS_KEY": testKMSKey}
	cases := []struct {
		name    string
		env     map[string]string
		rotate  bool
		mention string // non-empty: an error naming this variable is expected
	}{
		{"dev with all dev vars", testDevEnv(), false, ""},
		{"dev custom addrs", envWith(testDevEnv(), map[string]string{"VAULT_PUBLIC_ADDR": "127.0.0.1:1", "VAULT_INTERNAL_ADDR": "127.0.0.1:2"}), false, ""},
		{"dev http localhost origin", envWith(testDevEnv(), map[string]string{"VAULT_ALLOW_ORIGIN": "http://localhost:3000"}), false, ""},
		{"dev KMS instead of dev DEK", envWith(testDevEnv(), map[string]string{"VAULT_DEV_DEK_HEX": omit, "VAULT_KMS_KEY": testKMSKey}), false, ""},
		{"dev SM instead of dev secrets", envWith(testDevEnv(), map[string]string{"VAULT_DEV_SESSION_HMAC_HEX": omit, "VAULT_SESSION_HMAC_SECRET": testHMACName, "VAULT_DEV_SECRET_STRIPE_TEST_SECRETKEY": omit}), false, ""},
		{"prod", testProdEnv(), false, ""},
		{"missing VAULT_ENV", envWith(testDevEnv(), map[string]string{"VAULT_ENV": omit}), false, "VAULT_ENV"},
		{"VAULT_ENV staging", envWith(testDevEnv(), map[string]string{"VAULT_ENV": "staging"}), false, "VAULT_ENV"},
		{"VAULT_ENV Prod", envWith(testProdEnv(), map[string]string{"VAULT_ENV": "Prod"}), false, "VAULT_ENV"},
		{"dev missing VAULT_CERT", envWith(testDevEnv(), map[string]string{"VAULT_CERT": omit}), false, "VAULT_CERT"},
		{"dev missing VAULT_KEY", envWith(testDevEnv(), map[string]string{"VAULT_KEY": omit}), false, "VAULT_KEY"},
		{"dev missing VAULT_CLIENT_CA", envWith(testDevEnv(), map[string]string{"VAULT_CLIENT_CA": omit}), false, "VAULT_CLIENT_CA"},
		{"dev missing VAULT_ALLOW_ORIGIN", envWith(testDevEnv(), map[string]string{"VAULT_ALLOW_ORIGIN": omit}), false, "VAULT_ALLOW_ORIGIN"},
		{"dev missing VAULT_DB_URL", envWith(testDevEnv(), map[string]string{"VAULT_DB_URL": omit}), false, "VAULT_DB_URL"},
		{"origin trailing slash", envWith(testDevEnv(), map[string]string{"VAULT_ALLOW_ORIGIN": testOrigin + "/"}), false, "VAULT_ALLOW_ORIGIN"},
		{"origin wildcard", envWith(testDevEnv(), map[string]string{"VAULT_ALLOW_ORIGIN": "*"}), false, "VAULT_ALLOW_ORIGIN"},
		{"origin with path", envWith(testDevEnv(), map[string]string{"VAULT_ALLOW_ORIGIN": testOrigin + "/pay"}), false, "VAULT_ALLOW_ORIGIN"},
		{"origin with query", envWith(testDevEnv(), map[string]string{"VAULT_ALLOW_ORIGIN": testOrigin + "?a=1"}), false, "VAULT_ALLOW_ORIGIN"},
		{"origin with userinfo", envWith(testDevEnv(), map[string]string{"VAULT_ALLOW_ORIGIN": "https://u@checkout.example.com"}), false, "VAULT_ALLOW_ORIGIN"},
		{"origin default https port", envWith(testDevEnv(), map[string]string{"VAULT_ALLOW_ORIGIN": testOrigin + ":443"}), false, "VAULT_ALLOW_ORIGIN"},
		{"prod origin default https port", envWith(testProdEnv(), map[string]string{"VAULT_ALLOW_ORIGIN": testOrigin + ":443"}), false, "VAULT_ALLOW_ORIGIN"},
		{"origin default http port", envWith(testDevEnv(), map[string]string{"VAULT_ALLOW_ORIGIN": "http://localhost:80"}), false, "VAULT_ALLOW_ORIGIN"},
		{"prod http origin", envWith(testProdEnv(), map[string]string{"VAULT_ALLOW_ORIGIN": "http://checkout.example.com"}), false, "VAULT_ALLOW_ORIGIN"},
		{"prod missing VAULT_KMS_KEY", envWith(testProdEnv(), map[string]string{"VAULT_KMS_KEY": omit}), false, "VAULT_KMS_KEY"},
		{"prod missing VAULT_SESSION_HMAC_SECRET", envWith(testProdEnv(), map[string]string{"VAULT_SESSION_HMAC_SECRET": omit}), false, "VAULT_SESSION_HMAC_SECRET"},
		{"prod + VAULT_DEV_DEK_HEX", envWith(testProdEnv(), map[string]string{"VAULT_DEV_DEK_HEX": strings.Repeat("ab", 32)}), false, "VAULT_DEV_DEK_HEX"},
		{"prod + VAULT_DEV_SESSION_HMAC_HEX", envWith(testProdEnv(), map[string]string{"VAULT_DEV_SESSION_HMAC_HEX": strings.Repeat("cd", 32)}), false, "VAULT_DEV_SESSION_HMAC_HEX"},
		{"dev DEK 63 hex", envWith(testDevEnv(), map[string]string{"VAULT_DEV_DEK_HEX": strings.Repeat("ab", 31) + "a"}), false, "VAULT_DEV_DEK_HEX"},
		{"dev DEK 66 hex", envWith(testDevEnv(), map[string]string{"VAULT_DEV_DEK_HEX": strings.Repeat("ab", 33)}), false, "VAULT_DEV_DEK_HEX"},
		{"dev DEK not hex", envWith(testDevEnv(), map[string]string{"VAULT_DEV_DEK_HEX": strings.Repeat("zq", 32)}), false, "VAULT_DEV_DEK_HEX"},
		{"dev HMAC 63 hex", envWith(testDevEnv(), map[string]string{"VAULT_DEV_SESSION_HMAC_HEX": strings.Repeat("cd", 31) + "c"}), false, "VAULT_DEV_SESSION_HMAC_HEX"},
		{"dev no DEK source", envWith(testDevEnv(), map[string]string{"VAULT_DEV_DEK_HEX": omit}), false, "VAULT_KMS_KEY"},
		{"dev no HMAC source", envWith(testDevEnv(), map[string]string{"VAULT_DEV_SESSION_HMAC_HEX": omit}), false, "VAULT_SESSION_HMAC_SECRET"},
		{"KMS key bad shape", envWith(testProdEnv(), map[string]string{"VAULT_KMS_KEY": "projects/p1/locations/global/keyRings/r1/cryptoKeys/../k1"}), false, "VAULT_KMS_KEY"},
		{"KMS key with query", envWith(testProdEnv(), map[string]string{"VAULT_KMS_KEY": testKMSKey + "?x=1"}), false, "VAULT_KMS_KEY"},
		{"HMAC secret bad shape", envWith(testProdEnv(), map[string]string{"VAULT_SESSION_HMAC_SECRET": "projects/p1/secrets/s/versions/3"}), false, "VAULT_SESSION_HMAC_SECRET"},
		{"rotate prod only ENV/DB/KMS", rotEnv, true, ""},
		{"rotate dev only ENV/DB/KMS", envWith(rotEnv, map[string]string{"VAULT_ENV": "dev"}), true, ""},
		{"rotate missing KMS", envWith(rotEnv, map[string]string{"VAULT_KMS_KEY": omit}), true, "VAULT_KMS_KEY"},
		{"rotate missing DB", envWith(rotEnv, map[string]string{"VAULT_DB_URL": omit}), true, "VAULT_DB_URL"},
		{"rotate missing ENV", envWith(rotEnv, map[string]string{"VAULT_ENV": omit}), true, "VAULT_ENV"},
		{"rotate prod + VAULT_DEV_DEK_HEX", envWith(rotEnv, map[string]string{"VAULT_DEV_DEK_HEX": strings.Repeat("ab", 32)}), true, "VAULT_DEV_DEK_HEX"},
		{"serve with only rotate vars", rotEnv, false, "VAULT_CERT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := loadConfig(func(k string) string { return c.env[k] }, c.rotate)
			if c.mention == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("no error; want one naming %s", c.mention)
			}
			if !strings.Contains(err.Error(), c.mention) {
				t.Errorf("error %q does not name %s", err, c.mention)
			}
			for k, v := range c.env {
				if v != "dev" && v != "prod" && strings.Contains(err.Error(), v) {
					t.Errorf("error contains the value of %s", k) // never print the value
				}
			}
			_ = cfg
		})
	}

	// Field mapping and defaults.
	cfg, err := loadConfig(func(k string) string { return testDevEnv()[k] }, false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.env != "dev" || cfg.publicAddr != ":8443" || cfg.internalAddr != ":9443" ||
		cfg.certFile != "/etc/vault/srv-cert.pem" || cfg.keyFile != "/etc/vault/srv-key.pem" ||
		cfg.clientCAFile != "/etc/vault/client-ca.pem" || cfg.allowOrigin != testOrigin ||
		cfg.dbURL != testDevEnv()["VAULT_DB_URL"] || cfg.kmsKey != "" {
		t.Error("dev config fields or defaults wrong")
	}
	if !bytes.Equal(cfg.devDEK, bytes.Repeat([]byte{0xab}, 32)) || !bytes.Equal(cfg.devHMAC, bytes.Repeat([]byte{0xcd}, 32)) {
		t.Error("dev secrets not decoded")
	}
	cfg, err = loadConfig(func(k string) string { return testProdEnv()[k] }, false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.env != "prod" || cfg.kmsKey != testKMSKey || cfg.hmacSecretName != testHMACName ||
		cfg.devDEK != nil || cfg.devHMAC != nil {
		t.Error("prod config fields wrong")
	}
	cfg, err = loadConfig(func(k string) string { return rotEnv[k] }, true)
	if err != nil || cfg.env != "prod" || cfg.kmsKey != testKMSKey || cfg.dbURL != rotEnv["VAULT_DB_URL"] {
		t.Error("rotate config fields wrong")
	}
}

// TestValidOrigin covers the serialized-origin shape check. An origin carrying its
// scheme's default port, or any other port spelling a browser never sends, refuses boot: it
// could only produce a permanent 403.
func TestValidOrigin(t *testing.T) {
	for _, c := range []struct {
		origin   string
		prod, ok bool
	}{
		{"https://checkout.example.com", true, true},
		{"https://checkout.example.com:8443", true, true},
		{"https://checkout.example.com:65535", true, true},
		{"https://checkout.example.com:1", true, true},
		{"https://[2001:db8::1]:8443", true, true},
		{"http://localhost:3000", false, true},
		{"http://localhost", false, true},
		{"https://checkout.example.com:443", true, false},
		{"https://checkout.example.com:443", false, false},
		{"https://[2001:db8::1]:443", true, false},
		{"http://localhost:80", false, false},
		{"https://checkout.example.com:", true, false},
		{"https://checkout.example.com:0443", true, false},
		{"https://checkout.example.com:08443", true, false},
		{"https://checkout.example.com:0", true, false},
		{"https://checkout.example.com:65536", true, false},
		{"http://localhost:3000", true, false},
		{"https://checkout.example.com/", true, false},
		{"https://Checkout.example.com", true, false},
		{"*", true, false},
	} {
		if got := validOrigin(c.origin, c.prod); got != c.ok {
			t.Errorf("validOrigin(%q, prod=%v) = %v, want %v", c.origin, c.prod, got, c.ok)
		}
	}
}

func TestDevVarSet(t *testing.T) {
	if name, ok := devVarSet([]string{"PATH=/bin", "VAULT_ENV=prod", "VAULT_DEV_ANYTHING=", "HOME=/root"}); !ok || name != "VAULT_DEV_ANYTHING" {
		t.Errorf("got %q %v, want VAULT_DEV_ANYTHING", name, ok)
	}
	if _, ok := devVarSet([]string{"PATH=/bin", "VAULT_ENV=prod", "XVAULT_DEV_X=1", "VAULT_DEVX=1"}); ok {
		t.Error("false positive")
	}
}

func TestTokenSourceCaches(t *testing.T) {
	hits := newFakeMetadata(t, nil)
	ts := &tokenSource{client: newOutboundClient(nil)}
	ctx := context.Background()
	for i := range 2 {
		tok, err := ts.token(ctx)
		if err != nil || tok != testGCPToken {
			t.Fatalf("call %d: token wrong, err %v", i, err)
		}
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("metadata hits %d, want 1", n)
	}
	// Within 60s of expiry the token is refreshed.
	ts.mu.Lock()
	ts.exp = time.Now().Add(59 * time.Second)
	ts.mu.Unlock()
	if _, err := ts.token(ctx); err != nil {
		t.Fatal(err)
	}
	if n := hits.Load(); n != 2 {
		t.Errorf("metadata hits %d after near-expiry, want 2", n)
	}
}

func TestTokenSourceRejects(t *testing.T) {
	good := func(w http.ResponseWriter, body string) {
		w.Header().Set("Metadata-Flavor", "Google")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}
	cases := map[string]func(w http.ResponseWriter){
		"status 500":         func(w http.ResponseWriter) { w.Header().Set("Metadata-Flavor", "Google"); w.WriteHeader(500) },
		"redirect":           func(w http.ResponseWriter) { w.Header().Set("Location", "http://evil.example/"); w.WriteHeader(302) },
		"no flavor header":   func(w http.ResponseWriter) { io.WriteString(w, `{"access_token":"abc","expires_in":3599}`) },
		"empty token":        func(w http.ResponseWriter) { good(w, `{"access_token":"","expires_in":3599}`) },
		"token with space":   func(w http.ResponseWriter) { good(w, `{"access_token":"ab c","expires_in":3599}`) },
		"token with newline": func(w http.ResponseWriter) { good(w, `{"access_token":"abc\r\nX: y","expires_in":3599}`) },
		"zero expiry":        func(w http.ResponseWriter) { good(w, `{"access_token":"abc","expires_in":0}`) },
		"not json":           func(w http.ResponseWriter) { good(w, `nope`) },
		"oversize": func(w http.ResponseWriter) {
			good(w, `{"access_token":"`+strings.Repeat("a", 1<<20)+`","expires_in":3599}`)
		},
	}
	for name, respond := range cases {
		t.Run(name, func(t *testing.T) {
			newFakeMetadata(t, respond)
			ts := &tokenSource{client: newOutboundClient(nil)}
			if tok, err := ts.token(context.Background()); err == nil {
				t.Errorf("accepted (token len %d)", len(tok))
			}
		})
	}
}

func TestKMSRoundTrip(t *testing.T) {
	newFakeMetadata(t, nil)
	k := newFakeKMS(t)
	c := newOutboundClient(nil)
	ts := &tokenSource{client: c}
	ctx := context.Background()
	pt := make([]byte, 32)
	for i := range pt {
		pt[i] = byte(i + 1)
	}
	wrapped, err := kmsEncrypt(ctx, c, ts, testKMSKey, pt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wrapped, reversed(pt)) {
		t.Error("encrypt did not return the KMS ciphertext")
	}
	got, err := kmsDecrypt(ctx, c, ts, testKMSKey, wrapped)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("decrypt round trip failed: %v", err)
	}

	k.setMode("short")
	if got, err := kmsDecrypt(ctx, c, ts, testKMSKey, wrapped); err == nil {
		t.Errorf("31-byte plaintext accepted (len %d)", len(got))
	}
	k.setMode("500")
	if _, err := kmsDecrypt(ctx, c, ts, testKMSKey, wrapped); err == nil {
		t.Error("decrypt: status 500 accepted")
	} else if strings.Contains(err.Error(), testKMSKey) {
		t.Error("error names the key")
	}
	if _, err := kmsEncrypt(ctx, c, ts, testKMSKey, pt); err == nil {
		t.Error("encrypt: status 500 accepted")
	}
	k.setMode("")
	before := k.count()
	for _, bad := range []string{"", "projects/p1/locations/global/keyRings/r1/cryptoKeys/k1/../../x", testKMSKey + "?a=b"} {
		if _, err := kmsDecrypt(ctx, c, ts, bad, wrapped); err == nil {
			t.Error("bad key name accepted")
		}
	}
	if k.count() != before {
		t.Error("bad key name reached KMS")
	}
}

func TestAccessSecret(t *testing.T) {
	newFakeMetadata(t, nil)
	newFakeSecretManager(t, map[string]string{testStripeName: testSecret}, false)
	c := newOutboundClient(nil)
	ts := &tokenSource{client: c}
	ctx := context.Background()
	got, err := accessSecret(ctx, c, ts, testStripeName)
	if err != nil || string(got) != testSecret {
		t.Fatalf("payload wrong (len %d), err %v", len(got), err)
	}
	if _, err := accessSecret(ctx, c, ts, "projects/p1/secrets/missing"); err == nil {
		t.Error("404 accepted")
	}
	if _, err := accessSecret(ctx, c, ts, "projects/p1/secrets/../x"); err == nil {
		t.Error("bad name accepted")
	}

	newFakeSecretManager(t, map[string]string{testStripeName: testSecret}, true)
	if _, err := accessSecret(ctx, c, ts, testStripeName); err == nil {
		t.Error("CRC mismatch accepted")
	}
}

func TestLoadSecrets(t *testing.T) {
	ctx := context.Background()
	hmacKey := bytes.Repeat([]byte{0x5a}, 32)

	// Dev value: no network at all (nil client and token source).
	k, err := loadSecrets(ctx, config{env: "dev", devHMAC: hmacKey}, nil, nil)
	if err != nil || !bytes.Equal(k, hmacKey) {
		t.Fatalf("dev secret wrong: %v", err)
	}
	for name, cfg := range map[string]config{
		"HMAC 31 bytes":      {env: "dev", devHMAC: hmacKey[:31]},
		"prod with dev HMAC": {env: "prod", devHMAC: hmacKey, hmacSecretName: testHMACName},
	} {
		if _, err := loadSecrets(ctx, cfg, nil, nil); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), hex.EncodeToString(hmacKey)) {
			t.Errorf("%s: error contains the key", name)
		}
	}

	// Secret Manager path.
	newFakeMetadata(t, nil)
	c := newOutboundClient(nil)
	prod := config{env: "prod", hmacSecretName: testHMACName}
	newFakeSecretManager(t, map[string]string{testHMACName: hex.EncodeToString(hmacKey)}, false)
	k, err = loadSecrets(ctx, prod, c, &tokenSource{client: c})
	if err != nil || !bytes.Equal(k, hmacKey) {
		t.Fatalf("Secret Manager secret wrong: %v", err)
	}
	for name, sm := range map[string]map[string]string{
		"HMAC trailing newline": {testHMACName: hex.EncodeToString(hmacKey) + "\n"},
		"HMAC 62 hex":           {testHMACName: hex.EncodeToString(hmacKey[:31])},
		"HMAC not hex":          {testHMACName: strings.Repeat("zz", 32)},
		"HMAC missing":          {},
	} {
		newFakeSecretManager(t, sm, false)
		if _, err := loadSecrets(ctx, prod, c, &tokenSource{client: c}); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), hex.EncodeToString(hmacKey)) {
			t.Errorf("%s: error contains secret material", name)
		}
	}
}

func TestDevSecretVar(t *testing.T) {
	for _, c := range []struct{ account, name, want string }{
		{"stripe_test", "secretKey", "VAULT_DEV_SECRET_STRIPE_TEST_SECRETKEY"},
		{"adyen_br", "apiKey", "VAULT_DEV_SECRET_ADYEN_BR_APIKEY"},
		{"a1", "x_Y9", "VAULT_DEV_SECRET_A1_X_Y9"},
		{"a", "b-c.d", "VAULT_DEV_SECRET_A_B_C_D"}, // every non-[A-Z0-9] character becomes "_"
	} {
		if got := devSecretVar(c.account, c.name); got != c.want {
			t.Errorf("devSecretVar(%q, %q) = %q, want %q", c.account, c.name, got, c.want)
		}
	}
}

// TestLoadAccountSecrets: every secret of every loaded account is loaded (dev variable first in
// dev, else Secret Manager) or the whole call fails, leaving no account with secrets; errors name
// the account and secret name, never a value or a resource.
func TestLoadAccountSecrets(t *testing.T) {
	ctx := context.Background()
	newFakeMetadata(t, nil)
	c := newOutboundClient(nil)
	ts := &tokenSource{client: c}
	dev := config{env: "dev"}
	// One distinct Secret Manager value per dev account resource of testCatalogJSON.
	smValues := map[string]string{
		"projects/pci-cde-dev/secrets/stripe-t-key":   "sm_stripe_t_v1",
		"projects/pci-cde-dev/secrets/adyen-br-key":   "sm_adyen_br_v1",
		"projects/pci-cde-dev/secrets/mp-ar-token":    "sm_mp_ar_v1",
		"projects/pci-cde-dev/secrets/payu-co-key":    "sm_payu_co_v1",
		"projects/pci-cde-dev/secrets/pagarme-br-key": "sm_pagarme_br_v1",
		"projects/pci-cde-prod/secrets/adyen-br-key":  "sm_adyen_br_live_v1",
	}
	allValues := append(slices.Collect(maps.Values(smValues)), "sk_env_x9", "sk_env x9", "sk_env_x9\n")
	noEnv := func(string) string { return "" }
	noSecrets := func(cat *catalog) bool {
		for _, a := range cat.accounts {
			if len(a.secrets) != 0 {
				return false
			}
		}
		return true
	}

	// All from Secret Manager: every loaded account ends up with every one of its secrets.
	hits := newFakeSecretManager(t, smValues, false)
	cat := testCatalog(t, testCatalogHost)
	if err := loadAccountSecrets(ctx, cat, dev, noEnv, c, ts); err != nil {
		t.Fatalf("Secret Manager load: %s", safeErr(err, allValues...))
	}
	for _, a := range cat.accounts {
		if len(a.secrets) != len(a.secretNames) {
			t.Errorf("account %s: %d of %d secrets loaded", a.name, len(a.secrets), len(a.secretNames))
		}
		for n, res := range a.secretNames {
			if a.secrets[n] != smValues[res] {
				t.Errorf("account %s secret %s: not the Secret Manager value", a.name, n)
			}
		}
	}
	if hits.Load() != 5 {
		t.Errorf("Secret Manager hits %d, want 5 (one per dev account secret)", hits.Load())
	}

	// A dev variable wins over Secret Manager; the others still come from Secret Manager.
	hits = newFakeSecretManager(t, smValues, false)
	cat = testCatalog(t, testCatalogHost)
	env := map[string]string{"VAULT_DEV_SECRET_STRIPE_T_SECRETKEY": "sk_env_x9"}
	if err := loadAccountSecrets(ctx, cat, dev, func(k string) string { return env[k] }, c, ts); err != nil {
		t.Fatalf("dev variable load: %s", safeErr(err, allValues...))
	}
	if cat.accounts["stripe_t"].secrets["secretKey"] != "sk_env_x9" {
		t.Error("the dev variable did not win")
	}
	if cat.accounts["adyen_br"].secrets["apiKey"] != "sm_adyen_br_v1" {
		t.Error("a secret without a dev variable did not come from Secret Manager")
	}
	if hits.Load() != 4 {
		t.Errorf("Secret Manager hits %d, want 4 (the dev variable's secret is not fetched)", hits.Load())
	}

	// Failures: each names the account and secret name, never a value or resource, and no account
	// is left with secrets (renderRequest's missing-secret path stays unreachable).
	missing := maps.Clone(smValues)
	delete(missing, "projects/pci-cde-dev/secrets/pagarme-br-key")
	spaced := maps.Clone(smValues)
	spaced["projects/pci-cde-dev/secrets/stripe-t-key"] = "sk_env x9"
	for _, f := range []struct {
		name    string
		sm      map[string]string
		env     map[string]string
		mention []string
	}{
		{"missing in Secret Manager", missing, nil, []string{"pagarme_br", "secretKey"}},
		{"Secret Manager value with whitespace", spaced, nil, []string{"stripe_t", "secretKey"}},
		{"Secret Manager value empty", envWithSM(smValues, "projects/pci-cde-dev/secrets/mp-ar-token", ""), nil, []string{"mp_ar", "accessToken"}},
		{"dev variable with whitespace", smValues, map[string]string{"VAULT_DEV_SECRET_ADYEN_BR_APIKEY": "sk_env x9"}, []string{"adyen_br", "apiKey", "VAULT_DEV_SECRET_ADYEN_BR_APIKEY"}},
		{"dev variable trailing newline", smValues, map[string]string{"VAULT_DEV_SECRET_PAYU_CO_APIKEY": "sk_env_x9\n"}, []string{"payu_co", "apiKey", "VAULT_DEV_SECRET_PAYU_CO_APIKEY"}},
	} {
		newFakeSecretManager(t, f.sm, false)
		cat := testCatalog(t, testCatalogHost)
		err := loadAccountSecrets(ctx, cat, dev, func(k string) string { return f.env[k] }, c, ts)
		if err == nil {
			t.Errorf("%s: accepted", f.name)
			continue
		}
		for _, m := range f.mention {
			if !strings.Contains(err.Error(), m) {
				t.Errorf("%s: error %q does not name %s", f.name, safeErr(err, allValues...), m)
			}
		}
		if safeErr(err, allValues...) != err.Error() || strings.Contains(err.Error(), "projects/") {
			t.Errorf("%s: error contains a secret value or resource", f.name)
		}
		if !noSecrets(cat) {
			t.Errorf("%s: an account was left with secrets after the failure", f.name)
		}
	}

	// Prod never reads VAULT_DEV_SECRET_* (main's devVarSet refuses such a boot anyway).
	newFakeSecretManager(t, smValues, false)
	prodCat, err := parseCatalog([]byte(testCatalogJSON), "prod")
	if err != nil {
		t.Fatal(err)
	}
	var devReads []string
	prodEnv := func(k string) string {
		if strings.HasPrefix(k, "VAULT_DEV_") {
			devReads = append(devReads, k)
		}
		return "sk_env_x9"
	}
	if err := loadAccountSecrets(ctx, prodCat, config{env: "prod"}, prodEnv, c, ts); err != nil {
		t.Fatalf("prod load: %s", safeErr(err, allValues...))
	}
	if prodCat.accounts["adyen_br_live"].secrets["apiKey"] != "sm_adyen_br_live_v1" || len(devReads) != 0 {
		t.Errorf("prod: secret not from Secret Manager, or %d VAULT_DEV_* reads", len(devReads))
	}

	// Refused inputs.
	if err := loadAccountSecrets(ctx, nil, dev, noEnv, c, ts); err == nil {
		t.Error("nil catalog accepted")
	}
	if err := loadAccountSecrets(ctx, testCatalog(t, testCatalogHost), config{env: "staging"}, noEnv, c, ts); err == nil {
		t.Error("unknown environment accepted")
	}
}

// envWithSM copies sm with name set to value.
func envWithSM(sm map[string]string, name, value string) map[string]string {
	m := maps.Clone(sm)
	m[name] = value
	return m
}

// TestCheckDevSecretVars: before the database is touched, a dev boot refuses any VAULT_DEV_*
// variable that is neither a fixed dev variable nor the dev variable of a loaded account secret
// (a misspelt account secret variable would otherwise silently fall back to Secret Manager), and
// any account secret variable whose value is not a valid secret. Prod is left to devVarSet.
func TestCheckDevSecretVars(t *testing.T) {
	devCat := testCatalog(t, testCatalogHost)
	prodCat, err := parseCatalog([]byte(testCatalogJSON), "prod")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name    string
		cat     *catalog
		env     string
		environ []string
		mention string // "" = accepted
	}{
		{"no dev variables", devCat, "dev", []string{"PATH=/bin"}, ""},
		{"fixed dev variables", devCat, "dev", []string{"VAULT_DEV_DEK_HEX=x", "VAULT_DEV_SESSION_HMAC_HEX=y"}, ""},
		{"account secret variables", devCat, "dev", []string{"VAULT_DEV_SECRET_STRIPE_T_SECRETKEY=sk_env_x9", "VAULT_DEV_SECRET_PAYU_CO_APIKEY=sk_env_x9"}, ""},
		{"account secret variable empty", devCat, "dev", []string{"VAULT_DEV_SECRET_STRIPE_T_SECRETKEY="}, ""},
		{"misspelt account secret variable", devCat, "dev", []string{"VAULT_DEV_SECRET_STRIPE_T_SECRET_KEY=sk_env_x9"}, "VAULT_DEV_SECRET_STRIPE_T_SECRET_KEY"},
		{"other environment's account", devCat, "dev", []string{"VAULT_DEV_SECRET_ADYEN_BR_LIVE_APIKEY=sk_env_x9"}, "VAULT_DEV_SECRET_ADYEN_BR_LIVE_APIKEY"},
		{"removed Stripe variable", devCat, "dev", []string{"VAULT_DEV_STRIPE_SECRET=sk_env_x9"}, "VAULT_DEV_STRIPE_SECRET"},
		{"unknown empty dev variable", devCat, "dev", []string{"VAULT_DEV_X="}, "VAULT_DEV_X"},
		{"account secret with whitespace", devCat, "dev", []string{"VAULT_DEV_SECRET_MP_AR_ACCESSTOKEN=sk_env x9"}, "VAULT_DEV_SECRET_MP_AR_ACCESSTOKEN"},
		{"prod is left to devVarSet", prodCat, "prod", []string{"VAULT_DEV_SECRET_ADYEN_BR_LIVE_APIKEY=sk_env_x9"}, ""},
	} {
		err := checkDevSecretVars(c.cat, c.env, c.environ)
		if c.mention == "" {
			if err != nil {
				t.Errorf("%s: %s", c.name, safeErr(err, "sk_env"))
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.mention) {
			t.Errorf("%s: error %s does not name %s", c.name, safeErr(err, "sk_env"), c.mention)
		}
		if err != nil && strings.Contains(err.Error(), "sk_env") {
			t.Errorf("%s: error contains the value", c.name)
		}
	}
}

func TestLoadDEKsDev(t *testing.T) {
	dek := bytes.Repeat([]byte{0x33}, 32)
	deks, cur, err := loadDEKs(context.Background(), config{env: "dev", devDEK: dek}, nil, nil, nil)
	if err != nil || cur != 1 || len(deks) != 1 || !bytes.Equal(deks[1], dek) {
		t.Fatalf("dev DEK not loaded as version 1: %v", err)
	}
	if _, _, err := loadDEKs(context.Background(), config{env: "prod", devDEK: dek, kmsKey: testKMSKey}, nil, nil, nil); err == nil {
		t.Error("prod accepted a dev DEK")
	}
	if _, _, err := loadDEKs(context.Background(), config{env: "dev", devDEK: dek[:31]}, nil, nil, nil); err == nil {
		t.Error("31-byte dev DEK accepted")
	}
	// With a dev DEK there is nothing to refresh: the refresher touches neither the database
	// (nil here) nor the snapshot.
	v, _ := newTestVault(t)
	before := v.keys.Load()
	if err := dekRefresher(v, config{env: "dev", devDEK: dek}, nil, nil, nil)(context.Background()); err != nil || v.keys.Load() != before {
		t.Error("dev refresher did something")
	}
}

// unwrapDEKs unwraps only the versions not already held, shares the held DEKs, and returns a new
// map with the highest version.
func TestUnwrapDEKsOnlyNew(t *testing.T) {
	newFakeMetadata(t, nil)
	k := newFakeKMS(t)
	c := newOutboundClient(nil)
	ts := &tokenSource{client: c}
	cfg := config{env: "prod", kmsKey: testKMSKey}
	dek := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	have := map[int][]byte{1: dek(1)}
	wrapped := map[int][]byte{1: reversed(dek(1)), 2: reversed(dek(2)), 3: reversed(dek(3))}
	before := k.count()
	got, cur, err := unwrapDEKs(context.Background(), cfg, c, ts, wrapped, have)
	if err != nil {
		t.Fatalf("unwrapDEKs: %v", err)
	}
	if n := k.count() - before; n != 2 {
		t.Errorf("KMS decrypts %d, want 2 (only the new versions)", n)
	}
	if len(got) != 3 || cur != 3 {
		t.Fatalf("got %d DEKs, current %d; want 3 and 3", len(got), cur)
	}
	for ver := 1; ver <= 3; ver++ {
		if !bytes.Equal(got[ver], dek(byte(ver))) {
			t.Errorf("version %d is not its DEK", ver)
		}
	}
	if &got[1][0] != &have[1][0] {
		t.Error("the held DEK for version 1 was not shared")
	}
	if len(have) != 1 {
		t.Error("unwrapDEKs modified the held map")
	}

	// A KMS failure fails the call and leaves the held DEKs intact.
	k.setMode("500")
	wrapped[4] = reversed(dek(4))
	if _, _, err := unwrapDEKs(context.Background(), cfg, c, ts, wrapped, got); err == nil {
		t.Fatal("KMS failure accepted")
	}
	for ver := 1; ver <= 3; ver++ {
		if !bytes.Equal(got[ver], dek(byte(ver))) {
			t.Errorf("a failed unwrap altered held version %d", ver)
		}
	}
	// Nothing new to unwrap: no KMS call, a copy of the held set.
	k.setMode("")
	before = k.count()
	delete(wrapped, 4)
	again, cur, err := unwrapDEKs(context.Background(), cfg, c, ts, wrapped, got)
	if err != nil || len(again) != 3 || cur != 3 || k.count() != before {
		t.Errorf("no-op unwrap: %d DEKs, current %d, %d KMS calls, err %v", len(again), cur, k.count()-before, err)
	}
}

func TestDEKVersionList(t *testing.T) {
	if got := dekVersions(map[int][]byte{10: nil, 2: nil, 1: nil}); got != "1,2,10" {
		t.Errorf("got %q", got)
	}
}

// rotateDEK verifies the wrapped DEK unwraps to the generated one before storing it; a KMS that
// does not round-trip fails before the database is touched (db is nil here).
func TestRotateDEKVerifiesWrap(t *testing.T) {
	newFakeMetadata(t, nil)
	k := newFakeKMS(t)
	c := newOutboundClient(nil)
	cfg := config{env: "prod", kmsKey: testKMSKey}
	for _, mode := range []string{"corrupt", "short", "500"} {
		k.setMode(mode)
		if _, err := rotateDEK(context.Background(), cfg, nil, c, &tokenSource{client: c}); err == nil {
			t.Errorf("mode %s: accepted", mode)
		}
	}
	if _, err := rotateDEK(context.Background(), config{env: "prod"}, nil, c, &tokenSource{client: c}); err == nil {
		t.Error("empty KMS key accepted")
	}
}

func TestOpenDB(t *testing.T) {
	const devURL = "postgres://vault_app:pw-x9q@127.0.0.1:1/vault?sslmode=disable&connect_timeout=2"
	db, err := openDB(config{env: "dev", dbURL: devURL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := db.Stats().MaxOpenConnections; n != 16 {
		t.Errorf("dev MaxOpenConnections %d, want 16", n)
	}
	db.Close()

	// prod: the password is a metadata access token fetched before every new connection.
	hits := newFakeMetadata(t, nil)
	c := newOutboundClient(nil)
	const prodURL = "postgres://vault_app@127.0.0.1:1/vault?sslmode=verify-full&connect_timeout=2"
	db, err = openDB(config{env: "prod", dbURL: prodURL}, &tokenSource{client: c})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if n := db.Stats().MaxOpenConnections; n != 16 {
		t.Errorf("prod MaxOpenConnections %d, want 16", n)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if db.PingContext(ctx) == nil {
		t.Fatal("ping to a closed port succeeded")
	}
	if hits.Load() < 1 {
		t.Error("BeforeConnect did not fetch a metadata token")
	}

	for name, cfg := range map[string]config{
		"prod sslmode=disable": {env: "prod", dbURL: "postgres://vault_app@127.0.0.1:1/vault?sslmode=disable"},
		"prod sslmode=prefer":  {env: "prod", dbURL: "postgres://vault_app@127.0.0.1:1/vault?sslmode=prefer"},
		"prod sslmode=allow":   {env: "prod", dbURL: "postgres://vault_app@127.0.0.1:1/vault?sslmode=allow"},
		"prod sslmode=require": {env: "prod", dbURL: "postgres://vault_app@127.0.0.1:1/vault?sslmode=require"},
		"prod default sslmode": {env: "prod", dbURL: "postgres://vault_app@127.0.0.1:1/vault"},
		"unparseable":          {env: "dev", dbURL: "postgres://vault_app:pw-x9q@127.0.0.1:notaport/vault"},
		"unparseable keyword":  {env: "dev", dbURL: "host=127.0.0.1 password=pw-x9q port=bad"},
	} {
		if db, err := openDB(cfg, &tokenSource{client: c}); err == nil {
			db.Close()
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "pw-x9q") || strings.Contains(err.Error(), "127.0.0.1") {
			t.Errorf("%s: error reveals the URL", name)
		}
	}
	if db, err := openDB(config{env: "prod", dbURL: prodURL}, nil); err == nil {
		db.Close()
		t.Error("prod without a token source accepted")
	}

	// No configuration from files. service/servicefile/passfile would make pgx read
	// pg_service.conf or a .pgpass file, so they refuse boot before pgx parses the URL (the
	// service file named here exists and is valid, so pgx itself would accept it). The
	// keyword/value form is refused because its parameters cannot be checked the same way.
	dir := t.TempDir()
	svc := filepath.Join(dir, "pg_service.conf")
	if err := os.WriteFile(svc, []byte("[s1]\nhost=127.0.0.1\nport=1\ndbname=vault\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pass := filepath.Join(dir, "pgpass")
	if err := os.WriteFile(pass, []byte("*:*:*:*:pw-x9q\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const base = "postgres://vault_app@127.0.0.1:1/vault?sslmode=verify-full&"
	for name, tc := range map[string]struct {
		cfg  config
		want string
	}{
		"dev service":             {config{env: "dev", dbURL: "postgres:///?service=s1&servicefile=" + svc}, "VAULT_DB_URL must not set service, servicefile or passfile"},
		"dev servicefile":         {config{env: "dev", dbURL: "postgres://vault_app@127.0.0.1:1/vault?servicefile=" + svc}, "VAULT_DB_URL must not set service, servicefile or passfile"},
		"dev passfile":            {config{env: "dev", dbURL: "postgres://vault_app@127.0.0.1:1/vault?sslmode=disable&passfile=" + pass}, "VAULT_DB_URL must not set service, servicefile or passfile"},
		"dev postgresql scheme":   {config{env: "dev", dbURL: "postgresql://vault_app@127.0.0.1:1/vault?passfile=" + pass}, "VAULT_DB_URL must not set service, servicefile or passfile"},
		"dev mixed-case key":      {config{env: "dev", dbURL: "postgres://vault_app@127.0.0.1:1/vault?PassFile=" + pass}, "VAULT_DB_URL must not set service, servicefile or passfile"},
		"dev percent-encoded key": {config{env: "dev", dbURL: "postgres://vault_app@127.0.0.1:1/vault?%73ervice=s1"}, "VAULT_DB_URL must not set service, servicefile or passfile"},
		"dev repeated key":        {config{env: "dev", dbURL: "postgres://vault_app@127.0.0.1:1/vault?sslmode=disable&sslmode=disable&service=s1"}, "VAULT_DB_URL must not set service, servicefile or passfile"},
		"prod service":            {config{env: "prod", dbURL: base + "service=s1"}, "VAULT_DB_URL must not set service, servicefile or passfile"},
		"prod passfile":           {config{env: "prod", dbURL: base + "passfile=" + pass}, "VAULT_DB_URL must not set service, servicefile or passfile"},
		"keyword/value form":      {config{env: "dev", dbURL: "host=127.0.0.1 port=1 dbname=vault sslmode=disable"}, "VAULT_DB_URL must be a postgres:// or postgresql:// URL"},
		"keyword/value service":   {config{env: "dev", dbURL: "service=s1 servicefile=" + svc}, "VAULT_DB_URL must be a postgres:// or postgresql:// URL"},
		"uppercase scheme":        {config{env: "dev", dbURL: "POSTGRES://vault_app@127.0.0.1:1/vault"}, "VAULT_DB_URL must be a postgres:// or postgresql:// URL"},
		"malformed query":         {config{env: "dev", dbURL: "postgres://vault_app@127.0.0.1:1/vault?sslmode=disable;service=s1"}, "VAULT_DB_URL cannot be parsed"},
	} {
		db, err := openDB(tc.cfg, &tokenSource{client: c})
		if err == nil {
			db.Close()
			t.Errorf("%s: accepted", name)
			continue
		}
		if err.Error() != tc.want {
			t.Errorf("%s: wrong error (len %d)", name, len(err.Error())) // never print it: it might quote the URL
		}
	}
}

// testCertPEM returns a PEM certificate: a self-signed CA when parent is nil and isCA, else a
// leaf signed by parent (or self-signed). It also returns the cert and key for chaining.
func testCertPEM(t *testing.T, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0x0A1B2C),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, key
}

func TestLoadClientCA(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	caPEM, ca, caKey := testCertPEM(t, true, nil, nil)
	ca2PEM, _, _ := testCertPEM(t, true, nil, nil)
	_, leaf, _ := testCertPEM(t, false, ca, caKey)
	selfLeafPEM, _, _ := testCertPEM(t, false, nil, nil)
	keyDER, _ := x509.MarshalECPrivateKey(caKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	pool, err := loadClientCA(write("ca.pem", caPEM))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("leaf signed by the CA does not verify: %v", err)
	}
	for name, b := range map[string][]byte{
		"two CAs":        append(slices.Clone(caPEM), ca2PEM...),
		"CA plus key":    append(slices.Clone(caPEM), keyPEM...),
		"leaf (non-CA)":  selfLeafPEM,
		"garbage":        []byte("not a certificate"),
		"empty":          {},
		"key only":       keyPEM,
		"wrong PEM type": pem.EncodeToMemory(&pem.Block{Type: "TRUSTED CERTIFICATE", Bytes: ca.Raw}),
		"corrupt DER":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw[:len(ca.Raw)/2]}),
	} {
		if _, err := loadClientCA(write(strings.ReplaceAll(name, " ", "_")+".pem", b)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := loadClientCA(filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("missing file accepted")
	}
}

func TestNewVault(t *testing.T) {
	db, err := openDB(config{env: "dev", dbURL: "postgres://vault_app@127.0.0.1:1/vault?sslmode=disable&connect_timeout=2"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	deks := map[int][]byte{1: bytes.Repeat([]byte{1}, 32), 2: bytes.Repeat([]byte{2}, 32)}
	c := newOutboundClient(nil)
	logger := log.New(&testLog, "", 0)
	cat := testCatalog(t, testCatalogHost)
	v := newVault(config{env: "dev", allowOrigin: testOrigin}, db, deks, 2, testHMACKey, cat, c, logger)
	if v.putCard == nil || v.getCard == nil || v.ping == nil || v.cvv == nil || v.now == nil {
		t.Fatal("function fields or CVV cache not wired")
	}
	if cur, d := v.currentDEK(); cur != 2 || !bytes.Equal(d, deks[2]) || len(v.keys.Load().deks) != 2 {
		t.Error("initial DEK snapshot not stored")
	}
	if v.refreshDEKs != nil {
		t.Error("newVault wired a refresh function; main does that")
	}
	if !bytes.Equal(v.hmacKey, testHMACKey) || v.allowOrigin != testOrigin ||
		v.client != c || v.log != logger {
		t.Error("fields not wired")
	}
	if v.catalog != cat {
		t.Error("catalog not wired")
	}
	if v.cvv.ttl != 15*time.Minute {
		t.Errorf("CVV TTL %v", v.cvv.ttl)
	}
	if d := time.Since(v.now()); d < 0 || d > time.Minute {
		t.Error("now is not the wall clock")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if v.ping(ctx) == nil {
		t.Error("ping is not wired to the database")
	}
}

// TestNewVaultDBDeadline: each putCard/getCard call runs under a 5s deadline derived from the
// request context, so a saturated pool or a stalled server fails the request instead of
// hanging it.
// The refresher's list_deks call runs under dbCallTimeout, like every other database call.
func TestDEKRefresherDBDeadline(t *testing.T) {
	got := make(chan time.Duration, 1)
	pc, err := pgx.ParseConfig("postgres://vault_app@127.0.0.1:1/vault?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	db := stdlib.OpenDB(*pc, stdlib.OptionBeforeConnect(func(ctx context.Context, _ *pgx.ConnConfig) error {
		dl, ok := ctx.Deadline()
		if !ok {
			dl = time.Now().Add(time.Hour)
		}
		got <- time.Until(dl)
		return errors.New("fake connect refused")
	}))
	defer db.Close()
	v, _ := newTestVault(t)
	before := v.keys.Load()
	refresh := dekRefresher(v, config{env: "prod", kmsKey: testKMSKey}, db, nil, nil)
	if refresh(context.Background()) == nil {
		t.Fatal("no error from a refused connection")
	}
	if left := <-got; left > dbCallTimeout || left < dbCallTimeout-time.Second {
		t.Errorf("list_deks deadline %v away, want ≤%v", left, dbCallTimeout)
	}
	if v.keys.Load() != before {
		t.Error("a failed refresh replaced the snapshot")
	}
}

func TestNewVaultDBDeadline(t *testing.T) {
	type ctxKey struct{}
	type seen struct {
		left time.Duration
		ok   bool
		req  bool
	}
	got := make(chan seen, 1)
	pc, err := pgx.ParseConfig("postgres://vault_app@127.0.0.1:1/vault?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	db := stdlib.OpenDB(*pc, stdlib.OptionBeforeConnect(func(ctx context.Context, _ *pgx.ConnConfig) error {
		dl, ok := ctx.Deadline()
		got <- seen{left: time.Until(dl), ok: ok, req: ctx.Value(ctxKey{}) != nil}
		return errors.New("fake connect refused")
	}))
	defer db.Close()
	v := newVault(config{env: "dev", allowOrigin: testOrigin}, db, map[int][]byte{1: bytes.Repeat([]byte{1}, 32)}, 1,
		testHMACKey, testCatalog(t, testCatalogHost), newOutboundClient(nil), log.New(&testLog, "", 0))

	reqCtx := context.WithValue(context.Background(), ctxKey{}, true)
	short, cancel := context.WithTimeout(reqCtx, time.Second)
	defer cancel()
	calls := map[string]func(context.Context) error{
		"putCard": func(ctx context.Context) error { return v.putCard(ctx, newToken(), []byte{1}, "4242", 1) },
		"getCard": func(ctx context.Context) error { _, _, err := v.getCard(ctx, newToken(), "1"); return err },
	}
	for name, call := range calls {
		if call(reqCtx) == nil {
			t.Fatalf("%s: no error from a refused connection", name)
		}
		s := <-got
		if !s.ok || s.left > 5*time.Second || s.left < 4*time.Second {
			t.Errorf("%s: deadline ok=%v %v away, want ≤5s", name, s.ok, s.left)
		}
		if !s.req {
			t.Errorf("%s: the DB context is not derived from the request context", name)
		}
		// An earlier request deadline is kept.
		if call(short) == nil {
			t.Fatalf("%s: no error from a refused connection", name)
		}
		if s := <-got; !s.ok || s.left > time.Second {
			t.Errorf("%s: request deadline not kept (%v away)", name, s.left)
		}
	}

	// A server that accepts and never answers: both calls fail after ~5s, not never.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var held sync.WaitGroup
	defer held.Wait()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			held.Go(func() { io.Copy(io.Discard, conn); conn.Close() })
		}
	}()
	stalled, err := openDB(config{env: "dev", dbURL: "postgres://vault_app@" + ln.Addr().String() + "/vault?sslmode=disable"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	v = newVault(config{env: "dev", allowOrigin: testOrigin}, stalled, map[int][]byte{1: bytes.Repeat([]byte{1}, 32)}, 1,
		testHMACKey, testCatalog(t, testCatalogHost), newOutboundClient(nil), log.New(&testLog, "", 0))
	var wg sync.WaitGroup
	for name, call := range calls {
		wg.Go(func() {
			// The 30s outer bound only keeps a regression from hanging the suite.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			start := time.Now()
			err := call(ctx)
			d := time.Since(start)
			if err == nil {
				t.Errorf("%s: stalled server: no error", name)
			} else if want := "vault." + map[string]string{"putCard": "put_card", "getCard": "get_card"}[name] + ": failed"; err.Error() != want {
				t.Errorf("%s: stalled server: error %q, want %q", name, err, want)
			}
			if d < 4500*time.Millisecond || d > 8*time.Second {
				t.Errorf("%s: stalled server: returned after %v, want ~5s", name, d)
			}
		})
	}
	wg.Wait()
	ln.Close()
	stalled.Close()
}

// runMain runs main() in a subprocess of the test binary with exactly env (nothing inherited)
// and args, and returns its exit code and stderr.
func runMain(t *testing.T, env map[string]string, args ...string) (int, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Env = []string{"PAN_VAULT_TEST_RUN_MAIN=1"}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatalf("subprocess did not run: %v", err)
	}
	return cmd.ProcessState.ExitCode(), stderr.String()
}

// bootBadDB is a VAULT_DB_URL that openDB refuses: a subprocess boot that fails with any other
// reason failed before it touched the database.
const bootBadDB = "postgres://vault_app@127.0.0.1:notaport/vault"

// writeBootTLSFiles writes a valid server certificate, its key and the client CA into dir.
func writeBootTLSFiles(t *testing.T, dir string) (certFile, keyFile, caFile string) {
	t.Helper()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	caPEM, ca, caKey := testCertPEM(t, true, nil, nil)
	leafPEM, _, leafKey := testCertPEM(t, false, ca, caKey)
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return write("cert.pem", leafPEM), write("key.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})), write("ca.pem", caPEM)
}

// TestBootFailsFastOnTLSFiles: in serve mode the certificate, key and client CA are loaded right
// after the environment is parsed, before the database, KMS or Secret Manager
// is touched. VAULT_DB_URL is unparseable in every case, so a boot that reached openDB would
// fail with the database reason instead. -rotate-dek never reads the TLS files.
func TestBootFailsFastOnTLSFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	certFile, keyFile, caFile := writeBootTLSFiles(t, dir)
	missing := filepath.Join(dir, "missing.pem")
	dev := envWith(testDevEnv(), map[string]string{"VAULT_CERT": certFile, "VAULT_KEY": keyFile, "VAULT_CLIENT_CA": caFile, "VAULT_DB_URL": bootBadDB})
	// The embedded catalog has no prod account, which refuses a prod boot right after the catalog
	// (TestBootRefusesEmptyAccountSet), so the prod cases run against one that has.
	prod := envWith(testProdEnv(), map[string]string{"VAULT_CERT": certFile, "VAULT_KEY": keyFile, "VAULT_CLIENT_CA": caFile, "VAULT_DB_URL": bootBadDB,
		"PAN_VAULT_TEST_CATALOG": bootCatalogJSON("prod")})
	for _, c := range []struct {
		name string
		env  map[string]string
		args []string
		want string
	}{
		{"dev missing cert", envWith(dev, map[string]string{"VAULT_CERT": missing}), nil, "VAULT_CERT/VAULT_KEY: cannot load key pair"},
		{"dev missing key", envWith(dev, map[string]string{"VAULT_KEY": missing}), nil, "VAULT_CERT/VAULT_KEY: cannot load key pair"},
		{"dev key does not match cert", envWith(dev, map[string]string{"VAULT_KEY": write("other-key.pem", func() []byte {
			_, _, k := testCertPEM(t, false, nil, nil)
			der, err := x509.MarshalECPrivateKey(k)
			if err != nil {
				t.Fatal(err)
			}
			return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		}())}), nil, "VAULT_CERT/VAULT_KEY: cannot load key pair"},
		{"dev missing client CA", envWith(dev, map[string]string{"VAULT_CLIENT_CA": missing}), nil, "VAULT_CLIENT_CA: client CA: cannot read file"},
		{"dev client CA not a CA", envWith(dev, map[string]string{"VAULT_CLIENT_CA": certFile}), nil, "VAULT_CLIENT_CA: client CA: certificate is not a CA"},
		{"prod missing cert", envWith(prod, map[string]string{"VAULT_CERT": missing}), nil, "VAULT_CERT/VAULT_KEY: cannot load key pair"},
		{"prod missing client CA", envWith(prod, map[string]string{"VAULT_CLIENT_CA": missing}), nil, "VAULT_CLIENT_CA: client CA: cannot read file"},
		// Controls: with good TLS files the boot proceeds to the database and fails there.
		{"dev good TLS files", dev, nil, "VAULT_DB_URL cannot be parsed"},
		{"prod good TLS files", prod, nil, "VAULT_DB_URL cannot be parsed"},
		// -rotate-dek ignores the TLS variables entirely.
		{"rotate ignores TLS files", envWith(prod, map[string]string{"VAULT_CERT": missing, "VAULT_KEY": missing, "VAULT_CLIENT_CA": missing}), []string{"-rotate-dek"}, "VAULT_DB_URL cannot be parsed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, stderr := runMain(t, c.env, c.args...)
			if code != 1 {
				t.Errorf("exit code %d, want 1", code)
			}
			if !strings.Contains(stderr, " boot failed: "+c.want+"\n") {
				t.Errorf("stderr (len %d) lacks boot failure reason %q", len(stderr), c.want)
			}
		})
	}
}

// TestBootCatalogFailsFast: in serve mode the compiled-in catalog is parsed and the dev account
// secret variables are checked right after the TLS files, before the database, KMS or Secret
// Manager is touched (VAULT_DB_URL is unparseable in every case, so a boot that reached openDB
// fails with the database reason instead). A dev account secret whose variable is misspelt (so the
// secret is missing from the environment) or malformed exits 1 there, as does any VAULT_DEV_* in
// prod. An account secret with no dev variable at all comes from Secret Manager, which boot loads
// after the DEKs; that path is TestLoadAccountSecrets'. No value ever reaches stderr.
func TestBootCatalogFailsFast(t *testing.T) {
	certFile, keyFile, caFile := writeBootTLSFiles(t, t.TempDir())
	files := map[string]string{"VAULT_CERT": certFile, "VAULT_KEY": keyFile, "VAULT_CLIENT_CA": caFile, "VAULT_DB_URL": bootBadDB}
	dev := envWith(testDevEnv(), files)
	// A prod account, so the prod control gets past the empty account set gate.
	prod := envWith(testProdEnv(), envWith(files, map[string]string{"PAN_VAULT_TEST_CATALOG": bootCatalogJSON("prod")}))
	const acctVar = "VAULT_DEV_SECRET_STRIPE_TEST_SECRETKEY"
	for _, c := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"dev account secret variable misspelt", envWith(dev, map[string]string{acctVar: omit, "VAULT_DEV_SECRET_STRIPE_TEST_SECRET_KEY": testSecret}),
			"VAULT_DEV_SECRET_STRIPE_TEST_SECRET_KEY is not a dev variable or the dev variable of a dev catalog account secret"},
		{"dev removed VAULT_DEV_STRIPE_SECRET", envWith(dev, map[string]string{"VAULT_DEV_STRIPE_SECRET": testSecret}),
			"VAULT_DEV_STRIPE_SECRET is not a dev variable or the dev variable of a dev catalog account secret"},
		{"dev account secret with whitespace", envWith(dev, map[string]string{acctVar: testSecret + " x"}),
			"account stripe_test secret secretKey: " + acctVar + " must be non-empty printable ASCII without whitespace"},
		{"prod with an account secret variable", envWith(prod, map[string]string{acctVar: testSecret}), acctVar + " is refused when VAULT_ENV=prod"},
		// Controls: the boot proceeds to the database and fails there.
		{"dev with the account secret variable", dev, "VAULT_DB_URL cannot be parsed"},
		{"dev without the account secret variable", envWith(dev, map[string]string{acctVar: omit}), "VAULT_DB_URL cannot be parsed"},
		{"prod", prod, "VAULT_DB_URL cannot be parsed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, stderr := runMain(t, c.env)
			if code != 1 {
				t.Errorf("exit code %d, want 1", code)
			}
			if strings.Contains(stderr, testSecret) {
				t.Fatal("stderr contains the secret value") // never print it
			}
			if !strings.Contains(stderr, " boot failed: "+c.want+"\n") {
				t.Errorf("stderr %q lacks boot failure reason %q", stderr, c.want)
			}
			if strings.Contains(stderr, "catalog loaded") {
				t.Error("catalog loaded before the account secrets")
			}
		})
	}
}

// bootCatalogJSON is a minimal valid catalog whose one account, stripe_test, belongs to env. A
// boot subprocess runs against it through PAN_VAULT_TEST_CATALOG (see TestMain).
func bootCatalogJSON(env string) string {
	return `{
  "providers": {"stripe": {"format": "form", "endpoints": [{"id": "tokens", "method": "POST", "path": "/v1/tokens", "card_data": true,
    "headers": {"Authorization": "Bearer {{secret:secretKey}}"}, "positions": {"card[number]": "{{pan}}"}}]}},
  "accounts": {"stripe_test": {"provider": "stripe", "env": "` + env + `", "host": "api.stripe.com", "base_path": "",
    "secrets": {"secretKey": "projects/pci-cde-` + env + `/secrets/stripe-key"}, "values": {}}}
}`
}

// TestBootRefusesEmptyAccountSet: a serve-mode boot whose catalog has no account for its
// environment exits 1 right after the catalog is parsed, before the dev variable check, the
// database, KMS or Secret Manager (VAULT_DB_URL is unparseable, so a boot past the gate fails
// with the database reason). A vault with no account could never send a card anywhere.
func TestBootRefusesEmptyAccountSet(t *testing.T) {
	certFile, keyFile, caFile := writeBootTLSFiles(t, t.TempDir())
	files := map[string]string{"VAULT_CERT": certFile, "VAULT_KEY": keyFile, "VAULT_CLIENT_CA": caFile, "VAULT_DB_URL": bootBadDB}
	dev := envWith(testDevEnv(), files)
	prod := envWith(testProdEnv(), files)
	withCatalog := func(env map[string]string, catEnv string) map[string]string {
		return envWith(env, map[string]string{"PAN_VAULT_TEST_CATALOG": bootCatalogJSON(catEnv)})
	}
	for _, c := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"dev, only a prod account", withCatalog(dev, "prod"), "catalog has no accounts for env=dev"},
		{"prod, only a dev account", withCatalog(prod, "dev"), "catalog has no accounts for env=prod"},
		// Controls: with an account for the environment the boot proceeds to the database.
		{"dev, a dev account", withCatalog(dev, "dev"), "VAULT_DB_URL cannot be parsed"},
		{"prod, a prod account", withCatalog(prod, "prod"), "VAULT_DB_URL cannot be parsed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, stderr := runMain(t, c.env)
			if code != 1 {
				t.Errorf("exit code %d, want 1", code)
			}
			if strings.Contains(stderr, testSecret) {
				t.Fatal("stderr contains the secret value") // never print it
			}
			if !strings.Contains(stderr, " boot failed: "+c.want+"\n") {
				t.Errorf("stderr %q lacks boot failure reason %q", stderr, c.want)
			}
			if strings.Contains(stderr, "catalog loaded") {
				t.Error("catalog loaded before the database was opened")
			}
		})
	}
}

func TestNewServersConfig(t *testing.T) {
	v, _ := newTestVault(t)
	pool := x509.NewCertPool()
	cert := tls.Certificate{Certificate: [][]byte{{1, 2, 3}}}
	cfg := config{publicAddr: "127.0.0.1:18443", internalAddr: "127.0.0.1:19443"}
	pub, internal := newServers(v, cfg, cert, pool)
	for _, s := range []struct {
		name  string
		srv   *http.Server
		addr  string
		write time.Duration
	}{{"public", pub, cfg.publicAddr, 30 * time.Second}, {"internal", internal, cfg.internalAddr, 60 * time.Second}} {
		srv := s.srv
		if srv.Addr != s.addr || srv.Handler == nil {
			t.Errorf("%s: addr or handler wrong", s.name)
		}
		if srv.ReadHeaderTimeout != 5*time.Second || srv.ReadTimeout != 10*time.Second || srv.WriteTimeout != s.write ||
			srv.IdleTimeout != 60*time.Second || srv.MaxHeaderBytes != 16<<10 {
			t.Errorf("%s: timeouts or MaxHeaderBytes wrong", s.name)
		}
		if srv.ErrorLog == nil || srv.ErrorLog.Writer() != io.Discard {
			t.Errorf("%s: ErrorLog does not discard", s.name)
		}
		tc := srv.TLSConfig
		if tc == nil || tc.MinVersion != tls.VersionTLS13 || len(tc.Certificates) != 1 || tc.InsecureSkipVerify {
			t.Fatalf("%s: TLS config wrong", s.name)
		}
	}
	if pub.TLSConfig.ClientAuth != tls.NoClientCert || pub.TLSConfig.ClientCAs != nil {
		t.Error("public listener asks for client certs")
	}
	if internal.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert || internal.TLSConfig.ClientCAs != pool {
		t.Error("internal listener does not require and verify client certs against the CA")
	}
	if pub.TLSConfig == internal.TLSConfig {
		t.Error("listeners share one *tls.Config")
	}

	// Each handler is the right one: /tokenize answers on public, /healthz (with a cert) on internal.
	rec := httptest.NewRecorder()
	pub.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("public /healthz status %d, want 404", rec.Code)
	}
	rec = httptest.NewRecorder()
	internal.Handler.ServeHTTP(rec, withClientCert(httptest.NewRequest(http.MethodGet, "/healthz", nil)))
	if rec.Code != http.StatusOK {
		t.Errorf("internal /healthz status %d, want 200", rec.Code)
	}
}
