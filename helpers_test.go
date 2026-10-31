// Test constants, fakes and helpers shared across the test files, and TestMain with the leak scanner.

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Test failure messages never print a PAN, expiry or CVV: they print a case index or a length.

// ---------------------------------------------------------------------------
// Vault core test helpers (used by every later handler test)
// ---------------------------------------------------------------------------

const (
	testPAN    = "4242424242424242"
	testCVV    = "9071"
	testSecret = "sk_test_vaultsecret_x9"
	testName   = "JANE Q TESTHOLDER" // cardholder-name sentinel for tests that use {{name}}; scanned for in the log
	testOrigin = "https://checkout.example.com"
)

var (
	testNow     = time.Date(2026, 10, 30, 15, 4, 5, 0, time.UTC)
	testHMACKey = bytes.Repeat([]byte{0x42}, 32)
)

// testLog is shared by every test vault and scanned for leaks in TestMain. Tests that assert
// on log output snapshot testLog.Len() first and inspect only testLog.since(n); such tests
// must not call t.Parallel.
var testLog lockedBuffer

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *lockedBuffer) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Len()
}

// since returns everything written after the buffer had length n.
func (l *lockedBuffer) since(n int) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()[n:]
}

type fakeRow struct {
	ciphertext []byte
	last4      string
	keyVersion int
}

type fakeStore struct {
	mu         sync.Mutex
	rows       map[string]fakeRow
	velocity   bool
	putErr     error  // when set, putCard returns it and stores nothing
	getErr     error  // when set (and velocity is not), getCard returns it
	lastCaller string // caller passed to the most recent getCard (the audit identity)
	gets       int    // number of getCard calls (each one is an audit and velocity row in the real store)
}

func (s *fakeStore) putCard(_ context.Context, token string, ciphertext []byte, last4 string, keyVersion int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.putErr != nil {
		return s.putErr
	}
	if _, dup := s.rows[token]; dup {
		return errors.New("duplicate token") // the real put_card fails on the primary key
	}
	s.rows[token] = fakeRow{ciphertext: bytes.Clone(ciphertext), last4: last4, keyVersion: keyVersion}
	return nil
}

func (s *fakeStore) getCard(_ context.Context, token, caller string) ([]byte, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastCaller = caller
	s.gets++
	if s.velocity {
		return nil, 0, errVelocity
	}
	if s.getErr != nil {
		return nil, 0, s.getErr
	}
	r, ok := s.rows[token]
	if !ok {
		return nil, 0, errUnknownToken
	}
	return bytes.Clone(r.ciphertext), r.keyVersion, nil
}

// newTestVault returns a vault wired to an in-memory fakeStore: DEK v1 = 32×0x01, session key
// testHMACKey, origin testOrigin, logger → &testLog, clock fixed at testNow, catalog =
// testCatalogJSON (dev) with every account secret set: payu_co's apiKey is payuTestAPIKey, every
// other one testSecret. The client stays nil; pointAccount aims an account and the client at a fake
// provider. The CVV cache reads the clock through v.now, so a test that replaces v.now moves both.
func newTestVault(t *testing.T) (*vault, *fakeStore) {
	t.Helper()
	s := &fakeStore{rows: make(map[string]fakeRow)}
	now := func() time.Time { return testNow }
	v := &vault{
		putCard:     s.putCard,
		getCard:     s.getCard,
		ping:        func(context.Context) error { return nil },
		hmacKey:     testHMACKey,
		allowOrigin: testOrigin,
		now:         now,
		log:         log.New(&testLog, "", 0),
		catalog:     testCatalog(t, testCatalogHost),
	}
	for _, a := range v.catalog.accounts {
		for name := range a.secretNames {
			a.secrets[name] = testSecret
		}
	}
	v.catalog.accounts["payu_co"].secrets["apiKey"] = payuTestAPIKey
	v.keys.Store(&dekSet{deks: map[int][]byte{1: bytes.Repeat([]byte{0x01}, 32)}, current: 1})
	v.cvv = newCVVCache(cvvCacheTTL, func() time.Time { return v.now() })
	return v, s
}

// mintSession builds a session token exactly as the platform does.
func mintSession(key []byte, exp time.Time) string {
	msg := "v1." + strconv.FormatInt(exp.Unix(), 10)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return msg + "." + hex.EncodeToString(m.Sum(nil))
}

// withClientCert attaches a verified client certificate with serial 0x0A1B2C to r.
func withClientCert(r *http.Request) *http.Request {
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{SerialNumber: big.NewInt(0x0A1B2C)}},
	}
	return r
}

// fillCVVCache inserts n entries expiring at exp under distinct tokens prefix+index. It writes the
// map directly: going through put would sweep the whole cache on every insert.
func fillCVVCache(c *cvvCache, prefix string, n int, exp time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := 0; i < n; i++ {
		c.m[prefix+strconv.Itoa(i)] = cvvEntry{cvv: []byte("000"), exp: exp}
	}
}

// storedCVV returns the slice cached for token (nil if absent), so a test can check that the
// cache zeroes it on removal.
func storedCVV(c *cvvCache, token string) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[token].cvv
}

// cvvCacheLen returns the number of entries in c, expired ones included.
func cvvCacheLen(c *cvvCache) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// allZero reports whether every byte of b is zero.
func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// fakeClock is a mutable clock owned by a single test.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// TestMain runs every test, then scans everything the test vaults logged (the log leak test).
// The scan checks the log as written and a copy with space/hyphen runs between digits removed
// (so "4242 4242 4242 4242" is caught), and within every maximal digit run it tests every window
// of length 13–19 (so a PAN embedded in a longer digit run is caught). Only offsets are printed.
func TestMain(m *testing.M) {
	if os.Getenv("PAN_VAULT_TEST_RUN_MAIN") == "1" {
		main() // a boot-sequence subprocess started by runMain; main always exits
		return
	}
	code := m.Run()
	out := regexp.MustCompile(`tok_[0-9a-f]{32}`).ReplaceAllString(testLog.String(), "tok_")
	for _, v := range []struct {
		name, text string
	}{{"as logged", out}, {"separators removed", joinDigitSeparators(out)}} {
		for _, off := range luhnWindowOffsets(v.text) {
			fmt.Fprintf(os.Stderr, "LOG LEAK: Luhn-valid 13–19 digit window at offset %d (%s)\n", off, v.name) // never print it
			code = 1
		}
	}
	for _, s := range []string{testCVV, testSecret, payuTestAPIKey, testName, url.QueryEscape(testName)} {
		if strings.Contains(out, s) {
			fmt.Fprintln(os.Stderr, "LOG LEAK: test secret/CVV/name in log")
			code = 1
		}
	}
	os.Exit(code)
}

// joinDigitSeparators removes every run of spaces and hyphens that sits between two ASCII
// digits, mirroring what normalizePAN strips.
func joinDigitSeparators(s string) string {
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == ' ' || s[i] == '-' {
			j := i
			for j < len(s) && (s[j] == ' ' || s[j] == '-') {
				j++
			}
			if i > 0 && isDigit(s[i-1]) && j < len(s) && isDigit(s[j]) {
				i = j
				continue
			}
			b.WriteString(s[i:j])
			i = j
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// luhnWindowOffsets returns the offset of every substring of length 13–19 inside a maximal
// ASCII digit run of s that passes Luhn.
func luhnWindowOffsets(s string) []int {
	var offs []int
	for _, run := range regexp.MustCompile(`[0-9]{13,}`).FindAllStringIndex(s, -1) {
		for i := run[0]; i < run[1]; i++ {
			for n := 13; n <= 19 && i+n <= run[1]; n++ {
				if luhnValid(s[i : i+n]) {
					offs = append(offs, i)
				}
			}
		}
	}
	return offs
}

// The leak scanner itself: separated and embedded PANs are found; short digit runs are not.
// Failure messages print only case indexes.
func TestLeakScanner(t *testing.T) {
	found := func(s string) bool {
		return len(luhnWindowOffsets(s)) > 0 || len(luhnWindowOffsets(joinDigitSeparators(s))) > 0
	}
	for i, s := range []string{
		"x " + testPAN + " y",
		"x 4242 4242 4242 4242 y",
		"x 4242-4242-4242-4242 y",
		"x 4242 - 4242  4242--4242 y",
		"x 99" + testPAN + "77 y",            // embedded in a longer run
		"x 1" + "4242 4242 4242 4242" + " y", // embedded after separator removal
		"x 4222222222222 y",                  // 13 digits
		"x 4000000000000000006 y",            // 19 digits
	} {
		if !found(s) {
			t.Errorf("leak case %d not found", i)
		}
	}
	for i, s := range []string{
		"2026-10-30T15:04:05Z req listener=internal method=POST path=/proxy status=200 dur=183ms caller=0A1B2C",
		"x 4242 4242 4242 y", // 12 digits
		"x 4242\n4242 y",     // newlines are not joined
		"",
	} {
		if found(s) {
			t.Errorf("clean case %d flagged", i)
		}
	}
	if got := joinDigitSeparators("a 1 - 2 b -3- c"); got != "a 12 b -3- c" {
		t.Errorf("joinDigitSeparators: got %q", got)
	}
}

// omit, as a header value in tokCase, means "do not send this header at all".
const omit = "\x00omit"

// tokBody returns goodBody's fields with over applied: a nil value removes the field.
func tokBody(over map[string]any) string {
	m := map[string]any{"pan": "4242 4242 4242 4242", "exp_month": "12", "exp_year": "2030", "cvv": testCVV}
	for k, val := range over {
		if val == nil {
			delete(m, k)
		} else {
			m[k] = val
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic("tokBody: marshal failed")
	}
	return string(b)
}

type tokCase struct {
	name                                       string
	method, target, origin, authz, ctype, body string // "" = default, omit = header absent
	wantStatus                                 int
	wantError                                  string // "" for a success
}

// tokRequest builds the request for c, filling defaults: POST /tokenize from testOrigin with a
// valid session, Content-Type application/json and goodBody.
func tokRequest(c tokCase) *http.Request {
	def := func(v, d string) string {
		if v == "" {
			return d
		}
		return v
	}
	r := httptest.NewRequest(def(c.method, "POST"), def(c.target, "/tokenize"), strings.NewReader(def(c.body, goodBody)))
	for _, h := range []struct{ name, val string }{
		{"Origin", def(c.origin, testOrigin)},
		{"Authorization", def(c.authz, validAuthz())},
		{"Content-Type", def(c.ctype, "application/json")},
	} {
		if h.val != omit {
			r.Header.Set(h.name, h.val)
		}
	}
	return r
}

// serveTokenize runs r through the public handler (guard included).
func serveTokenize(v *vault, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	v.publicHandler().ServeHTTP(rec, r)
	return rec
}

// padBody returns body with spaces inserted before the closing brace so it is exactly n bytes.
func padBody(body string, n int) string {
	return body[:len(body)-1] + strings.Repeat(" ", n-len(body)) + "}"
}

// testCatalogHost is the host of every testCatalogJSON account. testCatalog replaces it (quoted, so
// only host values change) with the host under test, e.g. an httptest server's 127.0.0.1:port. A
// test that needs different hosts per account sets c.accounts[name].host after parsing.
const testCatalogHost = "upstream.test"

// testCatalogJSON is the synthetic catalog the proxy tests run against. It models Stripe (form) and
// the four first-wave json shapes: Adyen (account pin, forbid list, X-API-Key header),
// Mercado Pago (single-use card token, :int expiry, Bearer), PayU (body credential, account and
// literal pins, payu signer, yyyy/mm expiry) and Pagar.me (Basic auth, array positions). Every
// provider has a dev account; adyen_br_live is the one prod account. Stripe's confirm_payment_intent
// carries the wildcard path segment and the query key. Every endpoint is card_data with a {{pan}}
// position: the catalog has no non-card endpoints. Endpoint and account entries
// keep their identifying fields on one line so that tests can mutate them with a string replace.
// Secret resources all start with "projects/", so a test can check that no error names one.
const testCatalogJSON = `{
  "providers": {
    "stripe": {
      "format": "form",
      "endpoints": [
        {
          "id": "payment_intents", "method": "POST", "path": "/v1/payment_intents", "card_data": true,
          "headers": {"Authorization": "Bearer {{secret:secretKey}}"},
          "positions": {
            "payment_method_data[card][number]": "{{pan}}",
            "payment_method_data[card][exp_month]": "{{exp_month}}",
            "payment_method_data[card][exp_year]": "{{exp_year}}",
            "payment_method_data[card][cvc]": "{{cvv}}",
            "payment_method_data[billing_details][name]": "{{name}}"
          },
          "forbid": {
            "setup_future_usage": [],
            "customer": [],
            "save_payment_method": [],
            "payment_method_options[card][setup_future_usage]": []
          }
        },
        {
          "id": "tokens", "method": "POST", "path": "/v1/tokens", "card_data": true,
          "headers": {"Authorization": "Bearer {{secret:secretKey}}"},
          "positions": {
            "card[number]": "{{pan}}",
            "card[exp_month]": "{{exp_month}}",
            "card[exp_year]": "{{exp_year}}",
            "card[cvc]": "{{cvv}}",
            "card[name]": "{{name}}"
          }
        },
        {
          "id": "confirm_payment_intent", "method": "POST", "path": "/v1/payment_intents/{id}/confirm", "query": ["expand[]"], "card_data": true,
          "headers": {"Authorization": "Bearer {{secret:secretKey}}"},
          "positions": {
            "payment_method_data[card][number]": "{{pan}}",
            "payment_method_data[card][exp_month]": "{{exp_month}}",
            "payment_method_data[card][exp_year]": "{{exp_year}}",
            "payment_method_data[card][cvc]": "{{cvv}}"
          },
          "forbid": {"setup_future_usage": [], "save_payment_method": [], "payment_method_options[card][setup_future_usage]": []}
        }
      ]
    },
    "adyen": {
      "format": "json",
      "endpoints": [
        {
          "id": "payments", "method": "POST", "path": "/v72/payments", "card_data": true,
          "headers": {"X-API-Key": "{{secret:apiKey}}"},
          "positions": {
            "/paymentMethod/number": "{{pan}}",
            "/paymentMethod/expiryMonth": "{{exp_month}}",
            "/paymentMethod/expiryYear": "{{exp_year}}",
            "/paymentMethod/cvc": "{{cvv}}",
            "/paymentMethod/holderName": "{{name}}"
          },
          "pins": {"/merchantAccount": {"account": "merchantAccount"}},
          "forbid": {"/storePaymentMethod": [false], "/recurringProcessingModel": [], "/shopperReference": []}
        }
      ]
    },
    "mercadopago": {
      "format": "json",
      "endpoints": [
        {
          "id": "card_tokens", "method": "POST", "path": "/v1/card_tokens", "card_data": true,
          "headers": {"Authorization": "Bearer {{secret:accessToken}}"},
          "positions": {
            "/card_number": "{{pan}}",
            "/expiration_month": "{{exp_month:int}}",
            "/expiration_year": "{{exp_year:int}}",
            "/security_code": "{{cvv}}",
            "/cardholder/name": "{{name}}"
          }
        }
      ]
    },
    "payu": {
      "format": "json",
      "endpoints": [
        {
          "id": "submit_transaction", "method": "POST", "path": "/payments-api/4.0/service.cgi", "card_data": true,
          "positions": {
            "/merchant/apiKey": "{{secret:apiKey}}",
            "/transaction/order/signature": "{{signature}}",
            "/transaction/creditCard/number": "{{pan}}",
            "/transaction/creditCard/securityCode": "{{cvv}}",
            "/transaction/creditCard/expirationDate": "{{exp:yyyy/mm}}",
            "/transaction/creditCard/name": "{{name}}"
          },
          "pins": {
            "/merchant/apiLogin": {"account": "apiLogin"},
            "/command": {"literal": "SUBMIT_TRANSACTION"},
            "/transaction/order/accountId": {"account": "accountId"}
          },
          "signer": "payu"
        }
      ]
    },
    "pagarme": {
      "format": "json",
      "endpoints": [
        {
          "id": "orders", "method": "POST", "path": "/core/v5/orders", "card_data": true,
          "headers": {"Authorization": "Basic {{basic:secretKey}}"},
          "positions": {
            "/payments/0/credit_card/card/number": "{{pan}}",
            "/payments/0/credit_card/card/exp_month": "{{exp_month:int}}",
            "/payments/0/credit_card/card/exp_year": "{{exp_year:int}}",
            "/payments/0/credit_card/card/cvv": "{{cvv}}",
            "/payments/0/credit_card/card/holder_name": "{{name}}"
          }
        }
      ]
    }
  },
  "accounts": {
    "stripe_t": {"provider": "stripe", "env": "dev", "host": "upstream.test", "base_path": "", "secrets": {"secretKey": "projects/pci-cde-dev/secrets/stripe-t-key"}},
    "adyen_br": {"provider": "adyen", "env": "dev", "host": "upstream.test", "base_path": "/checkout", "secrets": {"apiKey": "projects/pci-cde-dev/secrets/adyen-br-key"}, "values": {"merchantAccount": "AcmeBR_ECOM"}},
    "adyen_br_live": {"provider": "adyen", "env": "prod", "host": "upstream.test", "base_path": "/checkout", "secrets": {"apiKey": "projects/pci-cde-prod/secrets/adyen-br-key"}, "values": {"merchantAccount": "AcmeBR_LIVE"}},
    "mp_ar": {"provider": "mercadopago", "env": "dev", "host": "upstream.test", "secrets": {"accessToken": "projects/pci-cde-dev/secrets/mp-ar-token"}},
    "payu_co": {"provider": "payu", "env": "dev", "host": "upstream.test", "secrets": {"apiKey": "projects/pci-cde-dev/secrets/payu-co-key"}, "values": {"apiLogin": "pRRXKOl8ikMmt9u", "accountId": "512321", "merchantId": "508029", "hash": "sha256"}},
    "pagarme_br": {"provider": "pagarme", "env": "dev", "host": "upstream.test", "secrets": {"secretKey": "projects/pci-cde-dev/secrets/pagarme-br-key"}}
  }
}`

// testCatalog parses testCatalogJSON for env "dev" with every account host replaced by host.
func testCatalog(t *testing.T, host string) *catalog {
	t.Helper()
	data := strings.ReplaceAll(testCatalogJSON, `"`+testCatalogHost+`"`, `"`+host+`"`)
	c, err := parseCatalog([]byte(data), "dev")
	if err != nil {
		t.Fatalf("test catalog: %v", err)
	}
	return c
}

// catEndpointByID returns provider's endpoint id, failing the test if there is none.
func catEndpointByID(t *testing.T, c *catalog, provider, id string) *catEndpoint {
	t.Helper()
	if p := c.providers[provider]; p != nil {
		for _, e := range p.endpoints {
			if e.id == id {
				return e
			}
		}
	}
	t.Fatalf("no endpoint %s/%s", provider, id)
	return nil
}

// Example platform bodies for the embedded catalog's stripe tokens endpoint (catalog.json), with and
// without the CVV, used by TestEmbeddedCatalog, TestProxyEmbeddedCardOnly, TestStripeMock and
// TestStripeLive.
const (
	embeddedTokensBody = `card[number]={{pan}}&card[exp_month]={{exp_month}}&card[exp_year]={{exp_year}}` +
		`&card[cvc]={{cvv}}&card[name]={{name}}`
	embeddedTokensNoCVV = `card[number]={{pan}}&card[exp_month]={{exp_month}}&card[exp_year]={{exp_year}}` +
		`&card[name]={{name}}`
)

// Valid platform bodies for each modelled provider (see testCatalogJSON).
const (
	stripePIBody = `amount=1000&currency=usd&confirm=true&payment_method_data[type]=card` +
		`&payment_method_data[card][number]={{pan}}&payment_method_data[card][exp_month]={{exp_month}}` +
		`&payment_method_data[card][exp_year]={{exp_year}}&payment_method_data[card][cvc]={{cvv}}`
	stripeConfirmBody = `payment_method_data[type]=card&payment_method_data[card][number]={{pan}}` +
		`&payment_method_data[card][exp_month]={{exp_month}}&payment_method_data[card][exp_year]={{exp_year}}`
	adyenBody = `{"amount":{"currency":"BRL","value":1000},"reference":"ord-1","merchantAccount":"AcmeBR_ECOM",` +
		`"paymentMethod":{"type":"scheme","number":"{{pan}}","expiryMonth":"{{exp_month}}","expiryYear":"{{exp_year}}",` +
		`"cvc":"{{cvv}}","holderName":"{{name}}"},"storePaymentMethod":false}`
	mpBody = `{"card_number":"{{pan}}","expiration_month":"{{exp_month:int}}","expiration_year":"{{exp_year:int}}",` +
		`"security_code":"{{cvv}}"}`
	payuBody = `{"language":"es","command":"SUBMIT_TRANSACTION","merchant":{"apiKey":"{{secret:apiKey}}","apiLogin":"pRRXKOl8ikMmt9u"},` +
		`"transaction":{"order":{"accountId":"512321","referenceCode":"TestPayU","description":"x","signature":"{{signature}}",` +
		`"additionalValues":{"TX_VALUE":{"value":3,"currency":"USD"}}},` +
		`"creditCard":{"number":"{{pan}}","securityCode":"{{cvv}}","expirationDate":"{{exp:yyyy/mm}}","name":"{{name}}"},` +
		`"type":"AUTHORIZATION_AND_CAPTURE"},"test":true}`
	pagarmeBody = `{"items":[{"amount":1000,"description":"x","quantity":1}],"payments":[{"payment_method":"credit_card",` +
		`"credit_card":{"card":{"number":"{{pan}}","exp_month":"{{exp_month:int}}","exp_year":"{{exp_year:int}}",` +
		`"holder_name":"{{name}}"}}}]}`
)

// newEnvelope returns a /proxy envelope for checkProxy.
func newEnvelope(account, method, path string, headers map[string]string, body string) *proxyEnvelope {
	e := &proxyEnvelope{Account: account, Token: checkToken}
	e.Request.Method, e.Request.Path, e.Request.Headers, e.Request.Body = method, path, headers, body
	return e
}

// validEnvelope returns a fresh valid envelope for each modelled provider endpoint.
func validEnvelope(name string) *proxyEnvelope {
	switch name {
	case "stripe":
		return newEnvelope("stripe_t", "POST", "/v1/payment_intents",
			map[string]string{"Idempotency-Key": "ord-1", "Authorization": "Bearer {{secret:secretKey}}"}, stripePIBody)
	case "stripe_confirm":
		return newEnvelope("stripe_t", "POST", "/v1/payment_intents/pi_123/confirm?expand[]=latest_charge&expand%5B%5D=customer",
			map[string]string{"Accept": "application/json"}, stripeConfirmBody)
	case "adyen":
		return newEnvelope("adyen_br", "POST", "/v72/payments",
			map[string]string{"Idempotency-Key": "ord-1", "X-API-Key": "{{secret:apiKey}}"}, adyenBody)
	case "mercadopago":
		return newEnvelope("mp_ar", "POST", "/v1/card_tokens",
			map[string]string{"X-Idempotency-Key": "k-1", "Authorization": "Bearer {{secret:accessToken}}"}, mpBody)
	case "payu":
		return newEnvelope("payu_co", "POST", "/payments-api/4.0/service.cgi", nil, payuBody)
	case "pagarme":
		return newEnvelope("pagarme_br", "POST", "/core/v5/orders", map[string]string{"Accept": "application/json"}, pagarmeBody)
	}
	panic("validEnvelope: unknown provider")
}

const payuTestAPIKey = "4Vj8eK4rloUd272L48hsrarnUA" // PayU's documented example key

// fakeProvider is an httptest TLS server standing in for a provider. It records the last request
// it received; respond (if set) writes the response, else it answers 200 {"id":"pm_123"}.
type fakeProvider struct {
	ts      *httptest.Server
	respond func(w http.ResponseWriter, r *http.Request)

	mu     sync.Mutex
	hits   int
	method string
	path   string
	query  string
	header http.Header
	body   []byte
}

func newFakeProvider(t *testing.T, respond func(w http.ResponseWriter, r *http.Request)) *fakeProvider {
	t.Helper()
	fp := &fakeProvider{respond: respond}
	fp.ts = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		buf.ReadFrom(r.Body)
		fp.mu.Lock()
		fp.hits++
		fp.method, fp.path, fp.query, fp.header, fp.body = r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), buf.Bytes()
		fp.mu.Unlock()
		if fp.respond != nil {
			fp.respond(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"pm_123"}`))
	}))
	fp.ts.Config.ErrorLog = log.New(io.Discard, "", 0) // e.g. handshakes from an untrusting client
	fp.ts.StartTLS()
	t.Cleanup(fp.ts.Close)
	return fp
}

// last returns a snapshot of the last recorded request.
func (fp *fakeProvider) last() (hits int, method, path string, header http.Header, body []byte) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	return fp.hits, fp.method, fp.path, fp.header, fp.body
}

// lastQuery returns the raw query of the last recorded request.
func (fp *fakeProvider) lastQuery() string {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	return fp.query
}

// pointAccount aims account's host at the httptest TLS server ts (the account's base path is kept)
// and the vault's client at a pool that trusts only ts's certificate.
func pointAccount(t *testing.T, v *vault, account string, ts *httptest.Server) {
	t.Helper()
	a := v.catalog.accounts[account]
	if a == nil {
		t.Fatalf("no account %s", account)
	}
	u, err := url.Parse(ts.URL)
	if err != nil || u.Host == "" {
		t.Fatal("bad fake provider URL")
	}
	a.host = u.Host
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	v.client = newOutboundClient(pool)
}

// seedCard seals testPAN 12/2030 (no name) under DEK 1 into the store, caches cvv if non-empty,
// and returns the token.
func seedCard(t *testing.T, v *vault, s *fakeStore, cvv string) string {
	t.Helper()
	return seedCardNamed(t, v, s, cvv, "")
}

// seedCardNamed is seedCard with a cardholder name ("" = stored without one).
func seedCardNamed(t *testing.T, v *vault, s *fakeStore, cvv, name string) string {
	t.Helper()
	pt, err := json.Marshal(card{PAN: testPAN, ExpMonth: "12", ExpYear: "2030", Name: name})
	if err != nil {
		t.Fatal("marshal card failed")
	}
	tok := newToken()
	s.mu.Lock()
	s.rows[tok] = fakeRow{ciphertext: seal(dekOf(v, 1), pt, cardAAD(tok)), last4: "4242", keyVersion: 1}
	s.mu.Unlock()
	if cvv != "" {
		v.cvv.put(tok, cvv)
	}
	return tok
}

// stripe_t POST /v1/tokens bodies: with every card placeholder but the name, and without the CVV.
const (
	stripeTokensBody  = `card[number]={{pan}}&card[exp_month]={{exp_month}}&card[exp_year]={{exp_year}}&card[cvc]={{cvv}}`
	stripeTokensNoCVV = `card[number]={{pan}}&card[exp_month]={{exp_month}}&card[exp_year]={{exp_year}}`
)

// seededValues replaces the placeholders of a body with what the vault substitutes for a
// seedCardNamed card (12/2030, testCVV, testName), encoded for format.
func seededValues(format, body string) string {
	if format == "form" {
		return strings.NewReplacer("{{pan}}", testPAN, "{{exp_month}}", "12", "{{exp_year}}", "2030",
			"{{cvv}}", testCVV, "{{name}}", url.QueryEscape(testName)).Replace(body)
	}
	return strings.NewReplacer(`"{{pan}}"`, `"`+testPAN+`"`, `"{{exp_month}}"`, `"12"`, `"{{exp_year}}"`, `"2030"`,
		`"{{exp_month:int}}"`, `12`, `"{{exp_year:int}}"`, `2030`, `"{{exp:yyyy/mm}}"`, `"2030/12"`,
		`"{{cvv}}"`, `"`+testCVV+`"`, `"{{name}}"`, `"`+testName+`"`).Replace(body)
}

// envelopeJSON encodes e as a /proxy request body.
func envelopeJSON(e *proxyEnvelope) string {
	b, err := json.Marshal(e)
	if err != nil {
		panic("envelopeJSON: marshal failed")
	}
	return string(b)
}

// newProxyRequest builds POST /proxy with a client certificate and Content-Type application/json.
func newProxyRequest(body string) *http.Request {
	r := withClientCert(httptest.NewRequest("POST", "/proxy", strings.NewReader(body)))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// serveInternal runs r through the internal handler (guard included).
func serveInternal(v *vault, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	v.internalHandler().ServeHTTP(rec, r)
	return rec
}

// wantErrBody is the exact error response body for msg.
func wantErrBody(msg string) string {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return string(b) + "\n"
}

const (
	testKMSKey     = "projects/p1/locations/global/keyRings/r1/cryptoKeys/k1"
	testHMACName   = "projects/p1/secrets/session-hmac"
	testStripeName = "projects/p1/secrets/stripe-key"
	testGCPToken   = "ya29.fake-access-token"
)

// newFakeMetadata serves the metadata token endpoint (requires Metadata-Flavor: Google) and
// points metadataTokenURL at it. respond, if set, writes the response instead.
func newFakeMetadata(t *testing.T, respond func(w http.ResponseWriter)) *atomic.Int32 {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/token" || r.Header.Get("Metadata-Flavor") != "Google" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		hits.Add(1)
		if respond != nil {
			respond(w)
			return
		}
		w.Header().Set("Metadata-Flavor", "Google")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"expires_in":3599,"token_type":"Bearer"}`, testGCPToken)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(srv.Close)
	pointURL(t, &metadataTokenURL, srv.URL+"/token")
	return &hits
}

func reversed(b []byte) []byte {
	out := slices.Clone(b)
	slices.Reverse(out)
	return out
}

// fakeKMS stands in for Cloud KMS: encrypt reverses the bytes, decrypt reverses them back.
// mode "short" makes decrypt return 31 bytes, "corrupt" flips a byte, "500" fails every call.
type fakeKMS struct {
	mu   sync.Mutex
	mode string
	hits int
}

func (k *fakeKMS) setMode(m string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.mode = m
}

func (k *fakeKMS) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.hits
}

func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()
	k := &fakeKMS{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k.mu.Lock()
		k.hits++
		mode := k.mode
		k.mu.Unlock()
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+testGCPToken ||
			r.Header.Get("Content-Type") != "application/json" || mode == "500" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var in map[string]string
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || len(in) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var field, out string
		switch r.URL.Path {
		case "/v1/" + testKMSKey + ":encrypt":
			field, out = "plaintext", "ciphertext"
		case "/v1/" + testKMSKey + ":decrypt":
			field, out = "ciphertext", "plaintext"
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		b, err := base64.StdEncoding.DecodeString(in[field])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		b = reversed(b)
		if out == "plaintext" && mode == "short" {
			b = b[:len(b)-1]
		}
		if out == "plaintext" && mode == "corrupt" {
			b[0] ^= 0xff
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{out: base64.StdEncoding.EncodeToString(b), "name": testKMSKey})
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(srv.Close)
	pointURL(t, &kmsBaseURL, srv.URL+"/v1/")
	return k
}

// newFakeSecretManager serves secrets[name] at /v1/<name>/versions/latest:access with a correct
// dataCrc32c (or a wrong one when badCRC). Unknown names are 404.
func newFakeSecretManager(t *testing.T, secrets map[string]string, badCRC bool) *atomic.Int32 {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+testGCPToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		name, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/v1/"), "/versions/latest:access")
		data, found := secrets[name]
		if !ok || !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		crc := crc32.Checksum([]byte(data), crc32.MakeTable(crc32.Castagnoli))
		if badCRC {
			crc++
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"name":%q,"payload":{"data":%q,"dataCrc32c":"%d"}}`,
			name+"/versions/1", base64.StdEncoding.EncodeToString([]byte(data)), crc)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(srv.Close)
	pointURL(t, &secretManagerBaseURL, srv.URL+"/v1/")
	return &hits
}

// safeErr is err's text for a failure message, unless it contains one of secrets.
func safeErr(err error, secrets ...string) string {
	if err == nil {
		return "<nil>"
	}
	for _, s := range secrets {
		if s != "" && strings.Contains(err.Error(), s) {
			return "<withheld: the error contains a secret>"
		}
	}
	return err.Error()
}

// testPKI returns a test CA (ECDSA P-256) with a pool holding it, a server certificate for
// 127.0.0.1 and a client certificate with serial 0x0A1B2C, both issued by the CA.
func testPKI(t *testing.T) (ca *x509.Certificate, caPool *x509.CertPool, server tls.Certificate, client tls.Certificate) {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	notBefore, notAfter := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	caKey := newKey()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pan-vault test CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if ca, err = x509.ParseCertificate(der); err != nil {
		t.Fatal(err)
	}
	caPool = x509.NewCertPool()
	caPool.AddCert(ca)

	issue := func(tmpl *x509.Certificate) tls.Certificate {
		key := newKey()
		tmpl.NotBefore, tmpl.NotAfter = notBefore, notAfter
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	}
	server = issue(&x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	client = issue(&x509.Certificate{
		SerialNumber: big.NewInt(0x0A1B2C),
		Subject:      pkix.Name{CommonName: "platform"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return ca, caPool, server, client
}

// tlsClient returns an HTTPS client that trusts roots and presents certs (none = no client cert).
func tlsClient(t *testing.T, roots *x509.CertPool, certs ...tls.Certificate) *http.Client {
	t.Helper()
	tr := &http.Transport{
		Proxy:           nil,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: certs},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}
}

// embeddedStripeVault returns a test vault whose catalog is the embedded catalog.json (dev), with
// the stripe_test account's secretKey set to secret. The account's host stays api.stripe.com until a
// test points it elsewhere.
func embeddedStripeVault(t *testing.T, secret string) (*vault, *fakeStore) {
	t.Helper()
	v, s := newTestVault(t)
	c, err := parseCatalog(catalogJSON, "dev")
	if err != nil {
		t.Fatalf("embedded catalog: %v", err)
	}
	c.accounts["stripe_test"].secrets["secretKey"] = secret
	v.catalog = c
	return v, s
}

// stripeProxyRequest returns POST /proxy for the stripe_test account on tok.
func stripeProxyRequest(tok, path string, headers map[string]string, body string) *http.Request {
	e := newEnvelope("stripe_test", "POST", path, headers, body)
	e.Token = tok
	return newProxyRequest(envelopeJSON(e))
}

// dekOf returns DEK version ver from the vault's current snapshot, or nil.
func dekOf(v *vault, ver int) []byte {
	d, _ := v.dek(ver)
	return d
}
