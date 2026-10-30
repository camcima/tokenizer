package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Test failure messages never print a PAN, expiry or CVV: they print a case index or a length.

func TestLuhn(t *testing.T) {
	for i, s := range []string{"4242424242424242", "4000056655665556", "5555555555554444",
		"378282246310005", "6011111111111117", "4222222222222", "6200000000000005"} {
		if !luhnValid(s) {
			t.Errorf("valid case %d (len %d) rejected", i, len(s))
		}
	}
	for i, s := range []string{"4242424242424241", "1234567890123", ""} {
		if luhnValid(s) {
			t.Errorf("invalid case %d (len %d) accepted", i, len(s))
		}
	}
}

func TestNormalizePAN(t *testing.T) {
	ok := []struct{ in, want string }{
		{"4242 4242 4242 4242", "4242424242424242"},
		{"4242-4242-4242-4242", "4242424242424242"},
		{"4242424242424242", "4242424242424242"},
		{"4222222222222", "4222222222222"},             // 13 digits
		{"6200000000000005", "6200000000000005"},       // 16 digits, non-Visa
		{"4000000000000000006", "4000000000000000006"}, // 19 digits
	}
	for i, c := range ok {
		got, valid := normalizePAN(c.in)
		if !valid {
			t.Errorf("ok case %d (len %d) rejected", i, len(c.in))
			continue
		}
		if got != c.want {
			t.Errorf("ok case %d: normalized len %d, want len %d (or digits differ)", i, len(got), len(c.want))
		}
	}

	reject := []string{
		"424242424242",           // 12 digits
		"42424242424242424242",   // 20 digits
		"4242a42424242424",       // letter
		"4242424242424241",       // Luhn failure
		"4242\t4242424242424242", // tab is not stripped
		"",                       // empty
		" - ",                    // separators only
		"４２４２４２４２４２４２４２４２",    // full-width digits
		"4242.4242.4242.4242", // dot is not stripped
		"+4242424242424242",   // sign
	}
	for i, s := range reject {
		if got, valid := normalizePAN(s); valid || got != "" {
			t.Errorf("reject case %d (len %d) accepted or returned non-empty", i, len(s))
		}
	}
}

func TestValidExpiry(t *testing.T) {
	now := time.Date(2026, 10, 30, 15, 4, 5, 0, time.UTC)
	ok := []struct{ m, y string }{
		{"10", "2026"}, // current month
		{"12", "2026"},
		{"01", "2027"},
		{"01", "2030"},
	}
	for i, c := range ok {
		if !validExpiry(c.m, c.y, now) {
			t.Errorf("ok case %d rejected", i)
		}
	}
	reject := []struct{ m, y string }{
		{"09", "2026"}, // last month
		{"12", "2025"}, // last year
		{"1", "2030"},
		{"13", "2030"},
		{"00", "2030"},
		{"12", "30"},
		{"12", "20301"},
		{"1a", "2030"},
		{"", ""},
		{"12", ""},
		{"", "2030"},
		{" 1", "2030"},
		{"12", "２０３０"},
	}
	for i, c := range reject {
		if validExpiry(c.m, c.y, now) {
			t.Errorf("reject case %d accepted", i)
		}
	}
}

// The month comparison is done in UTC: 2026-11-01 00:30 in UTC+02:00 is still October in UTC.
func TestValidExpiryUsesUTC(t *testing.T) {
	loc := time.FixedZone("UTC+2", 2*3600)
	now := time.Date(2026, 11, 1, 0, 30, 0, 0, loc) // == 2026-10-31 22:30 UTC
	if !validExpiry("10", "2026", now) {
		t.Error("current UTC month rejected when local zone is already in the next month")
	}
}

func TestValidCVV(t *testing.T) {
	for i, s := range []string{"123", "1234", "000"} {
		if !validCVV(s) {
			t.Errorf("ok case %d rejected", i)
		}
	}
	for i, s := range []string{"12", "12345", "12a", "", " 123", "１２３"} {
		if validCVV(s) {
			t.Errorf("reject case %d accepted", i)
		}
	}
}

func TestTokenFormatAndUniqueness(t *testing.T) {
	seen := make(map[string]bool, 100000)
	for i := 0; i < 100000; i++ {
		tok := newToken()
		if !tokenRe.MatchString(tok) {
			t.Fatalf("bad token format %q", tok)
		}
		if seen[tok] {
			t.Fatal("duplicate token")
		}
		seen[tok] = true
	}
}

func TestTokenRe(t *testing.T) {
	for i, s := range []string{
		"tok_" + strings.Repeat("A", 32), // uppercase hex
		"tok_" + strings.Repeat("a", 31),
		"tok_" + strings.Repeat("a", 33),
		"tok_" + strings.Repeat("g", 32),
		"TOK_" + strings.Repeat("a", 32),
		"tok_" + strings.Repeat("a", 32) + "\n",
		"",
	} {
		if tokenRe.MatchString(s) {
			t.Errorf("reject case %d matched", i)
		}
	}
}

func testDEK(t *testing.T) []byte {
	t.Helper()
	dek := make([]byte, 32)
	rand.Read(dek)
	return dek
}

func TestSealUnseal(t *testing.T) {
	dek := testDEK(t)
	pt := []byte(`{"pan":"4242424242424242","exp_month":"12","exp_year":"2030"}`)

	blob := seal(dek, pt)
	if len(blob) != 12+len(pt)+16 {
		t.Fatalf("blob len %d, want %d", len(blob), 12+len(pt)+16)
	}
	if bytes.Contains(blob, []byte("4242424242424242")) {
		t.Fatal("blob contains plaintext PAN")
	}
	got, err := unseal(dek, blob)
	if err != nil {
		t.Fatal("round trip unseal failed")
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round trip mismatch (got len %d, want len %d)", len(got), len(pt))
	}

	// Empty plaintext round-trips too.
	if got, err := unseal(dek, seal(dek, nil)); err != nil || len(got) != 0 {
		t.Fatal("empty plaintext round trip failed")
	}

	// Tampering with the nonce, the ciphertext, or the tag is detected.
	for _, off := range []int{0, 20, len(blob) - 1} {
		bad := bytes.Clone(blob)
		bad[off] ^= 0x01
		if _, err := unseal(dek, bad); err == nil {
			t.Errorf("tampered byte at offset %d accepted", off)
		}
	}

	// Wrong DEK.
	if _, err := unseal(testDEK(t), blob); err == nil {
		t.Error("wrong DEK accepted")
	}

	// Truncated blobs (shorter than nonce+tag) return an error, not a panic.
	for n := 0; n < 28; n++ {
		if _, err := unseal(dek, blob[:n]); err == nil {
			t.Errorf("blob of len %d accepted", n)
		}
	}
	if _, err := unseal(dek, nil); err == nil {
		t.Error("nil blob accepted")
	}
	// Truncated by one byte (tag damaged).
	if _, err := unseal(dek, blob[:len(blob)-1]); err == nil {
		t.Error("blob truncated by one byte accepted")
	}

	// Non-AES-256 keys are refused by unseal.
	for _, n := range []int{0, 16, 24, 31, 33} {
		if _, err := unseal(make([]byte, n), blob); err == nil {
			t.Errorf("DEK of len %d accepted", n)
		}
	}

	// Errors never carry plaintext or key material: they are static strings.
	if _, err := unseal(dek, blob[:5]); err == nil || strings.Contains(err.Error(), "4242") {
		t.Error("unexpected error text")
	}

	// A fresh random nonce per seal.
	nonces := make(map[string]bool, 10000)
	for i := 0; i < 10000; i++ {
		b := seal(dek, pt)
		nonces[string(b[:12])] = true
	}
	if len(nonces) != 10000 {
		t.Fatalf("got %d distinct nonces from 10000 seals", len(nonces))
	}
}

func TestSealRejectsNonAES256Key(t *testing.T) {
	for _, n := range []int{0, 16, 24, 31, 33} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("seal with DEK of len %d did not panic", n)
				}
			}()
			seal(make([]byte, n), []byte("x"))
		}()
	}
}

// The sealed plaintext is exactly json.Marshal(card{PAN, ExpMonth, ExpYear}) with these keys
// and no CVV (§8.1); it must round-trip through seal/unseal.
func TestCardJSONSealRoundTrip(t *testing.T) {
	c := card{PAN: "4242424242424242", ExpMonth: "12", ExpYear: "2030"}
	pt, err := json.Marshal(c)
	if err != nil {
		t.Fatal("marshal failed")
	}
	if want := `{"pan":"4242424242424242","exp_month":"12","exp_year":"2030"}`; string(pt) != want {
		t.Fatalf("card JSON shape differs (len %d, want len %d)", len(pt), len(want))
	}
	dek := testDEK(t)
	out, err := unseal(dek, seal(dek, pt))
	if err != nil {
		t.Fatal("unseal failed")
	}
	var got card
	if err := json.Unmarshal(out, &got); err != nil || got != c {
		t.Fatal("card did not round-trip")
	}
	zero(pt)
	zero(out)
}

func TestZero(t *testing.T) {
	b := []byte("4242424242424242")
	zero(b)
	for i, c := range b {
		if c != 0 {
			t.Fatalf("byte %d not zeroed", i)
		}
	}
	zero(nil) // must not panic
}

// ---------------------------------------------------------------------------
// Vault core test helpers (used by every later handler test)
// ---------------------------------------------------------------------------

const (
	testPAN    = "4242424242424242"
	testCVV    = "9071"
	testSecret = "sk_test_vaultsecret_x9"
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
	mu       sync.Mutex
	rows     map[string]fakeRow
	velocity bool
}

func (s *fakeStore) putCard(_ context.Context, token string, ciphertext []byte, last4 string, keyVersion int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.rows[token]; dup {
		return errors.New("duplicate token") // the real put_card fails on the primary key
	}
	s.rows[token] = fakeRow{ciphertext: bytes.Clone(ciphertext), last4: last4, keyVersion: keyVersion}
	return nil
}

func (s *fakeStore) getCard(_ context.Context, token, _ string) ([]byte, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.velocity {
		return nil, 0, errVelocity
	}
	r, ok := s.rows[token]
	if !ok {
		return nil, 0, errUnknownToken
	}
	return bytes.Clone(r.ciphertext), r.keyVersion, nil
}

// newTestVault returns a vault wired to an in-memory fakeStore: DEK v1 = 32×0x01, session key
// testHMACKey, origin testOrigin, logger → &testLog, clock fixed at testNow (shared with the
// CVV cache).
func newTestVault(t *testing.T) (*vault, *fakeStore) {
	t.Helper()
	s := &fakeStore{rows: make(map[string]fakeRow)}
	now := func() time.Time { return testNow }
	v := &vault{
		putCard:     s.putCard,
		getCard:     s.getCard,
		ping:        func(context.Context) error { return nil },
		deks:        map[int][]byte{1: bytes.Repeat([]byte{0x01}, 32)},
		currentDEK:  1,
		hmacKey:     testHMACKey,
		allowOrigin: testOrigin,
		cvv:         newCVVCache(15*time.Minute, now),
		now:         now,
		log:         log.New(&testLog, "", 0),
	}
	return v, s
}

// mintSession builds a session token exactly as the platform does (§5.4).
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

// TestMain runs every test, then scans everything the test vaults logged (§13.1 log leak test).
func TestMain(m *testing.M) {
	code := m.Run()
	out := regexp.MustCompile(`tok_[0-9a-f]{32}`).ReplaceAllString(testLog.String(), "tok_")
	for _, loc := range regexp.MustCompile(`\d{13,19}`).FindAllStringIndex(out, -1) {
		if luhnValid(out[loc[0]:loc[1]]) {
			fmt.Fprintf(os.Stderr, "LOG LEAK: Luhn-valid digit run at offset %d\n", loc[0]) // never print it
			code = 1
		}
	}
	for _, s := range []string{testCVV, testSecret} {
		if strings.Contains(out, s) {
			fmt.Fprintln(os.Stderr, "LOG LEAK: test secret/CVV in log")
			code = 1
		}
	}
	os.Exit(code)
}

// ---------------------------------------------------------------------------
// Session tokens (§5.4) and the session_token_invalid alert (§10.1)
// ---------------------------------------------------------------------------

// upperMAC uppercases the third (HMAC) part of a "Bearer v1.<exp>.<mac>" header.
func upperMAC(authz string) string {
	i := strings.LastIndexByte(authz, '.')
	return authz[:i+1] + strings.ToUpper(authz[i+1:])
}

// signedExp returns a correctly signed token whose exp part carries a '+' sign, which
// strconv.ParseInt would accept but the format does not.
func signedExp(exp time.Time) string {
	msg := "v1.+" + strconv.FormatInt(exp.Unix(), 10)
	m := hmac.New(sha256.New, testHMACKey)
	m.Write([]byte(msg))
	return "Bearer " + msg + "." + hex.EncodeToString(m.Sum(nil))
}

// signRaw returns "Bearer v1.<exp>.<mac>" signed with testHMACKey for an arbitrary exp string.
func signRaw(exp string) string {
	m := hmac.New(sha256.New, testHMACKey)
	m.Write([]byte("v1." + exp))
	return "Bearer v1." + exp + "." + hex.EncodeToString(m.Sum(nil))
}

func TestCheckSession(t *testing.T) {
	now := testNow
	ok := func(exp time.Time) string { return "Bearer " + mintSession(testHMACKey, exp) }
	wrongKey := bytes.Repeat([]byte{1}, 32)
	cases := []struct{ name, authz, want string }{
		{"valid", ok(now.Add(time.Minute)), ""},
		{"exactly 15m", ok(now.Add(15 * time.Minute)), ""},
		{"now+1s", ok(now.Add(time.Second)), ""},
		{"15m+1s", ok(now.Add(15*time.Minute + time.Second)), "expired"},
		{"exp==now", ok(now), "expired"},
		{"past", ok(now.Add(-time.Second)), "expired"},
		{"far future", signRaw("9223372036854775807"), "expired"},
		{"wrong key", "Bearer " + mintSession(wrongKey, now.Add(time.Minute)), "hmac"},
		{"wrong key and expired", "Bearer " + mintSession(wrongKey, now.Add(-time.Hour)), "hmac"},
		{"no bearer", mintSession(testHMACKey, now.Add(time.Minute)), "format"},
		{"lowercase bearer", "bearer " + mintSession(testHMACKey, now.Add(time.Minute)), "format"},
		{"double space", "Bearer  " + mintSession(testHMACKey, now.Add(time.Minute)), "format"},
		{"trailing space", ok(now.Add(time.Minute)) + " ", "format"},
		{"empty", "", "format"},
		{"bearer only", "Bearer ", "format"},
		{"v2", strings.Replace(ok(now.Add(time.Minute)), "v1.", "v2.", 1), "format"},
		{"V1", strings.Replace(ok(now.Add(time.Minute)), "v1.", "V1.", 1), "format"},
		{"extra part", ok(now.Add(time.Minute)) + ".x", "format"},
		{"two parts", "Bearer v1." + strconv.FormatInt(now.Unix()+60, 10), "format"},
		{"uppercase hex", upperMAC(ok(now.Add(time.Minute))), "format"},
		{"short mac", ok(now.Add(time.Minute))[:len(ok(now.Add(time.Minute)))-1], "format"},
		{"long mac", ok(now.Add(time.Minute)) + "0", "format"},
		{"signed exp", signedExp(now.Add(time.Minute)), "format"},
		{"empty exp", signRaw(""), "format"},
		{"20-digit exp", signRaw("10000000000000000000"), "format"},
		{"int64 overflow exp", signRaw("9999999999999999999"), "format"},
		{"non-digit exp", signRaw("17x"), "format"},
		{"non-ASCII digit exp", signRaw("１７"), "format"},
	}
	for _, c := range cases {
		if got := checkSession(testHMACKey, c.authz, now); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}

	// A misconfigured (short or empty) key never authenticates anything, even a token signed
	// with that same key.
	for _, key := range [][]byte{nil, {}, bytes.Repeat([]byte{0x42}, 31)} {
		authz := "Bearer " + mintSession(key, now.Add(time.Minute))
		if got := checkSession(key, authz, now); got == "" {
			t.Errorf("key of len %d accepted a token", len(key))
		}
	}
}

func TestSessionAlertRateLimited(t *testing.T) {
	v, _ := newTestVault(t)
	clk := &fakeClock{t: testNow}
	v.now = clk.now
	const line = "ALERT session_token_invalid reason=hmac"

	start := testLog.Len()
	for i := 0; i < 5; i++ {
		v.alertSession("hmac")
	}
	if n := strings.Count(testLog.since(start), line); n != 1 {
		t.Fatalf("5 alerts within one second logged %d lines, want 1", n)
	}

	clk.advance(999 * time.Millisecond) // same second
	v.alertSession("hmac")
	if n := strings.Count(testLog.since(start), line); n != 1 {
		t.Fatalf("alert in the same second logged again (%d lines)", n)
	}

	clk.advance(time.Second)
	v.alertSession("hmac")
	if n := strings.Count(testLog.since(start), line); n != 2 {
		t.Fatalf("alert in the next second: %d lines, want 2", n)
	}

	// Concurrent callers in a fresh second still produce exactly one line.
	clk.advance(time.Second)
	start = testLog.Len()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); v.alertSession("expired") }()
	}
	wg.Wait()
	if n := strings.Count(testLog.since(start), "ALERT session_token_invalid reason=expired"); n != 1 {
		t.Fatalf("50 concurrent alerts logged %d lines, want 1", n)
	}

	// The line is timestamped by logf.
	re := regexp.MustCompile(`(?m)^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ ALERT session_token_invalid reason=expired$`)
	if !re.MatchString(testLog.since(start)) {
		t.Fatal("alert line has unexpected shape")
	}
}

// ---------------------------------------------------------------------------
// CVV cache (§8.5)
// ---------------------------------------------------------------------------

func TestCVVSingleUse(t *testing.T) {
	clk := &fakeClock{t: testNow}
	c := newCVVCache(15*time.Minute, clk.now)
	c.put("tok_a", testCVV)
	if c.take("tok_a") != testCVV {
		t.Fatal("first take did not return the cached CVV")
	}
	if c.take("tok_a") != "" {
		t.Fatal("second take returned a CVV")
	}
	if c.take("tok_absent") != "" {
		t.Fatal("take of an absent token returned a CVV")
	}
}

func TestCVVExpiry(t *testing.T) {
	clk := &fakeClock{t: testNow}
	c := newCVVCache(15*time.Minute, clk.now)

	c.put("tok_a", testCVV)
	clk.advance(15*time.Minute - time.Second)
	if c.take("tok_a") != testCVV {
		t.Fatal("CVV expired before its TTL")
	}

	c.put("tok_b", testCVV)
	clk.advance(15*time.Minute + time.Second)
	if c.take("tok_b") != "" {
		t.Fatal("CVV returned after its TTL")
	}

	// SPEC-DECISION (tested): an entry is expired at exactly put+TTL.
	c.put("tok_c", testCVV)
	clk.advance(15 * time.Minute)
	if c.take("tok_c") != "" {
		t.Fatal("CVV returned at exactly put+TTL")
	}
}

func TestCVVSweep(t *testing.T) {
	clk := &fakeClock{t: testNow}
	c := newCVVCache(15*time.Minute, clk.now)
	c.put("tok_a", testCVV)
	clk.advance(16 * time.Minute)
	c.put("tok_b", testCVV)
	c.mu.Lock()
	n := len(c.m)
	_, hasA := c.m["tok_a"]
	c.mu.Unlock()
	if n != 1 || hasA {
		t.Fatalf("after sweep the cache holds %d entries (expired entry present: %v), want 1", n, hasA)
	}
}

func TestCVVConcurrentTake(t *testing.T) {
	c := newCVVCache(15*time.Minute, func() time.Time { return testNow })
	c.put("tok_a", testCVV)
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		hits int
	)
	start := make(chan struct{})
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if c.take("tok_a") != "" {
				mu.Lock()
				hits++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if hits != 1 {
		t.Fatalf("%d concurrent takes received the CVV, want exactly 1", hits)
	}
}

// ---------------------------------------------------------------------------
// guard, access log, error bodies (§5.7, §10.1)
// ---------------------------------------------------------------------------

// serveGuard runs one request through v.guard and returns the recorder and the log delta.
func serveGuard(v *vault, listener string, h http.Handler, r *http.Request) (*httptest.ResponseRecorder, string) {
	start := testLog.Len()
	rec := httptest.NewRecorder()
	v.guard(listener, h).ServeHTTP(rec, r)
	return rec, testLog.since(start)
}

func TestGuardLogLine(t *testing.T) {
	v, _ := newTestVault(t)
	noContent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	public := regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ req listener=public method=POST path=/tokenize status=204 dur=\d+ms\n$`)

	rec, out := serveGuard(v, "public", noContent, httptest.NewRequest("POST", "/tokenize", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d, want 204", rec.Code)
	}
	if !public.MatchString(out) {
		t.Fatalf("public log line has unexpected shape (len %d)", len(out))
	}
	if !strings.HasPrefix(out, "2026-10-30T15:04:05Z ") {
		t.Fatal("log timestamp does not come from the vault clock in RFC 3339 UTC")
	}

	// Internal listener: caller serial is appended.
	internal := regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ req listener=internal method=POST path=/proxy status=204 dur=\d+ms caller=A1B2C\n$`)
	_, out = serveGuard(v, "internal", noContent, withClientCert(httptest.NewRequest("POST", "/proxy", nil)))
	if !internal.MatchString(out) {
		t.Fatalf("internal log line has unexpected shape: %q", out)
	}

	// A handler that writes nothing is logged as 200.
	_, out = serveGuard(v, "internal", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		withClientCert(httptest.NewRequest("GET", "/healthz", nil)))
	if !strings.Contains(out, " method=GET path=/healthz status=200 ") {
		t.Fatalf("empty handler logged as %q", out)
	}

	// A body write without WriteHeader is logged as 200; a later WriteHeader does not change it.
	_, out = serveGuard(v, "public", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{}"))
		w.WriteHeader(http.StatusTeapot)
	}), httptest.NewRequest("OPTIONS", "/tokenize", nil))
	if !strings.Contains(out, " method=OPTIONS path=/tokenize status=200 ") {
		t.Fatalf("implicit 200 logged as %q", out)
	}

	// An unknown path never lands in the log (a PAN in the URL path).
	_, out = serveGuard(v, "public", noContent, httptest.NewRequest("POST", "/"+testPAN, nil))
	if !strings.Contains(out, " path=other ") || strings.Contains(out, testPAN) {
		t.Fatal("unknown path was not logged as path=other")
	}
	for _, p := range []string{"/", "/tokenize/", "/TOKENIZE", "/tokenize/x", "//tokenize", "/proxy/"} {
		_, out = serveGuard(v, "public", noContent, httptest.NewRequest("POST", p, nil))
		if !strings.Contains(out, " path=other ") {
			t.Errorf("path %q logged as %q", p, out)
		}
	}
	// The query string is never logged.
	_, out = serveGuard(v, "public", noContent, httptest.NewRequest("POST", "/tokenize?pan="+testPAN, nil))
	if !strings.Contains(out, " path=/tokenize ") || strings.Contains(out, testPAN) || strings.Contains(out, "?") {
		t.Fatal("query string reached the log")
	}

	// Unknown methods are logged as method=other.
	for _, m := range []string{"BREW", "PUT", "DELETE", "post", "HEAD"} {
		_, out = serveGuard(v, "public", noContent, httptest.NewRequest(m, "/tokenize", nil))
		if !strings.Contains(out, " method=other ") {
			t.Errorf("method %q logged as %q", m, out)
		}
	}

	// Without a client certificate the internal line carries an empty caller.
	_, out = serveGuard(v, "internal", noContent, httptest.NewRequest("POST", "/proxy", nil))
	if !strings.HasSuffix(out, "ms caller=\n") {
		t.Fatalf("internal line without cert: %q", out)
	}

	// Exactly one line per request.
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("%d lines for one request", n)
	}
}

func TestGuardRecoversPanic(t *testing.T) {
	v, _ := newTestVault(t)
	const marker = "guard-panic-marker-5d1e"
	before := testLog.Len()

	for _, val := range []any{marker + " " + testPAN, errors.New(marker + " " + testCVV)} {
		rec, out := serveGuard(v, "public", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic(val)
		}), httptest.NewRequest("POST", "/tokenize", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status %d, want 500", rec.Code)
		}
		if got := rec.Body.String(); got != `{"error":"internal error"}`+"\n" {
			t.Fatalf("panic body len %d is not the internal error body", len(got))
		}
		if !strings.Contains(out, " path=/tokenize status=500 dur=") || strings.Count(out, "\n") != 1 {
			t.Fatalf("panic log line: %q", out)
		}
	}

	// A wrong-length DEK makes seal panic; guard turns that into a 500 too.
	rec, _ := serveGuard(v, "public", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		seal(make([]byte, 7), []byte(testPAN))
	}), httptest.NewRequest("POST", "/tokenize", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("seal panic: status %d, want 500", rec.Code)
	}

	if out := testLog.since(before); strings.Contains(out, marker) || strings.Contains(out, "seal") {
		t.Fatal("panic value reached the log")
	}
}

// A panic after the response has started cannot become a clean 500: guard logs status=500 and
// aborts the connection (http.ErrAbortHandler) so the client never sees a truncated success.
func TestGuardPanicAfterWrite(t *testing.T) {
	v, _ := newTestVault(t)
	start := testLog.Len()
	rec := httptest.NewRecorder()
	h := v.guard("internal", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"partial":`))
		panic("guard-panic-marker-late")
	}))
	func() {
		defer func() {
			if p := recover(); p != http.ErrAbortHandler {
				t.Fatalf("guard re-panicked with %T, want http.ErrAbortHandler", p)
			}
		}()
		h.ServeHTTP(rec, withClientCert(httptest.NewRequest("POST", "/proxy", nil)))
		t.Fatal("guard did not abort the response")
	}()
	out := testLog.since(start)
	if !strings.Contains(out, " path=/proxy status=500 dur=") || strings.Contains(out, "marker") {
		t.Fatalf("late panic log line: %q", out)
	}
}

func TestCallerSerial(t *testing.T) {
	if got := callerSerial(httptest.NewRequest("POST", "/proxy", nil)); got != "" {
		t.Errorf("no TLS: got %q", got)
	}
	r := httptest.NewRequest("POST", "/proxy", nil)
	r.TLS = &tls.ConnectionState{}
	if got := callerSerial(r); got != "" {
		t.Errorf("no peer certificates: got %q", got)
	}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	if got := callerSerial(r); got != "" {
		t.Errorf("nil serial: got %q", got)
	}
	if got := callerSerial(withClientCert(httptest.NewRequest("POST", "/proxy", nil))); got != "A1B2C" {
		t.Errorf("got %q, want A1B2C", got)
	}
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, http.StatusNotFound, msgNotFound)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
	// The body ends with a newline (json.Encoder style); pinned.
	if got := rec.Body.String(); got != `{"error":"not found"}`+"\n" {
		t.Fatalf("body len %d is not the pinned error body", len(got))
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control %q", cc)
	}
	if n := rec.Header().Get("X-Content-Type-Options"); n != "nosniff" {
		t.Fatalf("X-Content-Type-Options %q", n)
	}

	rec = httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, map[string]string{"token": "tok_x"})
	if rec.Code != http.StatusOK || rec.Body.String() != `{"token":"tok_x"}`+"\n" ||
		rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("writeJSON: status %d, body len %d", rec.Code, rec.Body.Len())
	}

	// A body that cannot be marshalled becomes a 500 internal error, not a partial write.
	rec = httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, func() {})
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != `{"error":"internal error"}`+"\n" {
		t.Fatalf("unmarshalable body: status %d, body len %d", rec.Code, rec.Body.Len())
	}
}

// Every error message is one of the fixed constants (§5.7) with its exact text.
func TestErrorConstants(t *testing.T) {
	want := map[string]string{
		msgNotFound: "not found", msgMethod: "method not allowed", msgQuery: "query string not allowed",
		msgContentType: "content type must be application/json", msgTooLarge: "request body too large",
		msgBadBody: "invalid request body", msgInvalidPAN: "invalid pan", msgInvalidExpiry: "invalid expiry",
		msgInvalidCVV: "invalid cvv", msgUnauthorized: "unauthorized", msgOrigin: "origin not allowed",
		msgUnknownProvider: "unknown provider", msgUnknownOp: "unknown op", msgInvalidToken: "invalid token",
		msgUnknownToken: "unknown token", msgInvalidParams: "invalid params",
		msgInvalidIdempotency: "invalid idempotency key", msgVelocity: "rate limit exceeded",
		msgInternal: "internal error", msgProvider: "provider unreachable", msgUnavailable: "unavailable",
	}
	if len(want) != 21 {
		t.Fatalf("%d distinct constants, want 21", len(want))
	}
	for k, v := range want {
		if k != v {
			t.Errorf("constant %q, want %q", k, v)
		}
	}
}

func TestNewTestVaultStore(t *testing.T) {
	v, s := newTestVault(t)
	ctx := context.Background()
	if err := v.ping(ctx); err != nil {
		t.Fatal("ping failed")
	}
	if _, _, err := v.getCard(ctx, "tok_absent", "A1B2C"); !errors.Is(err, errUnknownToken) {
		t.Fatal("absent token did not return errUnknownToken")
	}
	if err := v.putCard(ctx, "tok_a", []byte{1, 2, 3}, "4242", 1); err != nil {
		t.Fatal("putCard failed")
	}
	if err := v.putCard(ctx, "tok_a", []byte{1}, "4242", 1); err == nil {
		t.Fatal("duplicate putCard accepted")
	}
	ct, ver, err := v.getCard(ctx, "tok_a", "A1B2C")
	if err != nil || ver != 1 || !bytes.Equal(ct, []byte{1, 2, 3}) {
		t.Fatal("getCard did not return the stored row")
	}
	s.velocity = true
	if _, _, err := v.getCard(ctx, "tok_a", "A1B2C"); !errors.Is(err, errVelocity) {
		t.Fatal("velocity flag did not return errVelocity")
	}
	if !v.now().Equal(testNow) || !v.cvv.now().Equal(testNow) || len(v.deks[v.currentDEK]) != 32 {
		t.Fatal("test vault clock or DEK misconfigured")
	}
}
