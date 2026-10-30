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
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
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
	putErr   error // when set, putCard returns it and stores nothing
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
// testHMACKey, origin testOrigin, logger → &testLog, clock fixed at testNow, providers =
// newProviders(testSecret) (client stays nil; proxy tests set it). The CVV cache reads
// the clock through v.now, so a test that replaces v.now moves both.
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
		now:         now,
		log:         log.New(&testLog, "", 0),
		providers:   newProviders(testSecret),
	}
	v.cvv = newCVVCache(15*time.Minute, func() time.Time { return v.now() })
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
// The scan checks the log as written and a copy with space/hyphen runs between digits removed
// (so "4242 4242 4242 4242" is caught), and within every maximal digit run it tests every window
// of length 13–19 (so a PAN embedded in a longer digit run is caught). Only offsets are printed.
func TestMain(m *testing.M) {
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
	for _, s := range []string{testCVV, testSecret} {
		if strings.Contains(out, s) {
			fmt.Fprintln(os.Stderr, "LOG LEAK: test secret/CVV in log")
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
	internal := regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ req listener=internal method=POST path=/proxy status=204 dur=\d+ms caller=0A1B2C\n$`)
	_, out = serveGuard(v, "internal", noContent, withClientCert(httptest.NewRequest("POST", "/proxy", nil)))
	if !internal.MatchString(out) {
		t.Fatalf("internal log line has unexpected shape (len %d, %d lines)", len(out), strings.Count(out, "\n"))
	}

	// A handler that writes nothing is logged as 200.
	_, out = serveGuard(v, "internal", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		withClientCert(httptest.NewRequest("GET", "/healthz", nil)))
	if !strings.Contains(out, " method=GET path=/healthz status=200 ") {
		t.Fatalf("empty handler log line unexpected (len %d, %d lines)", len(out), strings.Count(out, "\n"))
	}

	// A body write without WriteHeader is logged as 200; a later WriteHeader does not change it.
	_, out = serveGuard(v, "public", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{}"))
		w.WriteHeader(http.StatusTeapot)
	}), httptest.NewRequest("OPTIONS", "/tokenize", nil))
	if !strings.Contains(out, " method=OPTIONS path=/tokenize status=200 ") {
		t.Fatalf("implicit 200 log line unexpected (len %d, %d lines)", len(out), strings.Count(out, "\n"))
	}

	// An unknown path never lands in the log (a PAN in the URL path).
	_, out = serveGuard(v, "public", noContent, httptest.NewRequest("POST", "/"+testPAN, nil))
	if !strings.Contains(out, " path=other ") || strings.Contains(out, testPAN) {
		t.Fatal("unknown path was not logged as path=other")
	}
	for _, p := range []string{"/", "/tokenize/", "/TOKENIZE", "/tokenize/x", "//tokenize", "/proxy/"} {
		_, out = serveGuard(v, "public", noContent, httptest.NewRequest("POST", p, nil))
		if !strings.Contains(out, " path=other ") {
			t.Errorf("path %q not logged as path=other (len %d, %d lines)", p, len(out), strings.Count(out, "\n"))
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
			t.Errorf("method %q not logged as method=other (len %d, %d lines)", m, len(out), strings.Count(out, "\n"))
		}
	}

	// Without a client certificate the internal line carries an empty caller.
	_, out = serveGuard(v, "internal", noContent, httptest.NewRequest("POST", "/proxy", nil))
	if !strings.HasSuffix(out, "ms caller=\n") {
		t.Fatalf("internal line without cert unexpected (len %d, %d lines)", len(out), strings.Count(out, "\n"))
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
			t.Fatalf("panic log line unexpected (len %d, %d lines)", len(out), strings.Count(out, "\n"))
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
		t.Fatalf("late panic log line unexpected (len %d, %d lines)", len(out), strings.Count(out, "\n"))
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
	if got := callerSerial(withClientCert(httptest.NewRequest("POST", "/proxy", nil))); got != "0A1B2C" {
		t.Errorf("got %q, want 0A1B2C", got)
	}
	// Byte-wise uppercase hex as `openssl x509 -serial` prints it (§10.1).
	for _, c := range []struct {
		serial *big.Int
		want   string
	}{
		{big.NewInt(0), "00"},
		{big.NewInt(0x0F), "0F"},
		{big.NewInt(0xFF), "FF"},
		{big.NewInt(0x100), "0100"},
		{new(big.Int).SetBytes([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}), "DEADBEEF0001"},
		{big.NewInt(-5), ""}, // negative serials are invalid (RFC 5280) and never identify a caller
	} {
		r := httptest.NewRequest("POST", "/proxy", nil)
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SerialNumber: c.serial}}}
		if got := callerSerial(r); got != c.want {
			t.Errorf("serial %s: got %q, want %q", c.serial, got, c.want)
		}
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
	if _, _, err := v.getCard(ctx, "tok_absent", "0A1B2C"); !errors.Is(err, errUnknownToken) {
		t.Fatal("absent token did not return errUnknownToken")
	}
	if err := v.putCard(ctx, "tok_a", []byte{1, 2, 3}, "4242", 1); err != nil {
		t.Fatal("putCard failed")
	}
	if err := v.putCard(ctx, "tok_a", []byte{1}, "4242", 1); err == nil {
		t.Fatal("duplicate putCard accepted")
	}
	ct, ver, err := v.getCard(ctx, "tok_a", "0A1B2C")
	if err != nil || ver != 1 || !bytes.Equal(ct, []byte{1, 2, 3}) {
		t.Fatal("getCard did not return the stored row")
	}
	s.velocity = true
	if _, _, err := v.getCard(ctx, "tok_a", "0A1B2C"); !errors.Is(err, errVelocity) {
		t.Fatal("velocity flag did not return errVelocity")
	}
	if !v.now().Equal(testNow) || !v.cvv.now().Equal(testNow) || len(v.deks[v.currentDEK]) != 32 {
		t.Fatal("test vault clock or DEK misconfigured")
	}
}

// ---------------------------------------------------------------------------
// POST /tokenize and CORS (§5)
// ---------------------------------------------------------------------------

// omit, as a header value in tokCase, means "do not send this header at all".
const omit = "\x00omit"

// goodBody is the canonical valid /tokenize request (spaced PAN, CVV present).
const goodBody = `{"pan":"4242 4242 4242 4242","exp_month":"12","exp_year":"2030","cvv":"9071"}`

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

// validAuthz is a session token the platform would mint for testNow.
func validAuthz() string { return "Bearer " + mintSession(testHMACKey, testNow.Add(10*time.Minute)) }

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

func TestTokenize(t *testing.T) {
	expired := "Bearer " + mintSession(testHMACKey, testNow.Add(-time.Second))
	future := "Bearer " + mintSession(testHMACKey, testNow.Add(15*time.Minute+time.Second))
	wrongKey := "Bearer " + mintSession(bytes.Repeat([]byte{0x43}, 32), testNow.Add(time.Minute))

	cases := []tokCase{
		// Success, including every passing variant of the §5.5 rules.
		{name: "good", wantStatus: 200},
		{name: "no cvv", body: tokBody(map[string]any{"cvv": nil}), wantStatus: 200},
		{name: "cvv null is absent", body: `{"pan":"4242424242424242","exp_month":"12","exp_year":"2030","cvv":null}`, wantStatus: 200},
		{name: "hyphen pan", body: tokBody(map[string]any{"pan": "4242-4242-4242-4242"}), wantStatus: 200},
		{name: "plain pan", body: tokBody(map[string]any{"pan": testPAN}), wantStatus: 200},
		{name: "13-digit pan", body: tokBody(map[string]any{"pan": "4222222222222"}), wantStatus: 200},
		{name: "19-digit pan", body: tokBody(map[string]any{"pan": "4000000000000000006"}), wantStatus: 200},
		{name: "3-digit cvv", body: tokBody(map[string]any{"cvv": "123"}), wantStatus: 200},
		{name: "current month", body: tokBody(map[string]any{"exp_month": "10", "exp_year": "2026"}), wantStatus: 200},
		{name: "january next year", body: tokBody(map[string]any{"exp_month": "01", "exp_year": "2027"}), wantStatus: 200},
		{name: "ctype charset utf-8", ctype: "application/json; charset=utf-8", wantStatus: 200},
		{name: "ctype mixed case", ctype: "Application/JSON", wantStatus: 200},
		{name: "trailing whitespace", body: goodBody + "\n  \t", wantStatus: 200},
		{name: "body exactly 4096", body: padBody(goodBody, 4096), wantStatus: 200},

		// 404: path must be exactly /tokenize.
		{name: "trailing slash path", target: "/tokenize/", wantStatus: 404, wantError: msgNotFound},
		{name: "root path", target: "/", wantStatus: 404, wantError: msgNotFound},
		{name: "upper path", target: "/TOKENIZE", wantStatus: 404, wantError: msgNotFound},
		{name: "encoded path", target: "/%74okenize", wantStatus: 404, wantError: msgNotFound},
		{name: "pan path", target: "/" + testPAN, wantStatus: 404, wantError: msgNotFound},

		// 405: POST or OPTIONS only.
		{name: "GET", method: "GET", wantStatus: 405, wantError: msgMethod},
		{name: "PUT", method: "PUT", wantStatus: 405, wantError: msgMethod},
		{name: "HEAD", method: "HEAD", wantStatus: 405, wantError: msgMethod},
		{name: "lowercase post", method: "post", wantStatus: 405, wantError: msgMethod},

		// 400 query string.
		{name: "query", target: "/tokenize?x=1", wantStatus: 400, wantError: msgQuery},
		{name: "pan in query", target: "/tokenize?pan=" + testPAN, wantStatus: 400, wantError: msgQuery},
		{name: "bare question mark", target: "/tokenize?", wantStatus: 400, wantError: msgQuery},

		// 403 origin: exact match only.
		{name: "evil origin", origin: "https://evil.example", wantStatus: 403, wantError: msgOrigin},
		{name: "origin trailing slash", origin: testOrigin + "/", wantStatus: 403, wantError: msgOrigin},
		{name: "origin other port", origin: "https://checkout.example.com:8443", wantStatus: 403, wantError: msgOrigin},
		{name: "origin http", origin: "http://checkout.example.com", wantStatus: 403, wantError: msgOrigin},
		{name: "origin upper", origin: "https://CHECKOUT.example.com", wantStatus: 403, wantError: msgOrigin},
		{name: "origin null", origin: "null", wantStatus: 403, wantError: msgOrigin},
		{name: "no origin", origin: omit, wantStatus: 403, wantError: msgOrigin},

		// 401 session.
		{name: "no authz", authz: omit, wantStatus: 401, wantError: msgUnauthorized},
		{name: "expired", authz: expired, wantStatus: 401, wantError: msgUnauthorized},
		{name: "future", authz: future, wantStatus: 401, wantError: msgUnauthorized},
		{name: "wrong key", authz: wrongKey, wantStatus: 401, wantError: msgUnauthorized},
		{name: "garbage authz", authz: "Basic Zm9vOmJhcg==", wantStatus: 401, wantError: msgUnauthorized},

		// 400 content type.
		{name: "text/plain", ctype: "text/plain", wantStatus: 400, wantError: msgContentType},
		{name: "missing ctype", ctype: omit, wantStatus: 400, wantError: msgContentType},
		{name: "jsonx", ctype: "application/jsonx", wantStatus: 400, wantError: msgContentType},
		{name: "ctype list", ctype: "application/json, text/plain", wantStatus: 400, wantError: msgContentType},
		{name: "ctype latin1", ctype: "application/json; charset=latin1", wantStatus: 400, wantError: msgContentType},
		{name: "ctype extra param", ctype: "application/json; foo=bar", wantStatus: 400, wantError: msgContentType},

		// 413.
		{name: "body 4097", body: padBody(goodBody, 4097), wantStatus: 413, wantError: msgTooLarge},
		{name: "body 1MiB", body: padBody(goodBody, 1<<20), wantStatus: 413, wantError: msgTooLarge},

		// 400 body shape.
		{name: "unknown field", body: tokBody(map[string]any{"name": "J SMITH"}), wantStatus: 400, wantError: msgBadBody},
		{name: "trailing object", body: goodBody + `{}`, wantStatus: 400, wantError: msgBadBody},
		{name: "trailing garbage", body: goodBody + `x`, wantStatus: 400, wantError: msgBadBody},
		{name: "not json", body: "pan=" + testPAN, wantStatus: 400, wantError: msgBadBody},
		{name: "pan number", body: `{"pan":4242424242424242,"exp_month":"12","exp_year":"2030"}`, wantStatus: 400, wantError: msgBadBody},
		{name: "cvv number", body: tokBody(map[string]any{"cvv": 9071}), wantStatus: 400, wantError: msgBadBody},
		{name: "array", body: `[]`, wantStatus: 400, wantError: msgBadBody},
		{name: "null body", body: `null`, wantStatus: 400, wantError: msgBadBody},
		{name: "string body", body: `"4242424242424242"`, wantStatus: 400, wantError: msgBadBody},
		{name: "empty body", body: " ", wantStatus: 400, wantError: msgBadBody},
		{name: "truncated", body: goodBody[:20], wantStatus: 400, wantError: msgBadBody},
		{name: "duplicate pan", body: `{"pan":"4000056655665556","pan":"4242424242424242","exp_month":"12","exp_year":"2030"}`, wantStatus: 400, wantError: msgBadBody},
		{name: "case-variant key", body: `{"PAN":"4242424242424242","exp_month":"12","exp_year":"2030"}`, wantStatus: 400, wantError: msgBadBody},
		{name: "case-variant shadow", body: `{"pan":"4000056655665556","Pan":"4242424242424242","exp_month":"12","exp_year":"2030"}`, wantStatus: 400, wantError: msgBadBody},

		// 400 pan.
		{name: "luhn fail", body: tokBody(map[string]any{"pan": "4242424242424241"}), wantStatus: 400, wantError: msgInvalidPAN},
		{name: "12 digits", body: tokBody(map[string]any{"pan": "4242 4242 4242"}), wantStatus: 400, wantError: msgInvalidPAN},
		{name: "20 digits", body: tokBody(map[string]any{"pan": "42424242424242424242"}), wantStatus: 400, wantError: msgInvalidPAN},
		{name: "letters", body: tokBody(map[string]any{"pan": "4242a42424242424"}), wantStatus: 400, wantError: msgInvalidPAN},
		{name: "dots", body: tokBody(map[string]any{"pan": "4242.4242.4242.4242"}), wantStatus: 400, wantError: msgInvalidPAN},
		{name: "missing pan", body: tokBody(map[string]any{"pan": nil}), wantStatus: 400, wantError: msgInvalidPAN},
		{name: "empty pan", body: tokBody(map[string]any{"pan": ""}), wantStatus: 400, wantError: msgInvalidPAN},

		// 400 expiry.
		{name: "past month", body: tokBody(map[string]any{"exp_month": "09", "exp_year": "2026"}), wantStatus: 400, wantError: msgInvalidExpiry},
		{name: "past year", body: tokBody(map[string]any{"exp_month": "12", "exp_year": "2025"}), wantStatus: 400, wantError: msgInvalidExpiry},
		{name: "one-digit month", body: tokBody(map[string]any{"exp_month": "1"}), wantStatus: 400, wantError: msgInvalidExpiry},
		{name: "month 13", body: tokBody(map[string]any{"exp_month": "13"}), wantStatus: 400, wantError: msgInvalidExpiry},
		{name: "month 00", body: tokBody(map[string]any{"exp_month": "00"}), wantStatus: 400, wantError: msgInvalidExpiry},
		{name: "two-digit year", body: tokBody(map[string]any{"exp_year": "30"}), wantStatus: 400, wantError: msgInvalidExpiry},
		{name: "missing month", body: tokBody(map[string]any{"exp_month": nil}), wantStatus: 400, wantError: msgInvalidExpiry},
		{name: "missing year", body: tokBody(map[string]any{"exp_year": nil}), wantStatus: 400, wantError: msgInvalidExpiry},

		// 400 cvv.
		{name: "cvv 2 digits", body: tokBody(map[string]any{"cvv": "12"}), wantStatus: 400, wantError: msgInvalidCVV},
		{name: "cvv 5 digits", body: tokBody(map[string]any{"cvv": "12345"}), wantStatus: 400, wantError: msgInvalidCVV},
		{name: "cvv letter", body: tokBody(map[string]any{"cvv": "12a"}), wantStatus: 400, wantError: msgInvalidCVV},
		{name: "cvv empty", body: tokBody(map[string]any{"cvv": ""}), wantStatus: 400, wantError: msgInvalidCVV},

		// Check order: each pair fails two checks; the earlier one wins.
		{name: "order 404>405", method: "PUT", target: "/x", wantStatus: 404, wantError: msgNotFound},
		{name: "order 405>query", method: "GET", target: "/tokenize?x=1", wantStatus: 405, wantError: msgMethod},
		{name: "order query>origin", target: "/tokenize?x=1", origin: "https://evil.example", wantStatus: 400, wantError: msgQuery},
		{name: "order origin>session", origin: "https://evil.example", authz: omit, wantStatus: 403, wantError: msgOrigin},
		{name: "order session>ctype", authz: omit, ctype: "text/plain", wantStatus: 401, wantError: msgUnauthorized},
		{name: "order ctype>size", ctype: "text/plain", body: padBody(goodBody, 4097), wantStatus: 400, wantError: msgContentType},
		{name: "order size>shape", body: padBody(goodBody, 4097) + "x", wantStatus: 413, wantError: msgTooLarge},
		{name: "order shape>pan", body: tokBody(map[string]any{"pan": "1", "name": "x"}), wantStatus: 400, wantError: msgBadBody},
		{name: "order pan>expiry", body: tokBody(map[string]any{"pan": "1", "exp_month": "13"}), wantStatus: 400, wantError: msgInvalidPAN},
		{name: "order expiry>cvv", body: tokBody(map[string]any{"exp_month": "13", "cvv": "1"}), wantStatus: 400, wantError: msgInvalidExpiry},
	}

	for _, c := range cases {
		v, s := newTestVault(t)
		rec := serveTokenize(v, tokRequest(c))
		if rec.Code != c.wantStatus {
			t.Errorf("%s: status %d, want %d (body len %d)", c.name, rec.Code, c.wantStatus, rec.Body.Len())
			continue
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s: Cache-Control %q, want no-store", c.name, cc)
		}
		if c.wantError != "" {
			want, _ := json.Marshal(map[string]string{"error": c.wantError})
			if rec.Body.String() != string(want)+"\n" {
				t.Errorf("%s: body (len %d) is not exactly the %q error body", c.name, rec.Body.Len(), c.wantError)
			}
			if len(s.rows) != 0 || len(v.cvv.m) != 0 {
				t.Errorf("%s: failed request stored %d rows, cached %d CVVs", c.name, len(s.rows), len(v.cvv.m))
			}
			continue
		}
		var resp map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp) != 4 {
			t.Errorf("%s: success body (len %d) is not a 4-field JSON object", c.name, rec.Body.Len())
			continue
		}
		if !tokenRe.MatchString(resp["token"]) || len(resp["last4"]) != 4 || resp["exp_month"] == "" || resp["exp_year"] == "" {
			t.Errorf("%s: success body has wrong field shapes", c.name)
		}
		if strings.Contains(rec.Body.String(), testPAN) || strings.Contains(rec.Body.String(), testCVV) {
			t.Errorf("%s: response body echoes the PAN or CVV", c.name)
		}
		if len(s.rows) != 1 {
			t.Errorf("%s: %d rows stored, want 1", c.name, len(s.rows))
		}
	}
}

// A preflight never needs a session and gets exactly the §5.3 headers.
func TestTokenizePreflight(t *testing.T) {
	v, _ := newTestVault(t)
	r := httptest.NewRequest("OPTIONS", "/tokenize", nil)
	r.Header.Set("Origin", testOrigin)
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Header.Set("Access-Control-Request-Headers", "content-type, authorization")
	rec := serveTokenize(v, r)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d, want 204", rec.Code)
	}
	want := map[string]string{
		"Access-Control-Allow-Origin":  testOrigin,
		"Access-Control-Allow-Methods": "POST",
		"Access-Control-Allow-Headers": "Content-Type, Authorization",
		"Access-Control-Max-Age":       "600",
		"Vary":                         "Origin",
	}
	for k, val := range want {
		if got := rec.Header().Values(k); len(got) != 1 || got[0] != val {
			t.Errorf("%s: got %q, want %q", k, got, val)
		}
	}
	for k := range rec.Header() {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected preflight header %q", k)
		}
	}
	if rec.Body.Len() != 0 {
		t.Errorf("preflight body len %d, want 0", rec.Body.Len())
	}

	for _, origin := range []string{"https://evil.example", testOrigin + "/", omit} {
		r := httptest.NewRequest("OPTIONS", "/tokenize", nil)
		if origin != omit {
			r.Header.Set("Origin", origin)
		}
		rec := serveTokenize(v, r)
		if rec.Code != http.StatusForbidden || rec.Body.String() != `{"error":"origin not allowed"}`+"\n" {
			t.Errorf("origin %q: status %d, body len %d, want 403 origin error", origin, rec.Code, rec.Body.Len())
		}
		if len(rec.Header().Values("Access-Control-Allow-Origin")) != 0 {
			t.Errorf("origin %q: Allow-Origin set on 403", origin)
		}
	}

	// Two Origin headers are ambiguous and rejected even if one matches.
	r = httptest.NewRequest("OPTIONS", "/tokenize", nil)
	r.Header.Add("Origin", testOrigin)
	r.Header.Add("Origin", "https://evil.example")
	if rec := serveTokenize(v, r); rec.Code != http.StatusForbidden {
		t.Errorf("two Origin headers: status %d, want 403", rec.Code)
	}

	// An unset allow-origin matches nothing, not even an empty Origin header.
	v.allowOrigin = ""
	r = httptest.NewRequest("OPTIONS", "/tokenize", nil)
	r.Header.Set("Origin", "")
	if rec := serveTokenize(v, r); rec.Code != http.StatusForbidden {
		t.Errorf("empty allow-origin: status %d, want 403", rec.Code)
	}
}

// Once the origin matched, every POST response (errors too) carries Allow-Origin + Vary, so the
// checkout page can read the error. Responses decided before the origin check carry neither.
func TestTokenizeCORSOnErrors(t *testing.T) {
	v, _ := newTestVault(t)
	for _, c := range []tokCase{
		{name: "success", wantStatus: 200},
		{name: "bad session", authz: "Bearer v1.1.x", wantStatus: 401},
		{name: "no session", authz: omit, wantStatus: 401},
		{name: "content type", ctype: "text/plain", wantStatus: 400},
		{name: "too large", body: padBody(goodBody, 4097), wantStatus: 413},
		{name: "bad body", body: "{", wantStatus: 400},
		{name: "invalid pan", body: tokBody(map[string]any{"pan": "4242424242424241"}), wantStatus: 400},
		{name: "invalid cvv", body: tokBody(map[string]any{"cvv": "1"}), wantStatus: 400},
	} {
		rec := serveTokenize(v, tokRequest(c))
		if rec.Code != c.wantStatus {
			t.Errorf("%s: status %d, want %d", c.name, rec.Code, c.wantStatus)
		}
		if got := rec.Header().Values("Access-Control-Allow-Origin"); len(got) != 1 || got[0] != testOrigin {
			t.Errorf("%s: Allow-Origin %q, want %q", c.name, got, testOrigin)
		}
		if got := rec.Header().Values("Vary"); len(got) != 1 || got[0] != "Origin" {
			t.Errorf("%s: Vary %q, want Origin", c.name, got)
		}
		if rec.Header().Get("Access-Control-Allow-Credentials") != "" {
			t.Errorf("%s: Allow-Credentials set", c.name)
		}
	}
	for _, c := range []tokCase{
		{name: "404", target: "/x"},
		{name: "405", method: "GET"},
		{name: "query", target: "/tokenize?x=1"},
		{name: "wrong origin", origin: "https://evil.example"},
		{name: "no origin", origin: omit},
	} {
		rec := serveTokenize(v, tokRequest(c))
		if rec.Header().Get("Access-Control-Allow-Origin") != "" || rec.Header().Get("Vary") != "" {
			t.Errorf("%s: CORS headers set before the origin matched (status %d)", c.name, rec.Code)
		}
	}
}

func TestTokenizeStoresDecryptableCard(t *testing.T) {
	v, s := newTestVault(t)
	rec := serveTokenize(v, tokRequest(tokCase{}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type %q", ct)
	}
	var resp tokenizeResponse
	dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("response body (len %d) does not decode as tokenizeResponse", rec.Body.Len())
	}
	if !tokenRe.MatchString(resp.Token) || resp.Last4 != "4242" || resp.ExpMonth != "12" || resp.ExpYear != "2030" {
		t.Fatal("response fields wrong (token shape, last4, or echoed expiry)")
	}

	row, ok := s.rows[resp.Token]
	if !ok || len(s.rows) != 1 {
		t.Fatalf("store has %d rows; response token present: %v", len(s.rows), ok)
	}
	if row.last4 != "4242" || row.keyVersion != 1 {
		t.Fatalf("row last4/keyVersion wrong (keyVersion %d)", row.keyVersion)
	}
	if bytes.Contains(row.ciphertext, []byte(testPAN)) || bytes.Contains(row.ciphertext, []byte(testCVV)) {
		t.Fatal("ciphertext contains plaintext card data")
	}
	pt, err := unseal(v.deks[1], row.ciphertext)
	if err != nil {
		t.Fatal("stored ciphertext does not unseal with DEK v1")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(pt, &fields); err != nil || len(fields) != 3 {
		t.Fatalf("plaintext is not a 3-field object (%d fields)", len(fields))
	}
	if _, has := fields["cvv"]; has {
		t.Fatal("plaintext contains a cvv key")
	}
	var c card
	if err := json.Unmarshal(pt, &c); err != nil || c != (card{PAN: testPAN, ExpMonth: "12", ExpYear: "2030"}) {
		t.Fatal("plaintext does not decode to the normalized card")
	}

	if got := v.cvv.take(resp.Token); got != testCVV {
		t.Fatalf("CVV cache returned len %d, want the request CVV", len(got))
	}

	// Without a CVV nothing is cached; with the current DEK at v2, v2 is used.
	v.deks[2] = bytes.Repeat([]byte{0x02}, 32)
	v.currentDEK = 2
	rec = serveTokenize(v, tokRequest(tokCase{body: tokBody(map[string]any{"cvv": nil})}))
	if rec.Code != http.StatusOK {
		t.Fatalf("no-cvv status %d, want 200", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal("no-cvv response does not decode")
	}
	if len(v.cvv.m) != 0 {
		t.Fatalf("no-cvv request cached %d CVVs", len(v.cvv.m))
	}
	if row := s.rows[resp.Token]; row.keyVersion != 2 {
		t.Fatalf("keyVersion %d, want current DEK 2", row.keyVersion)
	} else if _, err := unseal(v.deks[2], row.ciphertext); err != nil {
		t.Fatal("ciphertext does not unseal with DEK v2")
	}

	// The cached CVV expires on the vault clock after 15 minutes.
	clk := &fakeClock{t: testNow}
	v.now = clk.now
	rec = serveTokenize(v, tokRequest(tokCase{}))
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); rec.Code != http.StatusOK || err != nil {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	clk.advance(15 * time.Minute)
	if v.cvv.take(resp.Token) != "" {
		t.Fatal("CVV still available 15 minutes after tokenize")
	}
}

// A missing current DEK is an internal error, never a panic or a stored row.
func TestTokenizeMissingDEK(t *testing.T) {
	v, s := newTestVault(t)
	v.currentDEK = 9
	rec := serveTokenize(v, tokRequest(tokCase{}))
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != `{"error":"internal error"}`+"\n" {
		t.Fatalf("status %d, body len %d, want 500 internal error", rec.Code, rec.Body.Len())
	}
	if len(s.rows) != 0 || len(v.cvv.m) != 0 {
		t.Fatal("missing DEK stored a row or cached a CVV")
	}
}

func TestTokenizeStoreFailure(t *testing.T) {
	v, s := newTestVault(t)
	const marker = "store-failure-marker-77c1"
	s.putErr = errors.New(marker)
	start := testLog.Len()
	rec := serveTokenize(v, tokRequest(tokCase{}))
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != `{"error":"internal error"}`+"\n" {
		t.Fatalf("status %d, body len %d, want 500 internal error", rec.Code, rec.Body.Len())
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != testOrigin {
		t.Fatal("500 lacks Allow-Origin")
	}
	if len(v.cvv.m) != 0 {
		t.Fatalf("%d CVVs cached after a failed store", len(v.cvv.m))
	}
	if out := testLog.since(start); strings.Contains(out, marker) || strings.Count(out, "\n") != 1 ||
		!strings.Contains(out, " path=/tokenize status=500 ") {
		t.Fatalf("store failure log unexpected (len %d, %d lines)", len(out), strings.Count(out, "\n"))
	}
}

// Every rejected session raises the rate-limited session_token_invalid alert with its reason.
func TestTokenizeSessionAlert(t *testing.T) {
	v, _ := newTestVault(t)
	clk := &fakeClock{t: testNow}
	v.now = clk.now
	for _, c := range []struct{ authz, reason string }{
		{"Bearer " + mintSession(bytes.Repeat([]byte{0x43}, 32), testNow.Add(time.Minute)), "hmac"},
		{"Bearer " + mintSession(testHMACKey, testNow.Add(-time.Minute)), "expired"},
		{omit, "format"},
	} {
		clk.advance(time.Second)
		start := testLog.Len()
		rec := serveTokenize(v, tokRequest(tokCase{authz: c.authz}))
		out := testLog.since(start)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("reason %s: status %d, want 401", c.reason, rec.Code)
		}
		if !strings.Contains(out, "ALERT session_token_invalid reason="+c.reason+"\n") || strings.Count(out, "\n") != 2 {
			t.Errorf("reason %s: log delta unexpected (len %d, %d lines)", c.reason, len(out), strings.Count(out, "\n"))
		}
	}

	// Two Authorization headers are ambiguous: rejected as format even if one is valid.
	clk.advance(time.Second)
	r := tokRequest(tokCase{authz: omit})
	r.Header.Add("Authorization", validAuthz())
	r.Header.Add("Authorization", validAuthz())
	start := testLog.Len()
	if rec := serveTokenize(v, r); rec.Code != http.StatusUnauthorized {
		t.Errorf("two Authorization headers: status %d, want 401", rec.Code)
	}
	if !strings.Contains(testLog.since(start), "reason=format") {
		t.Error("two Authorization headers not alerted as format")
	}

	// A successful request logs only its access line.
	start = testLog.Len()
	if rec := serveTokenize(v, tokRequest(tokCase{})); rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if out := testLog.since(start); strings.Count(out, "\n") != 1 || !strings.Contains(out, " path=/tokenize status=200 ") {
		t.Fatalf("success log unexpected (len %d, %d lines)", len(out), strings.Count(out, "\n"))
	}
}

// 405 responses name the allowed methods.
func TestTokenizeAllowHeader(t *testing.T) {
	v, _ := newTestVault(t)
	rec := serveTokenize(v, tokRequest(tokCase{method: "DELETE"}))
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST, OPTIONS" {
		t.Fatalf("status %d, Allow %q", rec.Code, rec.Header().Get("Allow"))
	}
}

// Multiple Content-Type headers are ambiguous and rejected.
func TestTokenizeDuplicateContentType(t *testing.T) {
	v, _ := newTestVault(t)
	r := tokRequest(tokCase{})
	r.Header.Add("Content-Type", "application/json")
	if rec := serveTokenize(v, r); rec.Code != http.StatusBadRequest || rec.Body.String() != `{"error":"content type must be application/json"}`+"\n" {
		t.Fatalf("status %d, body len %d", rec.Code, rec.Body.Len())
	}
}

// ---------------------------------------------------------------------------
// Provider catalog, egress invariant, PAN masking, outbound client (§6.3, §6.4, §9)
// ---------------------------------------------------------------------------

// redactBody makes a provider request body printable in a failure message: the PAN (both forms)
// goes through maskPAN, then the values of card[cvc]/card[exp_month]/card[exp_year] and any
// stray test CVV are replaced, so only structure, field names and non-card values show.
func redactBody(b []byte) string {
	m, _ := maskPAN(b, testPAN)
	s := cardFieldRe.ReplaceAllString(string(m), "${1}<redacted>")
	return strings.ReplaceAll(s, testCVV, "<cvv>")
}

var cardFieldRe = regexp.MustCompile(`(card%5B(?:cvc|exp_month|exp_year)%5D=)[^&]*`)

func TestStripeBuilders(t *testing.T) {
	c := card{PAN: testPAN, ExpMonth: "12", ExpYear: "2030"}
	const form = "application/x-www-form-urlencoded"
	for _, tc := range []struct {
		name               string
		build              opBuilder
		params             map[string]string
		cvv                string
		wantPath, wantBody string
	}{
		{"create_payment_method customer+cvv", stripeCreatePaymentMethod, map[string]string{"customer": "cus_123"}, testCVV,
			"/v1/payment_methods",
			"card%5Bcvc%5D=9071&card%5Bexp_month%5D=12&card%5Bexp_year%5D=2030&card%5Bnumber%5D=4242424242424242&customer=cus_123&type=card"},
		{"create_payment_method bare", stripeCreatePaymentMethod, nil, "",
			"/v1/payment_methods",
			"card%5Bexp_month%5D=12&card%5Bexp_year%5D=2030&card%5Bnumber%5D=4242424242424242&type=card"},
		{"create_payment_method empty params map", stripeCreatePaymentMethod, map[string]string{}, "",
			"/v1/payment_methods",
			"card%5Bexp_month%5D=12&card%5Bexp_year%5D=2030&card%5Bnumber%5D=4242424242424242&type=card"},
		{"create_payment_method customer is encoded", stripeCreatePaymentMethod, map[string]string{"customer": "a&type=x"}, "",
			"/v1/payment_methods",
			"card%5Bexp_month%5D=12&card%5Bexp_year%5D=2030&card%5Bnumber%5D=4242424242424242&customer=a%26type%3Dx&type=card"},
		{"create_token cvv", stripeCreateToken, nil, testCVV,
			"/v1/tokens",
			"card%5Bcvc%5D=9071&card%5Bexp_month%5D=12&card%5Bexp_year%5D=2030&card%5Bnumber%5D=4242424242424242"},
		{"create_token bare", stripeCreateToken, map[string]string{}, "",
			"/v1/tokens",
			"card%5Bexp_month%5D=12&card%5Bexp_year%5D=2030&card%5Bnumber%5D=4242424242424242"},
	} {
		path, ct, body, err := tc.build(tc.params, c, tc.cvv)
		if err != nil {
			t.Errorf("%s: unexpected error", tc.name)
			continue
		}
		if path != tc.wantPath || ct != form {
			t.Errorf("%s: path %q content type %q", tc.name, path, ct)
		}
		if string(body) != tc.wantBody {
			t.Errorf("%s: body mismatch (card values redacted)\n got  %s\n want %s", tc.name, redactBody(body), redactBody([]byte(tc.wantBody)))
		}
	}

	// Builders fail closed on any param they do not declare, and on an empty customer.
	for _, tc := range []struct {
		name   string
		build  opBuilder
		params map[string]string
	}{
		{"create_payment_method unknown key", stripeCreatePaymentMethod, map[string]string{"amount": "1"}},
		{"create_payment_method empty customer", stripeCreatePaymentMethod, map[string]string{"customer": ""}},
		{"create_token customer", stripeCreateToken, map[string]string{"customer": "cus_123"}},
		{"create_token card override", stripeCreateToken, map[string]string{"card[number]": "4000056655665556"}},
	} {
		if _, _, body, err := tc.build(tc.params, c, testCVV); err == nil || body != nil {
			t.Errorf("%s: accepted (err nil=%v, body len %d)", tc.name, err == nil, len(body))
		}
	}
}

func TestStripeAuth(t *testing.T) {
	r := httptest.NewRequest("POST", "https://api.stripe.com/v1/tokens", nil)
	r.Header.Set("Authorization", "Bearer sk_test_attacker")
	stripeAuth(r, testSecret)
	if got := r.Header.Values("Authorization"); len(got) != 1 || got[0] != "Bearer "+testSecret {
		t.Fatalf("Authorization not exactly the vault credential (%d values)", len(got)) // never print the value
	}
}

func TestCatalogShape(t *testing.T) {
	ps := newProviders(testSecret)
	if len(ps) != 1 {
		t.Fatalf("catalog has %d providers, want 1", len(ps))
	}
	p, ok := ps["stripe"]
	if !ok {
		t.Fatal("no stripe provider")
	}
	if p.base == nil || p.base.Scheme != "https" || p.base.Host != "api.stripe.com" || p.base.User != nil ||
		p.base.Path != "" || p.base.RawQuery != "" || p.base.Fragment != "" {
		t.Fatal("stripe base is not exactly https://api.stripe.com")
	}
	if p.secret != testSecret || p.auth == nil {
		t.Fatal("stripe secret or auth not wired") // never print the secret
	}
	want := map[string]struct {
		params []string
		path   string
	}{
		"create_payment_method": {[]string{"customer"}, "/v1/payment_methods"},
		"create_token":          {nil, "/v1/tokens"},
	}
	if len(p.ops) != len(want) {
		t.Fatalf("stripe has %d ops, want %d", len(p.ops), len(want))
	}
	for name, w := range want {
		o, ok := p.ops[name]
		if !ok || o.build == nil {
			t.Errorf("op %s missing or has no builder", name)
			continue
		}
		wantParams := map[string]bool{}
		for _, k := range w.params {
			wantParams[k] = true
		}
		if !maps.Equal(o.params, wantParams) {
			t.Errorf("op %s params %v, want %v", name, o.params, wantParams)
		}
		if path, _, _, err := o.build(nil, card{PAN: testPAN, ExpMonth: "12", ExpYear: "2030"}, ""); err != nil || path != w.path {
			t.Errorf("op %s builds path %q (err nil=%v), want %q", name, path, err == nil, w.path)
		}
	}

	v, _ := newTestVault(t)
	if s, ok := v.providers["stripe"]; !ok || s.secret != testSecret || s.base.Host != "api.stripe.com" {
		t.Fatal("newTestVault does not wire newProviders(testSecret)")
	}
	if v.client != nil {
		t.Fatal("newTestVault must leave client nil; proxy tests set it per fake provider")
	}
}

// egress-hosts.txt is the file the infra repo's firewall check diffs against (§9.1); it must list
// exactly the catalog's hosts.
func TestCatalogMatchesEgressHosts(t *testing.T) {
	raw, err := os.ReadFile("egress-hosts.txt")
	if err != nil {
		t.Fatal("cannot read egress-hosts.txt")
	}
	file := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		if h := strings.TrimSpace(line); h != "" {
			file[h] = true
		}
	}
	catalog := map[string]bool{}
	for _, p := range newProviders("x") {
		catalog[p.base.Host] = true
	}
	if len(catalog) == 0 || !maps.Equal(file, catalog) {
		t.Fatalf("egress-hosts.txt %v != catalog hosts %v", slices.Sorted(maps.Keys(file)), slices.Sorted(maps.Keys(catalog)))
	}
}

func TestProviderURLInvariant(t *testing.T) {
	base, _ := url.Parse("https://api.stripe.com")
	crafted := []string{
		"/v1/tokens", "//evil.com/x", "https://evil.com/x", "/v1/../../x", "@evil.com", "/%2F%2Fevil.com",
		"/\\evil.com/x", "/v1/tokens?x=https://evil.com#frag", "/v1/tokens\r\nHost: evil.com", "/@evil.com",
		"/:443@evil.com", "///evil.com", "/v1/tokens%00", "http://evil.com", "//api.stripe.com@evil.com/",
	}
	for i, p := range crafted {
		u, err := providerURL(base, p)
		if err != nil {
			continue
		}
		if u.Scheme != "https" || u.Host != "api.stripe.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			t.Errorf("case %d: constructed URL escapes scheme/host", i)
			continue
		}
		re, err := url.Parse(u.String())
		if err != nil || re.Scheme != "https" || re.Host != "api.stripe.com" || re.User != nil || re.RawQuery != "" || re.Fragment != "" {
			t.Errorf("case %d: reparsed URL escapes scheme/host", i)
		}
	}

	u, err := providerURL(base, "/v1/tokens")
	if err != nil || u.String() != "https://api.stripe.com/v1/tokens" {
		t.Fatalf("valid path rejected or altered (err nil=%v)", err == nil)
	}
	for i, p := range []string{"", "v1/tokens", "@evil.com", "https://evil.com/x", "evil.com/x", " /v1/tokens"} {
		if _, err := providerURL(base, p); err == nil {
			t.Errorf("relative case %d accepted", i)
		}
	}

	// A base that is not plain https with a host is itself refused (fail closed).
	for i, b := range []*url.URL{nil, {Scheme: "http", Host: "api.stripe.com"}, {Scheme: "https"}} {
		if _, err := providerURL(b, "/v1/tokens"); err == nil {
			t.Errorf("bad base %d accepted", i)
		}
	}
	// A test server base keeps its port.
	tb, _ := url.Parse("https://127.0.0.1:8443")
	if u, err := providerURL(tb, "/v1/tokens"); err != nil || u.Host != "127.0.0.1:8443" {
		t.Fatal("host:port base not preserved")
	}
}

func TestMaskPAN(t *testing.T) {
	body := []byte(`{"n":"4242424242424242","f":"4242 4242 4242 4242"}`)
	got, found := maskPAN(body, testPAN)
	if !found || string(got) != `{"n":"****4242","f":"****4242"}` {
		t.Errorf("masked: found=%v, still has PAN=%v, len %d", found, bytes.Contains(got, []byte("4242424242")), len(got))
	}

	// Every occurrence; a 15-digit PAN groups in fours from the left.
	amex := "378282246310005"
	got, found = maskPAN([]byte(amex+" x "+amex+" y 3782 8224 6310 005"), amex)
	if !found || string(got) != "****0005 x ****0005 y ****0005" {
		t.Errorf("amex: found=%v, len %d", found, len(got))
	}

	clean := []byte(`{"id":"pm_123","last4":"4242","n":"4242 4242 4242"}`)
	got, found = maskPAN(clean, testPAN)
	if found || !bytes.Equal(got, clean) {
		t.Errorf("clean body changed or flagged (found=%v)", found)
	}

	// A PAN too short to be real masks nothing (and never loops on an empty needle).
	for _, pan := range []string{"", "42"} {
		if got, found := maskPAN(clean, pan); found || !bytes.Equal(got, clean) {
			t.Errorf("short pan len %d: found=%v", len(pan), found)
		}
	}
}

func TestOutboundClientConfig(t *testing.T) {
	pool := x509.NewCertPool()
	for _, roots := range []*x509.CertPool{nil, pool} {
		c := newOutboundClient(roots)
		if c.Timeout != 30*time.Second {
			t.Errorf("timeout %v", c.Timeout)
		}
		if c.CheckRedirect == nil || c.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
			t.Error("CheckRedirect does not return http.ErrUseLastResponse")
		}
		tr, ok := c.Transport.(*http.Transport)
		if !ok {
			t.Fatal("transport is not *http.Transport")
		}
		if tr.Proxy != nil {
			t.Error("transport reads a proxy")
		}
		if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 ||
			tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.RootCAs != roots {
			t.Error("TLS config wrong (min version, verification, or roots)")
		}
		if tr.MaxIdleConnsPerHost != 16 {
			t.Errorf("MaxIdleConnsPerHost %d", tr.MaxIdleConnsPerHost)
		}
	}
	if maxProviderResponse != 4<<20 {
		t.Errorf("maxProviderResponse %d", maxProviderResponse)
	}
}
