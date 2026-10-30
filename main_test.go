package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
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

// validName: 1–100 runes (not bytes), valid UTF-8, no control rune. Failure messages print
// only case indexes.
func TestValidName(t *testing.T) {
	for i, s := range []string{
		"J",
		"JANE Q DOE",
		"José Ñúñez",
		"O'Brien-Smith",
		strings.Repeat("a", 100),
		strings.Repeat("é", 100), // 100 runes, 200 bytes
		strings.Repeat("😀", 100), // 100 runes, 400 bytes
	} {
		if !validName(s) {
			t.Errorf("ok case %d rejected", i)
		}
	}
	for i, s := range []string{
		"",
		strings.Repeat("a", 101),
		strings.Repeat("é", 101),
		strings.Repeat("😀", 101),
		"a\u0007b",
		"a\x00b",
		"a\tb",
		"a\nb",
		"a\rb",
		"a\x7fb",       // DEL
		"a\u0085b",     // C1 control (NEL)
		"a\u009fb",     // C1 control
		"Jos\xff",      // invalid UTF-8
		"Jos\xc3",      // truncated multi-byte sequence
		"Jos\uFFFD",    // what encoding/json makes of invalid UTF-8
		"\xed\xa0\x80", // UTF-8-encoded surrogate
	} {
		if validName(s) {
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
	mu         sync.Mutex
	rows       map[string]fakeRow
	velocity   bool
	putErr     error  // when set, putCard returns it and stores nothing
	getErr     error  // when set (and velocity is not), getCard returns it
	lastCaller string // caller passed to the most recent getCard (the audit identity, §6.4 step 1)
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
// testHMACKey, origin testOrigin, logger → &testLog, clock fixed at testNow, providers =
// newProviders(testSecret) (client stays nil; proxyVault points it at a fake provider). The CVV cache reads
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
		{name: "name", body: tokBody(map[string]any{"name": "JANE Q DOE"}), wantStatus: 200},
		{name: "name accented", body: tokBody(map[string]any{"name": "José Ñúñez"}), wantStatus: 200},
		{name: "name escaped accents", body: `{"pan":"4242424242424242","exp_month":"12","exp_year":"2030","name":"Jos\u00e9"}`, wantStatus: 200},
		{name: "name 1 rune", body: tokBody(map[string]any{"name": "J"}), wantStatus: 200},
		{name: "name 100 runes", body: tokBody(map[string]any{"name": strings.Repeat("a", 100)}), wantStatus: 200},
		{name: "name 100 two-byte runes", body: tokBody(map[string]any{"name": strings.Repeat("é", 100)}), wantStatus: 200},
		{name: "name no cvv", body: tokBody(map[string]any{"name": "JANE Q DOE", "cvv": nil}), wantStatus: 200},

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
		{name: "unknown field", body: tokBody(map[string]any{"holder": "J SMITH"}), wantStatus: 400, wantError: msgBadBody},
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
		{name: "cvv null", body: `{"pan":"4242424242424242","exp_month":"12","exp_year":"2030","cvv":null}`, wantStatus: 400, wantError: msgInvalidCVV},
		{name: "cvv null first", body: `{"cvv":null,"pan":"4242424242424242","exp_month":"12","exp_year":"2030"}`, wantStatus: 400, wantError: msgInvalidCVV},
		{name: "cvv null spaced", body: `{"pan":"4242424242424242","exp_month":"12","exp_year":"2030","cvv" : null }`, wantStatus: 400, wantError: msgInvalidCVV},
		{name: "cvv number", body: `{"pan":"4242424242424242","exp_month":"12","exp_year":"2030","cvv":123}`, wantStatus: 400, wantError: msgBadBody},

		// 400 name.
		{name: "name empty", body: tokBody(map[string]any{"name": ""}), wantStatus: 400, wantError: msgInvalidName},
		{name: "name null", body: `{"pan":"4242424242424242","exp_month":"12","exp_year":"2030","name":null}`, wantStatus: 400, wantError: msgInvalidName},
		{name: "name null first", body: `{"name":null,"pan":"4242424242424242","exp_month":"12","exp_year":"2030"}`, wantStatus: 400, wantError: msgInvalidName},
		{name: "name null spaced", body: `{"pan":"4242424242424242","exp_month":"12","exp_year":"2030","name" : null }`, wantStatus: 400, wantError: msgInvalidName},
		{name: "name 101 runes", body: tokBody(map[string]any{"name": strings.Repeat("a", 101)}), wantStatus: 400, wantError: msgInvalidName},
		{name: "name 101 two-byte runes", body: tokBody(map[string]any{"name": strings.Repeat("é", 101)}), wantStatus: 400, wantError: msgInvalidName},
		{name: "name bell", body: `{"pan":"4242424242424242","exp_month":"12","exp_year":"2030","name":"a\u0007b"}`, wantStatus: 400, wantError: msgInvalidName},
		{name: "name newline", body: tokBody(map[string]any{"name": "JANE\nDOE"}), wantStatus: 400, wantError: msgInvalidName},
		{name: "name C1 control", body: tokBody(map[string]any{"name": "JANE\u0085DOE"}), wantStatus: 400, wantError: msgInvalidName},
		{name: "name raw invalid utf-8", body: "{\"pan\":\"4242424242424242\",\"exp_month\":\"12\",\"exp_year\":\"2030\",\"name\":\"Jos\xff\"}", wantStatus: 400, wantError: msgInvalidName},
		{name: "name number", body: `{"pan":"4242424242424242","exp_month":"12","exp_year":"2030","name":1}`, wantStatus: 400, wantError: msgBadBody},
		{name: "name object", body: tokBody(map[string]any{"name": map[string]any{}}), wantStatus: 400, wantError: msgBadBody},
		{name: "duplicate name", body: `{"pan":"4242424242424242","exp_month":"12","exp_year":"2030","name":"","name":"JANE"}`, wantStatus: 400, wantError: msgBadBody},
		{name: "case-variant name", body: `{"pan":"4242424242424242","exp_month":"12","exp_year":"2030","Name":"JANE"}`, wantStatus: 400, wantError: msgBadBody},

		// Check order: each pair fails two checks; the earlier one wins.
		{name: "order 404>405", method: "PUT", target: "/x", wantStatus: 404, wantError: msgNotFound},
		{name: "order 405>query", method: "GET", target: "/tokenize?x=1", wantStatus: 405, wantError: msgMethod},
		{name: "order query>origin", target: "/tokenize?x=1", origin: "https://evil.example", wantStatus: 400, wantError: msgQuery},
		{name: "order origin>session", origin: "https://evil.example", authz: omit, wantStatus: 403, wantError: msgOrigin},
		{name: "order session>ctype", authz: omit, ctype: "text/plain", wantStatus: 401, wantError: msgUnauthorized},
		{name: "order ctype>size", ctype: "text/plain", body: padBody(goodBody, 4097), wantStatus: 400, wantError: msgContentType},
		{name: "order size>shape", body: padBody(goodBody, 4097) + "x", wantStatus: 413, wantError: msgTooLarge},
		{name: "order shape>pan", body: tokBody(map[string]any{"pan": "1", "holder": "x"}), wantStatus: 400, wantError: msgBadBody},
		{name: "order pan>expiry", body: tokBody(map[string]any{"pan": "1", "exp_month": "13"}), wantStatus: 400, wantError: msgInvalidPAN},
		{name: "order expiry>cvv", body: tokBody(map[string]any{"exp_month": "13", "cvv": "1"}), wantStatus: 400, wantError: msgInvalidExpiry},
		{name: "order expiry>cvv null", body: `{"pan":"4242424242424242","exp_month":"13","exp_year":"2030","cvv":null}`, wantStatus: 400, wantError: msgInvalidExpiry},
		{name: "order cvv>name", body: tokBody(map[string]any{"cvv": "1", "name": ""}), wantStatus: 400, wantError: msgInvalidCVV},
		{name: "order cvv null>name null", body: `{"pan":"4242424242424242","exp_month":"12","exp_year":"2030","cvv":null,"name":null}`, wantStatus: 400, wantError: msgInvalidCVV},
		{name: "order expiry>name", body: tokBody(map[string]any{"exp_month": "13", "name": ""}), wantStatus: 400, wantError: msgInvalidExpiry},
		{name: "order pan>name", body: tokBody(map[string]any{"pan": "1", "name": ""}), wantStatus: 400, wantError: msgInvalidPAN},
		{name: "order shape>name", body: tokBody(map[string]any{"name": "", "holder": "x"}), wantStatus: 400, wantError: msgBadBody},
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

// An optional name is sealed with the card (D§5.8): the plaintext gains a "name" key only when
// one was sent, and the response never echoes it. Failure messages never print the name.
func TestTokenizeStoresName(t *testing.T) {
	const name = "JANE Q DOE"
	v, s := newTestVault(t)
	rec := serveTokenize(v, tokRequest(tokCase{body: tokBody(map[string]any{"name": name})}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), name) {
		t.Fatal("response body echoes the name")
	}
	var resp tokenizeResponse
	dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("response body (len %d) does not decode as tokenizeResponse", rec.Body.Len())
	}
	row, ok := s.rows[resp.Token]
	if !ok {
		t.Fatal("no row stored for the response token")
	}
	if bytes.Contains(row.ciphertext, []byte(name)) {
		t.Fatal("ciphertext contains the plaintext name")
	}
	pt, err := unseal(v.deks[row.keyVersion], row.ciphertext)
	if err != nil {
		t.Fatal("stored ciphertext does not unseal")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(pt, &fields); err != nil || len(fields) != 4 {
		t.Fatalf("plaintext is not a 4-field object (%d fields)", len(fields))
	}
	var c card
	if err := json.Unmarshal(pt, &c); err != nil || c != (card{PAN: testPAN, ExpMonth: "12", ExpYear: "2030", Name: name}) {
		t.Fatal("plaintext does not decode to the normalized card with the name")
	}
	zero(pt)

	// Without a name the plaintext has no "name" key at all.
	rec = serveTokenize(v, tokRequest(tokCase{}))
	if rec.Code != http.StatusOK {
		t.Fatalf("no-name status %d, want 200", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal("no-name response does not decode")
	}
	pt, err = unseal(v.deks[s.rows[resp.Token].keyVersion], s.rows[resp.Token].ciphertext)
	if err != nil {
		t.Fatal("no-name ciphertext does not unseal")
	}
	fields = nil
	if err := json.Unmarshal(pt, &fields); err != nil || len(fields) != 3 {
		t.Fatalf("no-name plaintext is not a 3-field object (%d fields)", len(fields))
	}
	if _, has := fields["name"]; has {
		t.Fatal("no-name plaintext contains a name key")
	}
	zero(pt)

	// A row sealed before names existed decodes with an empty Name.
	old := []byte(`{"pan":"4242424242424242","exp_month":"12","exp_year":"2030"}`)
	var oc card
	if err := json.Unmarshal(old, &oc); err != nil || oc != (card{PAN: testPAN, ExpMonth: "12", ExpYear: "2030"}) {
		t.Fatal("pre-name plaintext does not decode to a card without a name")
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

	// The hyphen-grouped form is masked too (same left-to-right grouping in fours).
	got, found = maskPAN([]byte(`{"f":"4242-4242-4242-4242","a":"3782-8224-6310-005"}`), testPAN)
	if !found || string(got) != `{"f":"****4242","a":"3782-8224-6310-005"}` {
		t.Errorf("hyphen form: found=%v, still has PAN=%v, len %d", found, bytes.Contains(got, []byte("4242-4242")), len(got))
	}
	got, found = maskPAN([]byte("x 3782-8224-6310-005 y"), amex)
	if !found || string(got) != "x ****0005 y" {
		t.Errorf("amex hyphen form: found=%v, len %d", found, len(got))
	}

	// Residue: PAN+PAN[4:] (last 4 == first 4) leaves a full PAN after one ReplaceAll pass
	// ("****4242"+"424242424242"); the replacement repeats until no form remains.
	for i, in := range []string{
		testPAN + testPAN[4:],
		testPAN + testPAN[4:] + testPAN[4:],
		"4242 4242 4242 4242 4242 4242 4242",
		"4242-4242-4242-4242-4242-4242-4242",
	} {
		got, found := maskPAN([]byte(in), testPAN)
		if !found || len(luhnWindowOffsets(joinDigitSeparators(string(got)))) != 0 || bytes.Contains(got, []byte(testPAN)) {
			t.Errorf("residue case %d: found=%v, a PAN remains (len %d)", i, found, len(got))
		}
	}
	if got, _ := maskPAN([]byte(testPAN+testPAN[4:]), testPAN); string(got) != "********4242" {
		t.Errorf("residue: masked to len %d, want ********4242", len(got))
	}

	// A PAN too short to be real masks nothing (never loops on an empty needle, or on a needle the
	// mask itself contains).
	for _, pan := range []string{"", "42", "4242", "424242424242"} {
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

// ---------------------------------------------------------------------------
// Placeholders and strict body scanners (D§5.3, D§5.4)
// ---------------------------------------------------------------------------

func TestParsePlaceholder(t *testing.T) {
	cases := []struct {
		s              string
		card, number   bool
		kind, mod, arg string
	}{
		{"{{pan}}", true, false, "pan", "", ""},
		{"{{cvv}}", true, false, "cvv", "", ""},
		{"{{name}}", true, false, "name", "", ""},
		{"{{exp_month}}", true, false, "exp_month", "", ""},
		{"{{exp_month:int}}", true, true, "exp_month", "int", ""},
		{"{{exp_year}}", true, false, "exp_year", "", ""},
		{"{{exp_year:yy}}", true, false, "exp_year", "yy", ""},
		{"{{exp_year:int}}", true, true, "exp_year", "int", ""},
		{"{{exp:yyyy/mm}}", true, false, "exp", "yyyy/mm", ""},
		{"{{exp:mm/yy}}", true, false, "exp", "mm/yy", ""},
		{"{{secret:secretKey}}", false, false, "secret", "", "secretKey"},
		{"{{secret:A_9}}", false, false, "secret", "", "A_9"},
		{"{{secret:" + strings.Repeat("a", 64) + "}}", false, false, "secret", "", strings.Repeat("a", 64)},
		{"{{basic:apiKey}}", false, false, "basic", "", "apiKey"},
		{"{{signature}}", false, false, "signature", "", ""},
	}
	for _, c := range cases {
		p, ok := parsePlaceholder(c.s)
		if !ok {
			t.Errorf("%s rejected", c.s)
			continue
		}
		if p.kind != c.kind || p.mod != c.mod || p.arg != c.arg {
			t.Errorf("%s parsed as %+v", c.s, p)
		}
		if p.String() != c.s {
			t.Errorf("%s round-trips to %s", c.s, p.String())
		}
		if p.isCard() != c.card || p.isNumber() != c.number {
			t.Errorf("%s: isCard=%v isNumber=%v", c.s, p.isCard(), p.isNumber())
		}
	}
	for _, s := range []string{
		"{{ pan }}", "{{pan:int}}", "{{exp_year:yyyy}}", "{{secret:}}", "{{secret:a b}}", "{{foo}}", "{pan}",
		"", "{{}}", "{{pan}", "{pan}}", "{{{pan}}}", "{{PAN}}", "{{pan}} ", " {{pan}}", "{{pan:}}",
		"{{cvv:int}}", "{{name:x}}", "{{signature:x}}", "{{exp}}", "{{exp:}}", "{{exp:yy/mm}}",
		"{{exp_month:}}", "{{exp_month:yy}}", "{{exp_year:}}", "{{secret}}", "{{basic}}", "{{basic:}}",
		"{{secret:" + strings.Repeat("a", 65) + "}}", "{{secret:a-b}}", "{{secret:a:b}}", "{{secret:a/b}}",
		"{{secret:é}}", "{{pan}}{{cvv}}", "{{exp_month:int:int}}",
	} {
		if p, ok := parsePlaceholder(s); ok {
			t.Errorf("%q accepted as %+v", s, p)
		}
	}
}

// checkOccurrences checks that occs are exactly want (addr → placeholder text), in body order, and that each
// span slices back to the raw value text (rawQuoted adds the JSON quotes).
func checkOccurrences(t *testing.T, body string, occs []occurrence, want [][2]string, rawQuoted bool) {
	t.Helper()
	if len(occs) != len(want) {
		t.Fatalf("got %d occurrences, want %d", len(occs), len(want))
	}
	for i, o := range occs {
		if o.addr != want[i][0] || o.ph.String() != want[i][1] {
			t.Errorf("occurrence %d: %s %s, want %s %s", i, o.addr, o.ph, want[i][0], want[i][1])
		}
		raw := want[i][1]
		if rawQuoted {
			raw = `"` + raw + `"`
		}
		if o.start < 0 || o.end > len(body) || o.start >= o.end || body[o.start:o.end] != raw {
			t.Errorf("occurrence %d: span [%d,%d) does not slice back to %s", i, o.start, o.end, raw)
		}
		if i > 0 && occs[i-1].end > o.start {
			t.Errorf("occurrence %d not after occurrence %d", i, i-1)
		}
	}
}

func TestScanJSON(t *testing.T) {
	body := `{"a":{"n":"{{pan}}","m":"{{exp_month:int}}"},"x/y":"{{cvv}}","arr":[{"k":"{{name}}"}]}`
	occs, err := scanBody("json", []byte(body))
	if err != nil {
		t.Fatalf("scanBody: %v", err)
	}
	checkOccurrences(t, body, occs, [][2]string{
		{"/a/n", "{{pan}}"}, {"/a/m", "{{exp_month:int}}"}, {"/x~1y", "{{cvv}}"}, {"/arr/0/k", "{{name}}"},
	}, true)

	// Whitespace everywhere, escapes and multi-byte UTF-8 in the strings before each placeholder, and
	// keys needing "~0"/"~1" escaping and decoded escapes, all keep the spans exact.
	body = " {\n\t\"d\\\"esc\" : \"caf\u00e9 \\u00e9 \\\"q\\\" \\\\ \\n \\ud83d\\ude00 \U0001F600\" ,\r\n" +
		"  \"~a/b\"  :  \"{{secret:k_1}}\" , \"\\u0061rr\" : [ 1 , 2.50 , true , null , { } , [ ] ,\n" +
		"  \"{{exp:mm/yy}}\" , [ \"{{signature}}\" ] ] , \"\" : \"{{basic:B}}\" } \n"
	occs, err = scanBody("json", []byte(body))
	if err != nil {
		t.Fatalf("scanBody (whitespace/escapes): %v", err)
	}
	checkOccurrences(t, body, occs, [][2]string{
		{"/~0a~1b", "{{secret:k_1}}"}, {"/arr/6", "{{exp:mm/yy}}"}, {"/arr/7/0", "{{signature}}"}, {"/", "{{basic:B}}"},
	}, true)

	// A body with no placeholders has no occurrences; a top-level placeholder has the root address.
	if occs, err := scanBody("json", []byte(`{"a":"b","c":[1,{"d":"{x}"}]}`)); err != nil || len(occs) != 0 {
		t.Errorf("no placeholders: %d occurrences, err %v", len(occs), err)
	}
	occs, err = scanBody("json", []byte(` "{{pan}}" `))
	if err != nil {
		t.Fatalf("top-level placeholder: %v", err)
	}
	checkOccurrences(t, ` "{{pan}}" `, occs, [][2]string{{"", "{{pan}}"}}, true)

	if _, err := scanBody("xml", []byte(`<a/>`)); !errors.Is(err, errBody) {
		t.Errorf("unknown format: %v", err)
	}
}

// TestJSONSpans checks every string token's span (not just placeholders) against the decoded value,
// by slicing the raw text and unmarshalling it.
func TestJSONSpans(t *testing.T) {
	body := "{\"k\\u00e9y\":[\"a\\\"b\",\"\\ud83d\\ude00\",\"\u65e5\u672c\",{\"x\" :\"\\/\\b\\f\\n\\r\\t\"}], \"n\":-1.5e+3}"
	nodes, err := jsonWalk([]byte(body))
	if err != nil {
		t.Fatalf("jsonWalk: %v", err)
	}
	strs := 0
	for _, n := range nodes {
		raw := body[n.start:n.end]
		switch n.kind {
		case "string", "key":
			strs++
			var s string
			if err := json.Unmarshal([]byte(raw), &s); err != nil || s != n.text {
				t.Errorf("%s %s: span %q does not decode to the token", n.kind, n.ptr, raw)
			}
		case "number", "object", "array":
			if raw != n.text {
				t.Errorf("%s %s: span %q, text %q", n.kind, n.ptr, raw, n.text)
			}
		}
	}
	if strs != 7 {
		t.Errorf("%d string/key nodes, want 7", strs)
	}
}

func TestScanForm(t *testing.T) {
	body := "card[number]={{pan}}&type=card"
	occs, err := scanBody("form", []byte(body))
	if err != nil {
		t.Fatalf("scanBody: %v", err)
	}
	checkOccurrences(t, body, occs, [][2]string{{"card[number]", "{{pan}}"}}, false)

	body = "a%5Bb%5D=x+y%26&card[exp_month]={{exp_month:int}}&expand[]=a&expand[]=b&e=&card[cvc]={{cvv}}"
	occs, err = scanBody("form", []byte(body))
	if err != nil {
		t.Fatalf("scanBody: %v", err)
	}
	checkOccurrences(t, body, occs, [][2]string{{"card[exp_month]", "{{exp_month:int}}"}, {"card[cvc]", "{{cvv}}"}}, false)

	// An empty form body is zero fields.
	if occs, err := scanBody("form", nil); err != nil || len(occs) != 0 {
		t.Errorf("empty form: %d occurrences, err %v", len(occs), err)
	}
	// Malformed forms.
	for _, b := range []string{
		"&", "a=1&", "&a=1", "a=1&&b=2", "a", "a=1&b", "=1", "a=%zz", "%zz=1", "a=%", "a=1;b=2", "a=1 2",
		"a=\x00", "a=caf\xc3\xa9", "a=%ff", "a=%c3", "a=\x7f",
	} {
		if _, err := scanBody("form", []byte(b)); !errors.Is(err, errBody) {
			t.Errorf("form %q: %v", b, err)
		}
	}
}

func TestScanRejectsDisguisedPlaceholders(t *testing.T) {
	for _, b := range []string{
		// Escape-disguised: the decoded text is a placeholder but the raw bytes are not.
		`{"n":"\u007b\u007bpan}}"}`,
		`{"n":"\u007B\u007Bpan\u007D\u007D"}`,
		`{"n":"{\u007bpan}}"}`,
		`{"n":"{{p\u0061n}}"}`,
		`{"n":"{{pan\u007d\u007d"}`,
		`{"n":"{{pan}\u007d"}`,
		`"\u007b\u007bpan}}"`,
		// Placeholders in keys.
		`{"{{pan}}":1}`,
		`{"a":{"x{{cvv}}y":"v"}}`,
		`{"\u007b\u007bpan}}":1}`,
		// Partial, concatenated, or not in the vocabulary.
		`{"n":"x{{pan}}"}`,
		`{"n":"{{pan}}x"}`,
		`{"n":" {{pan}}"}`,
		`{"n":"{{pan}}{{cvv}}"}`,
		`{"n":"{{exp_month}}/{{exp_year}}"}`,
		`{"n":"{{foo}}"}`,
		`{"n":"{{ pan }}"}`,
		`{"n":"{{pan"}`,
		`{"n":"{{"}`,
		`{"n":["ok","{{pan:int}}"]}`,
	} {
		if _, err := scanBody("json", []byte(b)); !errors.Is(err, errPlaceholder) {
			t.Errorf("json %s: %v", b, err)
		}
	}
	for _, b := range []string{
		"n=%7B%7Bpan%7D%7D",
		"n=%7b%7bpan%7d%7d",
		"n={%7Bpan}}",
		"n={{p%61n}}",
		"{{pan}}=1",
		"%7B%7Bpan%7D%7D=1",
		"a[{{cvv}}]=1",
		"n=x{{pan}}",
		"n={{pan}}{{cvv}}",
		"n={{foo}}",
		"n={{+pan+}}",
		"n={{",
		"expand[]={{pan}}",
		"{{pan}}[]=x",
	} {
		if _, err := scanBody("form", []byte(b)); !errors.Is(err, errPlaceholder) {
			t.Errorf("form %s: %v", b, err)
		}
	}
}

func TestJSONStrict(t *testing.T) {
	for _, b := range []string{
		`{"a":1}`, `[]`, `"x"`, `1`, `true`, `null`, " {\"a\":[1,{\"a\":2}],\"b\":{\"a\":3}} \n",
		`{"a":{"b":1},"c":{"b":1}}`, `{"é":1,"e":2}`, `{"a":"\ufffe"}`, `{"a\u007f ":"\u0000\n"}`,
	} {
		if err := jsonStrict([]byte(b)); err != nil {
			t.Errorf("%s rejected: %v", b, err)
		}
	}
	deep := strings.Repeat("[", maxJSONDepth) + strings.Repeat("]", maxJSONDepth)
	if err := jsonStrict([]byte(deep)); err != nil {
		t.Errorf("depth %d rejected: %v", maxJSONDepth, err)
	}
	for _, b := range []string{
		// Duplicate keys: top level, nested, inside an array, after decoding escapes, container values.
		`{"a":1,"a":2}`, `{"x":{"a":1,"b":2,"a":3}}`, `[{"a":1},{"b":1,"b":1}]`, `{"a":1,"\u0061":2}`,
		`{"a":{},"a":[]}`,
		// Trailing data.
		`{}{}`, `{} {}`, `{}x`, `1 2`, `"a""b"`, `{}]`,
		// Invalid UTF-8, and a BOM.
		"{\"a\":\"\xff\"}", "{\"\xc3\":1}", "\xef\xbb\xbf{}",
		// Empty.
		``, ` `, "\n",
		// Malformed.
		`{`, `{"a"}`, `{"a":}`, `{"a" 1}`, `[1,]`, `{"a":1,}`, `[,1]`, `{'a':1}`, `[01]`, `NaN`, `"\x"`,
		// Control characters in keys (a NUL-truncating parser would alias them).
		`{"merchantAccount\u0000":"x"}`, `{"merchantAccount":"a","merchantAccount\u0000":"b"}`,
		`{"a\n":1}`, `{"x":{"\u001f":1}}`, `{"\u0000":1}`, `{"a\tb":1}`,
		// Replacement character and lone surrogates.
		`"\ud800"`, `{"\udc00":1}`, `"\ufffd"`, "\"\xef\xbf\xbd\"",
		// Too deep.
		strings.Repeat("[", maxJSONDepth+1) + strings.Repeat("]", maxJSONDepth+1),
		strings.Repeat(`{"a":`, maxJSONDepth+1) + "1" + strings.Repeat("}", maxJSONDepth+1),
	} {
		if err := jsonStrict([]byte(b)); !errors.Is(err, errBody) {
			t.Errorf("%q: %v", b, err)
		}
	}
	// Strictness failures win over placeholder failures, and scanBody applies them too.
	if _, err := scanBody("json", []byte(`{"{{pan}}":1,"{{pan}}":2}`)); !errors.Is(err, errBody) {
		t.Errorf("duplicate placeholder keys: %v", err)
	}
	if _, err := scanBody("json", []byte(`{"n":"{{pan}}"} {}`)); !errors.Is(err, errBody) {
		t.Errorf("trailing data: %v", err)
	}
}

func TestScanFormDuplicates(t *testing.T) {
	for _, b := range []string{
		"a=1&a=2", "a=1&a=1", "card[number]={{pan}}&card[number]=4242", "a=1&%61=2",
		"card%5Bnumber%5D=1&card[number]=2",
		// Aliases a bracket parser would merge with an earlier key are not canonical.
		"customer]=x&customer=y", "customer=y&[customer=x", "a=1&a%00=2",
	} {
		if _, err := scanBody("form", []byte(b)); !errors.Is(err, errBody) {
			t.Errorf("%s: %v", b, err)
		}
	}
	for _, b := range []string{"expand[]=a&expand[]=b", "expand[]=a&expand[]=a&x=1"} {
		if _, err := scanBody("form", []byte(b)); err != nil {
			t.Errorf("%s rejected: %v", b, err)
		}
	}
}

// TestScanFormKeys: form keys must be canonical (a name, [segment] groups, an optional final "[]"),
// so a provider's bracket parsing cannot alias one key onto another.
func TestScanFormKeys(t *testing.T) {
	for _, k := range []string{
		"card[number]", "payment_method_data[card][exp_month]", "expand[]", "metadata[order_id]",
		"type", "items[0][price]", "x-y", "A_9", "a[b-c][]",
	} {
		if _, err := scanBody("form", []byte(url.QueryEscape(k)+"=1")); err != nil {
			t.Errorf("escaped key %s rejected: %v", k, err)
		}
		if _, err := scanBody("form", []byte(k+"=1")); err != nil {
			t.Errorf("raw key %s rejected: %v", k, err)
		}
	}
	for _, k := range []string{
		"customer]", "[customer", "a[b]c", "a[[b]]", "a%00", "]]customer]]", "card[number]]", "a[]b",
		"a[][b]", "a[", "a]", "[]", "a[b", "a.b", "a+b", "a%20b", "a%0A", "a%7F", "caf%C3%A9", "a%5B%5Db",
		"a[b%00]",
	} {
		if _, err := scanBody("form", []byte(k+"=1")); !errors.Is(err, errBody) {
			t.Errorf("key %s: %v", k, err)
		}
		if _, _, err := readField("form", []byte(k+"=1"), "a"); !errors.Is(err, errBody) {
			t.Errorf("readField key %s: %v", k, err)
		}
	}
	// A key containing "{{" is still errPlaceholder, but a strictness failure anywhere wins.
	if _, err := scanBody("form", []byte("{{pan}}=1&a=2")); !errors.Is(err, errPlaceholder) {
		t.Errorf("placeholder key: %v", err)
	}
	if _, err := scanBody("form", []byte("{{pan}}=1&customer]=2")); !errors.Is(err, errBody) {
		t.Errorf("placeholder key then bad key: %v", err)
	}
}

func TestReadField(t *testing.T) {
	body := []byte(`{"s":"a\"b","amt":{"value":65000,"tax":3.50},"ok":true,"no":false,"z":null,` +
		`"o":{"k":[1, 2]},"a/b":["x"],"e":""}`)
	for addr, want := range map[string]fieldValue{
		"/s":         {"string", `a"b`},
		"/amt/value": {"number", "65000"},
		"/amt/tax":   {"number", "3.50"},
		"/ok":        {"bool", "true"},
		"/no":        {"bool", "false"},
		"/z":         {"null", "null"},
		"/o":         {"object", `{"k":[1, 2]}`},
		"/o/k":       {"array", "[1, 2]"},
		"/o/k/1":     {"number", "2"},
		"/a~1b/0":    {"string", "x"},
		"/e":         {"string", ""},
		"":           {"object", string(body)},
	} {
		got, ok, err := readField("json", body, addr)
		if err != nil || !ok || got != want {
			t.Errorf("json %q: %+v ok=%v err=%v, want %+v", addr, got, ok, err, want)
		}
	}
	for _, addr := range []string{"/missing", "/amt/missing", "/o/k/2", "/a/b/0", "/s/0", "s", "/amt/value/x"} {
		if _, ok, err := readField("json", body, addr); ok || err != nil {
			t.Errorf("json %q: ok=%v err=%v", addr, ok, err)
		}
	}
	if _, _, err := readField("json", []byte(`{"a":1,"a":2}`), "/a"); !errors.Is(err, errBody) {
		t.Errorf("json duplicate: %v", err)
	}

	form := []byte("referenceCode=ord+1%2F2&amount=65000&e=&card[number]={{pan}}&x[]=1&x[]=2&y[]=3")
	for addr, want := range map[string]fieldValue{
		"referenceCode": {"string", "ord 1/2"},
		"amount":        {"string", "65000"},
		"e":             {"string", ""},
		"card[number]":  {"string", "{{pan}}"},
		"y[]":           {"string", "3"},
	} {
		got, ok, err := readField("form", form, addr)
		if err != nil || !ok || got != want {
			t.Errorf("form %q: %+v ok=%v err=%v, want %+v", addr, got, ok, err, want)
		}
	}
	if _, ok, err := readField("form", form, "missing"); ok || err != nil {
		t.Errorf("form missing: ok=%v err=%v", ok, err)
	}
	if _, _, err := readField("form", form, "x[]"); !errors.Is(err, errBody) {
		t.Errorf("form repeated [] key: %v", err)
	}
	if _, _, err := readField("form", []byte("a=1&a=2"), "a"); !errors.Is(err, errBody) {
		t.Errorf("form duplicate: %v", err)
	}
	if _, _, err := readField("xml", form, "a"); !errors.Is(err, errBody) {
		t.Errorf("unknown format: %v", err)
	}
}

func TestEncodeValue(t *testing.T) {
	for _, c := range []struct {
		format, v string
		number    bool
		want      string
	}{
		{"json", "4242", false, `"4242"`},
		{"json", `Jo "Q" \ é`, false, `"Jo \"Q\" \\ é"`},
		{"json", "3", true, "3"},
		{"json", "03", true, "3"},
		{"json", "2030", true, "2030"},
		{"json", "0", true, "0"},
		{"json", "", true, `""`},
		{"json", "3a", true, `"3a"`},
		{"json", "-3", true, `"-3"`},
		{"form", "Jo Q&a=b", false, "Jo+Q%26a%3Db"},
		{"form", "03", true, "3"},
		{"form", "x y", true, "x+y"},
	} {
		if got := string(encodeValue(c.format, c.v, c.number)); got != c.want {
			t.Errorf("encodeValue(%s, %q, %v) = %s, want %s", c.format, c.v, c.number, got, c.want)
		}
	}
}

func TestSubstitute(t *testing.T) {
	body := `{"card":{"number":"{{pan}}","exp_month":"{{exp_month:int}}","name":"{{name}}"},"amount":100}`
	occs, err := scanBody("json", []byte(body))
	if err != nil {
		t.Fatalf("scanBody: %v", err)
	}
	repl := [][]byte{encodeValue("json", "4242", false), encodeValue("json", "03", true), encodeValue("json", `A "B"`, false)}
	got := substitute([]byte(body), occs, repl)
	want := `{"card":{"number":"4242","exp_month":3,"name":"A \"B\""},"amount":100}`
	if string(got) != want {
		t.Errorf("json substitute: %s", got)
	}
	if err := jsonStrict(got); err != nil {
		t.Errorf("substituted body is not strict JSON: %v", err)
	}

	form := "type=card&card[number]={{pan}}&card[exp_year]={{exp_year:int}}&x=%7Bok"
	occs, err = scanBody("form", []byte(form))
	if err != nil {
		t.Fatalf("scanBody: %v", err)
	}
	got = substitute([]byte(form), occs, [][]byte{encodeValue("form", "4242", false), encodeValue("form", "2030", true)})
	if string(got) != "type=card&card[number]=4242&card[exp_year]=2030&x=%7Bok" {
		t.Errorf("form substitute: %s", got)
	}

	// No occurrences: the body is returned unchanged (as a copy).
	in := []byte(`{"a":1}`)
	got = substitute(in, nil, nil)
	if string(got) != `{"a":1}` {
		t.Errorf("no occurrences: %s", got)
	}

	// Mismatched or out-of-order spans are a programming error and panic.
	for i, c := range []struct {
		occs []occurrence
		repl [][]byte
	}{
		{[]occurrence{{start: 0, end: 1}}, nil},
		{[]occurrence{{start: 2, end: 4}, {start: 3, end: 5}}, [][]byte{nil, nil}},
		{[]occurrence{{start: 3, end: 2}}, [][]byte{nil}},
		{[]occurrence{{start: 0, end: 99}}, [][]byte{nil}},
		{[]occurrence{{start: -1, end: 1}}, [][]byte{nil}},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("case %d did not panic", i)
				}
			}()
			substitute(in, c.occs, c.repl)
		}()
	}
}

// ---------------------------------------------------------------------------
// Provider catalog: catalog.json (D§5.1, D§5.5-5.7, D§5.10)
// ---------------------------------------------------------------------------

// testCatalogHost is the host of every testCatalogJSON account. testCatalog replaces it (quoted, so
// only host values change) with the host under test, e.g. an httptest server's 127.0.0.1:port. A
// test that needs different hosts per account sets c.accounts[name].host after parsing.
const testCatalogHost = "upstream.test"

// testCatalogJSON is the synthetic catalog the proxy tests run against. It models Stripe (form) and
// the four first-wave json shapes of D§6: Adyen (account pin, forbid list, X-API-Key header),
// Mercado Pago (single-use card token, :int expiry, Bearer), PayU (body credential, account and
// literal pins, payu signer, yyyy/mm expiry) and Pagar.me (Basic auth, array positions). Every
// provider has a dev account; adyen_br_live is the one prod account. Endpoint and account entries
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
          "id": "get_payment_intent", "method": "GET", "path": "/v1/payment_intents/{id}", "query": ["expand[]"],
          "headers": {"Authorization": "Bearer {{secret:secretKey}}"}
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

func TestParseCatalogValid(t *testing.T) {
	c := testCatalog(t, "127.0.0.1:9")
	if got := slices.Sorted(maps.Keys(c.accounts)); !slices.Equal(got, []string{"adyen_br", "mp_ar", "pagarme_br", "payu_co", "stripe_t"}) {
		t.Errorf("dev accounts = %v", got)
	}
	if got := slices.Sorted(maps.Keys(c.providers)); !slices.Equal(got, []string{"adyen", "mercadopago", "pagarme", "payu", "stripe"}) {
		t.Errorf("providers = %v", got)
	}
	prod, err := parseCatalog([]byte(testCatalogJSON), "prod")
	if err != nil {
		t.Fatalf("prod: %v", err)
	}
	if got := slices.Sorted(maps.Keys(prod.accounts)); !slices.Equal(got, []string{"adyen_br_live"}) {
		t.Errorf("prod accounts = %v", got)
	}
	if len(prod.providers) != 5 {
		t.Errorf("prod has %d providers, want all 5", len(prod.providers))
	}

	a := c.accounts["adyen_br"]
	if a.name != "adyen_br" || a.provider != "adyen" || a.env != "dev" || a.host != "127.0.0.1:9" || a.basePath != "/checkout" ||
		a.secretNames["apiKey"] != "projects/pci-cde-dev/secrets/adyen-br-key" || a.values["merchantAccount"] != "AcmeBR_ECOM" ||
		a.secrets == nil || len(a.secrets) != 0 {
		t.Errorf("adyen_br decoded as %+v", *a)
	}
	if s := c.accounts["stripe_t"]; s.basePath != "" || len(s.values) != 0 {
		t.Errorf("stripe_t decoded as %+v", *s)
	}

	// Stripe: form positions, forbid lists ("must be absent"), wildcard path and query keys.
	pi := catEndpointByID(t, c, "stripe", "payment_intents")
	if c.providers["stripe"].format != "form" || pi.method != "POST" || !slices.Equal(pi.path, []string{"v1", "payment_intents"}) || !pi.cardData ||
		pi.headers["Authorization"] != "Bearer {{secret:secretKey}}" || len(pi.headers) != 1 ||
		pi.positions["payment_method_data[card][number]"] != (placeholder{kind: "pan"}) || len(pi.positions) != 5 || pi.signer != "" {
		t.Errorf("stripe payment_intents decoded as %+v", *pi)
	}
	for _, addr := range []string{"setup_future_usage", "customer", "save_payment_method", "payment_method_options[card][setup_future_usage]"} {
		if f, ok := pi.forbid[addr]; !ok || f == nil || len(f) != 0 {
			t.Errorf("stripe forbid %s = %v (present %v), want empty", addr, f, ok)
		}
	}
	gpi := catEndpointByID(t, c, "stripe", "get_payment_intent")
	if gpi.method != "GET" || !slices.Equal(gpi.path, []string{"v1", "payment_intents", "{id}"}) || gpi.cardData ||
		!gpi.query["expand[]"] || len(gpi.query) != 1 || len(gpi.positions) != 0 {
		t.Errorf("stripe get_payment_intent decoded as %+v", *gpi)
	}

	// Adyen: canonical header name, account pin, forbid with an allowed literal.
	ay := catEndpointByID(t, c, "adyen", "payments")
	if ay.headers["X-Api-Key"] != "{{secret:apiKey}}" || len(ay.headers) != 1 {
		t.Errorf("adyen headers = %v", ay.headers)
	}
	if p := ay.pins["/merchantAccount"]; p.account != "merchantAccount" || p.literal != nil || len(ay.pins) != 1 {
		t.Errorf("adyen pin = %+v", p)
	}
	if f := ay.forbid["/storePaymentMethod"]; !slices.Equal(f, []fieldValue{{kind: "bool", text: "false"}}) {
		t.Errorf("adyen forbid storePaymentMethod = %v", f)
	}
	if f, ok := ay.forbid["/shopperReference"]; !ok || f == nil || len(f) != 0 {
		t.Errorf("adyen forbid shopperReference = %v", f)
	}

	// Mercado Pago: integer expiry.
	mp := catEndpointByID(t, c, "mercadopago", "card_tokens")
	if mp.positions["/expiration_month"] != (placeholder{kind: "exp_month", mod: "int"}) || mp.positions["/expiration_year"] != (placeholder{kind: "exp_year", mod: "int"}) {
		t.Errorf("mercadopago positions = %v", mp.positions)
	}

	// PayU: body secret, literal and account pins, signer.
	pu := catEndpointByID(t, c, "payu", "submit_transaction")
	if p := pu.pins["/command"]; p.account != "" || p.literal == nil || *p.literal != (fieldValue{kind: "string", text: "SUBMIT_TRANSACTION"}) {
		t.Errorf("payu /command pin = %+v", p)
	}
	if pu.pins["/merchant/apiLogin"].account != "apiLogin" || pu.pins["/transaction/order/accountId"].account != "accountId" ||
		pu.signer != "payu" || len(pu.headers) != 0 ||
		pu.positions["/merchant/apiKey"] != (placeholder{kind: "secret", arg: "apiKey"}) ||
		pu.positions["/transaction/order/signature"] != (placeholder{kind: "signature"}) ||
		pu.positions["/transaction/creditCard/expirationDate"] != (placeholder{kind: "exp", mod: "yyyy/mm"}) {
		t.Errorf("payu decoded as %+v", *pu)
	}

	// Pagar.me: Basic auth header, array-index position.
	pg := catEndpointByID(t, c, "pagarme", "orders")
	if pg.positions["/payments/0/credit_card/card/number"] != (placeholder{kind: "pan"}) || pg.headers["Authorization"] != "Basic {{basic:secretKey}}" {
		t.Errorf("pagarme decoded as %+v", *pg)
	}
}

// TestParseCatalogRejects applies one mutation per validation rule to testCatalogJSON. Each must be
// rejected with an error naming the rule (want), and no error may name a secret resource.
func TestParseCatalogRejects(t *testing.T) {
	if _, err := parseCatalog([]byte(testCatalogJSON), "dev"); err != nil {
		t.Fatalf("fixture rejected: %v", err)
	}
	const (
		stripeAcct = `"stripe_t": {"provider": "stripe", "env": "dev", "host": "upstream.test", "base_path": ""`
		adyenAcct  = `"adyen_br": {"provider": "adyen", "env": "dev", "host": "upstream.test", "base_path": "/checkout"`
		payuVals   = `"values": {"apiLogin": "pRRXKOl8ikMmt9u", "accountId": "512321", "merchantId": "508029", "hash": "sha256"}`
		gpiLine    = `"id": "get_payment_intent", "method": "GET", "path": "/v1/payment_intents/{id}", "query": ["expand[]"],`
		tokensLine = `"id": "tokens", "method": "POST", "path": "/v1/tokens", "card_data": true,`
	)
	cases := []struct{ name, old, new, want string }{
		// Strict JSON, unknown keys, wrong types.
		{"duplicate key", `"format": "form",`, `"format": "form", "format": "form",`, "strict JSON"},
		{"trailing data", "", "", "strict JSON"}, // special-cased below
		{"invalid utf-8", `AcmeBR_ECOM`, "Acme\xffBR", "strict JSON"},
		{"unknown root key", `"providers": {`, `"extra": {}, "providers": {`, `unknown key "extra"`},
		{"unknown provider key", `"format": "form",`, `"format": "form", "base": "x",`, `unknown key "base"`},
		{"unknown endpoint key", tokensLine, tokensLine + ` "bogus": true,`, `unknown key "bogus"`},
		{"unknown pin key", `{"account": "merchantAccount"}`, `{"account": "merchantAccount", "x": 1}`, `unknown key "x"`},
		{"unknown account key", stripeAcct, stripeAcct + `, "port": 1`, `unknown key "port"`},
		{"case-variant provider key", `"format": "form",`, `"Format": "form",`, `unknown key "Format"`},
		{"case-variant endpoint key", tokensLine, `"ID": "tokens", "method": "POST", "path": "/v1/tokens", "card_data": true,`, `unknown key "ID"`},
		{"case-variant account key", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "dev", "Host": "upstream.test", "base_path": ""`, `unknown key "Host"`},
		{"case-variant pin key", `{"literal": "SUBMIT_TRANSACTION"}`, `{"Literal": "SUBMIT_TRANSACTION"}`, `unknown key "Literal"`},
		{"wrong type", tokensLine, `"id": "tokens", "method": "POST", "path": "/v1/tokens", "card_data": "yes",`, "wrong type"},
		{"root not an object", "", "", "strict JSON"}, // special-cased below

		// Names.
		{"bad provider name", `"stripe": {`, `"Stripe": {`, `provider "Stripe": invalid name`},
		{"bad endpoint id", `"id": "tokens"`, `"id": "to kens"`, "invalid id"},
		{"bad account name", `"stripe_t": {`, `"stripe-t": {`, `account "stripe-t": invalid name`},

		// Provider format and endpoints.
		{"format not json/form", `"format": "form",`, `"format": "xml",`, `provider "stripe": format`},
		{"empty endpoints", `"providers": {`, `"providers": {"empty": {"format": "json", "endpoints": []},`, `provider "empty": no endpoints`},
		{"duplicate endpoint id", `"id": "tokens"`, `"id": "payment_intents"`, `endpoint "payment_intents": duplicate id`},
		{"method not allowed", tokensLine, `"id": "tokens", "method": "HEAD", "path": "/v1/tokens", "card_data": true,`, `endpoint "tokens": method`},
		{"method lowercase", tokensLine, `"id": "tokens", "method": "post", "path": "/v1/tokens", "card_data": true,`, `endpoint "tokens": method`},
		{"overlapping endpoints", gpiLine, `"id": "get_payment_intent", "method": "POST", "path": "/v1/{id}", "query": ["expand[]"],`, "overlap"},

		// Paths.
		{"path without slash", `"/v1/tokens"`, `"v1/tokens"`, `endpoint "tokens": invalid path`},
		{"path empty segment", `"/v1/tokens"`, `"/v1//tokens"`, `endpoint "tokens": invalid path`},
		{"path trailing slash", `"/v1/tokens"`, `"/v1/tokens/"`, `endpoint "tokens": invalid path`},
		{"path dot-dot", `"/v1/tokens"`, `"/v1/../tokens"`, `endpoint "tokens": invalid path`},
		{"path dot", `"/v1/tokens"`, `"/v1/./tokens"`, `endpoint "tokens": invalid path`},
		{"path percent", `"/v1/tokens"`, `"/v1/tok%65ns"`, `endpoint "tokens": invalid path`},
		{"path query", `"/v1/tokens"`, `"/v1/tokens?x=1"`, `endpoint "tokens": invalid path`},
		{"path empty", `"/v1/tokens"`, `""`, `endpoint "tokens": invalid path`},
		{"wildcard bad name", `{id}"`, `{i-d}"`, `endpoint "get_payment_intent": invalid path`},
		{"wildcard empty", `{id}"`, `{}"`, `endpoint "get_payment_intent": invalid path`},
		{"wildcard unclosed", `{id}"`, `{id"`, `endpoint "get_payment_intent": invalid path`},
		{"wildcard partial segment", `{id}"`, `pi_{id}"`, `endpoint "get_payment_intent": invalid path`},
		{"wildcard repeated", `/v1/payment_intents/{id}"`, `/v1/{id}/{id}"`, `endpoint "get_payment_intent": invalid path`},
		{"query key invalid", `["expand[]"]`, `["expand[]x"]`, `query key`},
		{"query key duplicate", `["expand[]"]`, `["expand[]", "expand[]"]`, `query key`},

		// Placeholders and positions.
		{"unknown placeholder", `"card[number]": "{{pan}}"`, `"card[number]": "{{card}}"`, `position "card[number]": unknown placeholder`},
		{"unknown modifier", `"card[number]": "{{pan}}"`, `"card[number]": "{{pan:int}}"`, `position "card[number]": unknown placeholder`},
		{"not a placeholder", `"card[number]": "{{pan}}"`, `"card[number]": "4242"`, `position "card[number]": unknown placeholder`},
		{"card placeholder without card_data", tokensLine, `"id": "tokens", "method": "POST", "path": "/v1/tokens", "card_data": false,`, `position "card[cvc]": card placeholder without card_data`},
		{"card position on non-card endpoint", gpiLine, gpiLine + ` "positions": {"x": "{{cvv}}"},`, `position "x": card placeholder without card_data`},
		{"card_data without card position", gpiLine, gpiLine + ` "card_data": true,`, "card_data without a card position"},
		{"basic in body position", `"/merchant/apiKey": "{{secret:apiKey}}"`, `"/merchant/apiKey": "{{basic:apiKey}}"`, `position "/merchant/apiKey": {{basic:}}`},

		// Headers.
		{"header Host", `"X-API-Key": "{{secret:apiKey}}"`, `"Host": "{{secret:apiKey}}"`, `header "Host": vault-owned`},
		{"header Content-Type", `"X-API-Key": "{{secret:apiKey}}"`, `"content-type": "{{secret:apiKey}}"`, `header "Content-Type": vault-owned`},
		{"header Content-Length", `"X-API-Key": "{{secret:apiKey}}"`, `"Content-Length": "{{secret:apiKey}}"`, `header "Content-Length": vault-owned`},
		{"header User-Agent", `"X-API-Key": "{{secret:apiKey}}"`, `"User-Agent": "{{secret:apiKey}}"`, `header "User-Agent": vault-owned`},
		{"header Transfer-Encoding", `"X-API-Key": "{{secret:apiKey}}"`, `"Transfer-Encoding": "{{secret:apiKey}}"`, `header "Transfer-Encoding": vault-owned`},
		{"header platform-allowlisted", `"X-API-Key": "{{secret:apiKey}}"`, `"Idempotency-Key": "{{secret:apiKey}}"`, `header "Idempotency-Key": vault-owned`},
		{"header duplicate after canonicalization", `"X-API-Key": "{{secret:apiKey}}"`, `"X-API-Key": "{{secret:apiKey}}", "x-api-key": "{{secret:apiKey}}"`, "duplicate header"},
		{"header bad name", `"X-API-Key": "{{secret:apiKey}}"`, `"X API Key": "{{secret:apiKey}}"`, "invalid header name"},
		{"header card placeholder", `"X-API-Key": "{{secret:apiKey}}"`, `"X-API-Key": "{{pan}}"`, `header "X-Api-Key": card placeholder`},
		{"header card placeholder in template", `"X-API-Key": "{{secret:apiKey}}"`, `"X-API-Key": "Card {{exp:mm/yy}}"`, `header "X-Api-Key": card placeholder`},
		{"header no placeholder", `"X-API-Key": "{{secret:apiKey}}"`, `"X-API-Key": "static"`, `header "X-Api-Key": template`},
		{"header two placeholders", `"X-API-Key": "{{secret:apiKey}}"`, `"X-API-Key": "{{secret:apiKey}}{{secret:apiKey}}"`, `header "X-Api-Key": template`},
		{"header unknown placeholder", `"X-API-Key": "{{secret:apiKey}}"`, `"X-API-Key": "{{secret:api-key}}"`, `header "X-Api-Key": template`},
		{"header stray brace", `"X-API-Key": "{{secret:apiKey}}"`, `"X-API-Key": "{{secret:apiKey}}}"`, `header "X-Api-Key": template`},
		{"header control char", `"X-API-Key": "{{secret:apiKey}}"`, `"X-API-Key": "{{secret:apiKey}}\r\nX: y"`, `header "X-Api-Key": template`},

		// Signers.
		{"signature without signer", `"signer": "payu"`, `"signer": ""`, "{{signature}} without signer"},
		{"signature header without signer", `"X-API-Key": "{{secret:apiKey}}"`, `"X-API-Key": "{{secret:apiKey}}", "X-Signature": "{{signature}}"`, "{{signature}} without signer"},
		{"signer without signature", `"/transaction/order/signature": "{{signature}}",`, ``, "signer without {{signature}}"},
		{"unknown signer", `"signer": "payu"`, `"signer": "hmac"`, `unknown signer`},

		// Addresses.
		{"position and forbid", `"customer": [],`, `"customer": [], "payment_method_data[card][number]": [],`, `address "payment_method_data[card][number]" appears in more than one`},
		{"position and pin", `"pins": {"/merchantAccount"`, `"pins": {"/paymentMethod/cvc": {"literal": "1"}, "/merchantAccount"`, `address "/paymentMethod/cvc" appears in more than one`},
		{"pin and forbid", `"/shopperReference": []`, `"/shopperReference": [], "/merchantAccount": []`, `address "/merchantAccount" appears in more than one`},
		{"json pointer without slash", `"/paymentMethod/cvc"`, `"paymentMethod/cvc"`, `position "paymentMethod/cvc": invalid address`},
		{"json pointer bad escape", `"/paymentMethod/cvc"`, `"/payment~2Method/cvc"`, `position "/payment~2Method/cvc": invalid address`},
		{"json pointer trailing tilde", `"/paymentMethod/cvc"`, `"/paymentMethod/cvc~"`, `invalid address`},
		{"json pointer empty", `"/paymentMethod/cvc"`, `""`, `position "": invalid address`},
		{"json pointer empty token", `"/paymentMethod/cvc"`, `"/paymentMethod//cvc"`, `invalid address`},
		{"json pin bad pointer", `"/command": {`, `"command": {`, `pin "command": invalid address`},
		{"json forbid bad pointer", `"/shopperReference": []`, `"shopperReference": []`, `forbid "shopperReference": invalid address`},
		{"form forbid bad key", `"customer": []`, `"customer]": []`, `forbid "customer]": invalid address`},
		{"form position bad key", `"card[name]": "{{name}}"`, `"card.name": "{{name}}"`, `position "card.name": invalid address`},
		{"form position repeatable key", `"card[name]": "{{name}}"`, `"card[name][]": "{{name}}"`, `position "card[name][]": invalid address`},

		// Pins and forbid literals.
		{"pin both account and literal", `{"literal": "SUBMIT_TRANSACTION"}`, `{"literal": "SUBMIT_TRANSACTION", "account": "apiLogin"}`, `pin "/command": needs exactly one`},
		{"pin neither", `{"literal": "SUBMIT_TRANSACTION"}`, `{}`, `pin "/command": needs exactly one`},
		{"pin null literal", `{"literal": "SUBMIT_TRANSACTION"}`, `{"literal": null}`, `pin "/command": needs exactly one`},
		{"pin object literal", `{"literal": "SUBMIT_TRANSACTION"}`, `{"literal": {"a": 1}}`, `pin "/command": invalid literal`},
		{"pin placeholder literal", `{"literal": "SUBMIT_TRANSACTION"}`, `{"literal": "{{pan}}"}`, `pin "/command": invalid literal`},
		{"pin bad value name", `{"account": "merchantAccount"}`, `{"account": "merchant-account"}`, `pin "/merchantAccount": invalid account value name`},
		{"forbid not a list", `"/shopperReference": []`, `"/shopperReference": null`, `forbid "/shopperReference": must be a list`},
		{"forbid object literal", `"/shopperReference": []`, `"/shopperReference": [{}]`, `forbid "/shopperReference": invalid literal`},
		{"form forbid non-string literal", `"customer": []`, `"customer": [false]`, `forbid "customer": invalid literal`},

		// Accounts.
		{"account env", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "staging", "host": "upstream.test", "base_path": ""`, `account "stripe_t": env`},
		{"account env missing", stripeAcct, `"stripe_t": {"provider": "stripe", "host": "upstream.test", "base_path": ""`, `account "stripe_t": env`},
		{"account unknown provider", stripeAcct, `"stripe_t": {"provider": "strype", "env": "dev", "host": "upstream.test", "base_path": ""`, `account "stripe_t": unknown provider`},
		{"host uppercase", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "dev", "host": "Upstream.test", "base_path": ""`, `account "stripe_t": invalid host`},
		{"host scheme", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "dev", "host": "https://upstream.test", "base_path": ""`, `account "stripe_t": invalid host`},
		{"host path", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "dev", "host": "upstream.test/x", "base_path": ""`, `account "stripe_t": invalid host`},
		{"host userinfo", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "dev", "host": "a@upstream.test", "base_path": ""`, `account "stripe_t": invalid host`},
		{"host port too long", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "dev", "host": "upstream.test:123456", "base_path": ""`, `account "stripe_t": invalid host`},
		{"host port out of range", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "dev", "host": "upstream.test:65536", "base_path": ""`, `account "stripe_t": invalid host`},
		{"host empty label", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "dev", "host": "upstream..test", "base_path": ""`, `account "stripe_t": invalid host`},
		{"host empty", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "dev", "host": "", "base_path": ""`, `account "stripe_t": invalid host`},
		{"base_path trailing slash", adyenAcct, `"adyen_br": {"provider": "adyen", "env": "dev", "host": "upstream.test", "base_path": "/checkout/"`, `account "adyen_br": invalid base_path`},
		{"base_path relative", adyenAcct, `"adyen_br": {"provider": "adyen", "env": "dev", "host": "upstream.test", "base_path": "checkout"`, `account "adyen_br": invalid base_path`},
		{"base_path slash", adyenAcct, `"adyen_br": {"provider": "adyen", "env": "dev", "host": "upstream.test", "base_path": "/"`, `account "adyen_br": invalid base_path`},
		{"base_path dot-dot", adyenAcct, `"adyen_br": {"provider": "adyen", "env": "dev", "host": "upstream.test", "base_path": "/a/.."`, `account "adyen_br": invalid base_path`},
		{"base_path wildcard", adyenAcct, `"adyen_br": {"provider": "adyen", "env": "dev", "host": "upstream.test", "base_path": "/{id}"`, `account "adyen_br": invalid base_path`},
		{"secret resource invalid", `"projects/pci-cde-dev/secrets/stripe-t-key"`, `"projects/pci-cde-dev/secrets/stripe-t-key/versions/1"`, `account "stripe_t": secret "secretKey": invalid Secret Manager resource`},
		{"secret resource not a resource", `"projects/pci-cde-dev/secrets/stripe-t-key"`, `"sk_test_123"`, `account "stripe_t": secret "secretKey": invalid Secret Manager resource`},
		{"secret name invalid", `{"secretKey": "projects/pci-cde-dev/secrets/stripe-t-key"}`, `{"secret-key": "projects/pci-cde-dev/secrets/stripe-t-key"}`, `account "stripe_t": invalid secret name`},
		{"value name invalid", `"merchantAccount": "AcmeBR_ECOM"`, `"merchant.account": "AcmeBR_ECOM"`, `account "adyen_br": invalid value name`},
		{"value empty", `"merchantAccount": "AcmeBR_ECOM"`, `"merchantAccount": ""`, `account "adyen_br": value "merchantAccount": invalid`},
		{"value placeholder", `"merchantAccount": "AcmeBR_ECOM"`, `"merchantAccount": "{{pan}}"`, `account "adyen_br": value "merchantAccount": invalid`},
		{"missing header secret", `{"secretKey": "projects/pci-cde-dev/secrets/stripe-t-key"}`, `{"secretKey2": "projects/pci-cde-dev/secrets/stripe-t-key"}`, `account "stripe_t": endpoint "payment_intents": missing secret "secretKey"`},
		{"missing basic secret", `"secretKey": "projects/pci-cde-dev/secrets/pagarme-br-key"`, `"key": "projects/pci-cde-dev/secrets/pagarme-br-key"`, `account "pagarme_br": endpoint "orders": missing secret "secretKey"`},
		{"missing position secret", `"apiKey": "projects/pci-cde-dev/secrets/payu-co-key"`, `"key": "projects/pci-cde-dev/secrets/payu-co-key"`, `account "payu_co": endpoint "submit_transaction": missing secret "apiKey"`},
		{"missing pin value", `"merchantAccount": "AcmeBR_ECOM"`, `"merchant": "AcmeBR_ECOM"`, `account "adyen_br": endpoint "payments": missing value "merchantAccount"`},
		{"missing pin value in prod account", `"merchantAccount": "AcmeBR_LIVE"`, `"merchant": "AcmeBR_LIVE"`, `account "adyen_br_live": endpoint "payments": missing value "merchantAccount"`},
		{"payu missing merchantId", payuVals, `"values": {"apiLogin": "pRRXKOl8ikMmt9u", "accountId": "512321", "hash": "sha256"}`, `account "payu_co": payu needs`},
		{"payu missing hash", payuVals, `"values": {"apiLogin": "pRRXKOl8ikMmt9u", "accountId": "512321", "merchantId": "508029"}`, `account "payu_co": payu needs`},
		{"payu bad hash", payuVals, `"values": {"apiLogin": "pRRXKOl8ikMmt9u", "accountId": "512321", "merchantId": "508029", "hash": "crc32"}`, `account "payu_co": payu needs`},
		{"payu hash case", payuVals, `"values": {"apiLogin": "pRRXKOl8ikMmt9u", "accountId": "512321", "merchantId": "508029", "hash": "SHA256"}`, `account "payu_co": payu needs`},
	}
	for _, c := range cases {
		data := testCatalogJSON
		switch c.name {
		case "trailing data":
			data += ` {}`
		case "root not an object":
			data = `[]`
		default:
			if !strings.Contains(data, c.old) {
				t.Errorf("%s: mutation target not in fixture", c.name)
				continue
			}
			data = strings.Replace(data, c.old, c.new, 1)
		}
		_, err := parseCatalog([]byte(data), "dev")
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not contain %q", c.name, err, c.want)
		}
		if strings.Contains(err.Error(), "projects/") || strings.Contains(err.Error(), "sk_test") {
			t.Errorf("%s: error names a secret resource", c.name)
		}
	}

	// The environment argument itself.
	for _, env := range []string{"", "staging", "Dev", "PROD"} {
		if _, err := parseCatalog([]byte(testCatalogJSON), env); err == nil {
			t.Errorf("env %q accepted", env)
		}
	}
}

func TestEmbeddedCatalog(t *testing.T) {
	for _, env := range []string{"dev", "prod"} {
		if _, err := parseCatalog(catalogJSON, env); err != nil {
			t.Fatalf("embedded catalog (%s): %v", env, err)
		}
	}
	c, _ := parseCatalog(catalogJSON, "dev")
	pi := catEndpointByID(t, c, "stripe", "payment_intents")
	tk := catEndpointByID(t, c, "stripe", "tokens")
	if c.providers["stripe"].format != "form" || len(c.providers["stripe"].endpoints) != 2 || !pi.cardData || !tk.cardData {
		t.Error("embedded stripe provider shape")
	}
	for _, addr := range []string{"setup_future_usage", "customer", "save_payment_method", "payment_method_options[card][setup_future_usage]"} {
		if f, ok := pi.forbid[addr]; !ok || len(f) != 0 {
			t.Errorf("embedded stripe payment_intents does not forbid %s", addr)
		}
	}
	if a := c.accounts["stripe_test"]; a == nil || a.host != "api.stripe.com" || a.secretNames["secretKey"] != "projects/pci-cde-dev/secrets/stripe-test-secret-key" {
		t.Error("embedded stripe_test account")
	}
}

// egress-hosts.<env>.txt are the files the infra repo's firewall check diffs against (§9.1, D§5.1):
// each must list exactly its environment's catalog account hosts, without ports.
func TestEgressHostsMatchCatalog(t *testing.T) {
	for _, env := range []string{"dev", "prod"} {
		raw, err := os.ReadFile("egress-hosts." + env + ".txt")
		if err != nil {
			t.Fatalf("cannot read egress-hosts.%s.txt", env)
		}
		var file []string
		for _, line := range strings.Split(string(raw), "\n") {
			if h := strings.TrimSpace(line); h != "" {
				file = append(file, h)
			}
		}
		slices.Sort(file)
		c, err := parseCatalog(catalogJSON, env)
		if err != nil {
			t.Fatalf("embedded catalog (%s): %v", env, err)
		}
		hosts := map[string]bool{}
		for _, a := range c.accounts {
			h, _, _ := strings.Cut(a.host, ":")
			hosts[h] = true
		}
		if want := slices.Sorted(maps.Keys(hosts)); !slices.Equal(file, want) {
			t.Errorf("egress-hosts.%s.txt %v != catalog hosts %v", env, file, want)
		}
	}
}

// ---------------------------------------------------------------------------
// /proxy request policy: checkProxy (D§5.2-5.6, D§5.10, D§5.11)
// ---------------------------------------------------------------------------

const checkToken = "tok_0123456789abcdef0123456789abcdef"

// Valid platform bodies for each modelled provider (see testCatalogJSON).
const (
	stripePIBody = `amount=1000&currency=usd&confirm=true&payment_method_data[type]=card` +
		`&payment_method_data[card][number]={{pan}}&payment_method_data[card][exp_month]={{exp_month}}` +
		`&payment_method_data[card][exp_year]={{exp_year}}&payment_method_data[card][cvc]={{cvv}}`
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
	case "stripe_get":
		return newEnvelope("stripe_t", "GET", "/v1/payment_intents/pi_123?expand[]=latest_charge&expand%5B%5D=customer",
			map[string]string{"Accept": "application/json"}, "")
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

// occSummary renders occs as "addr=placeholder" strings and checks each span holds the placeholder
// text (quoted for json).
func occSummary(t *testing.T, format string, body []byte, occs []occurrence) []string {
	t.Helper()
	var out []string
	for _, o := range occs {
		want := o.ph.String()
		if format == "json" {
			want = `"` + want + `"`
		}
		if string(body[o.start:o.end]) != want {
			t.Errorf("occurrence %s: span does not hold %s", o.addr, o.ph)
		}
		out = append(out, o.addr+"="+o.ph.String())
	}
	return out
}

func TestCheckProxyAccepts(t *testing.T) {
	c := testCatalog(t, "127.0.0.1:9")
	cases := []struct {
		name, provider, endpoint, path string
		occs                           []string
		headers                        http.Header
		cvv, holder                    bool
	}{
		{"stripe", "stripe", "payment_intents", "/v1/payment_intents", []string{
			"payment_method_data[card][number]={{pan}}", "payment_method_data[card][exp_month]={{exp_month}}",
			"payment_method_data[card][exp_year]={{exp_year}}", "payment_method_data[card][cvc]={{cvv}}",
		}, http.Header{"Idempotency-Key": {"ord-1"}}, true, false},
		{"stripe_get", "stripe", "get_payment_intent", "/v1/payment_intents/pi_123?expand[]=latest_charge&expand%5B%5D=customer",
			nil, http.Header{"Accept": {"application/json"}}, false, false},
		{"adyen", "adyen", "payments", "/v72/payments", []string{
			"/paymentMethod/number={{pan}}", "/paymentMethod/expiryMonth={{exp_month}}", "/paymentMethod/expiryYear={{exp_year}}",
			"/paymentMethod/cvc={{cvv}}", "/paymentMethod/holderName={{name}}",
		}, http.Header{"Idempotency-Key": {"ord-1"}}, true, true},
		{"mercadopago", "mercadopago", "card_tokens", "/v1/card_tokens", []string{
			"/card_number={{pan}}", "/expiration_month={{exp_month:int}}", "/expiration_year={{exp_year:int}}", "/security_code={{cvv}}",
		}, http.Header{"X-Idempotency-Key": {"k-1"}}, true, false},
		{"payu", "payu", "submit_transaction", "/payments-api/4.0/service.cgi", []string{
			"/merchant/apiKey={{secret:apiKey}}", "/transaction/order/signature={{signature}}",
			"/transaction/creditCard/number={{pan}}", "/transaction/creditCard/securityCode={{cvv}}",
			"/transaction/creditCard/expirationDate={{exp:yyyy/mm}}", "/transaction/creditCard/name={{name}}",
		}, http.Header{}, true, true},
		{"pagarme", "pagarme", "orders", "/core/v5/orders", []string{
			"/payments/0/credit_card/card/number={{pan}}", "/payments/0/credit_card/card/exp_month={{exp_month:int}}",
			"/payments/0/credit_card/card/exp_year={{exp_year:int}}", "/payments/0/credit_card/card/holder_name={{name}}",
		}, http.Header{"Accept": {"application/json"}}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validEnvelope(tc.name)
			p, perr := c.checkProxy(e)
			if perr != nil {
				t.Fatalf("rejected: %+v", *perr)
			}
			if p.acct != c.accounts[e.Account] || p.prov != c.providers[tc.provider] || p.ep != catEndpointByID(t, c, tc.provider, tc.endpoint) {
				t.Errorf("plan account/provider/endpoint = %v/%v/%v", p.acct.name, p.prov.name, p.ep.id)
			}
			if p.path != tc.path || string(p.body) != e.Request.Body {
				t.Errorf("plan path %q or body differs from the envelope", p.path)
			}
			if got := occSummary(t, p.prov.format, p.body, p.occs); !slices.Equal(got, tc.occs) {
				t.Errorf("occs = %v, want %v", got, tc.occs)
			}
			if p.usesCVV != tc.cvv || p.usesName != tc.holder {
				t.Errorf("usesCVV, usesName = %v, %v, want %v, %v", p.usesCVV, p.usesName, tc.cvv, tc.holder)
			}
			// Only allowlisted headers are carried; template headers are rendered by the vault.
			if !reflect.DeepEqual(p.headers, tc.headers) {
				t.Errorf("plan headers = %v, want %v", p.headers, tc.headers)
			}
		})
	}

	// Forbid with an allowed literal: storePaymentMethod false and absent both pass.
	e := validEnvelope("adyen")
	e.Request.Body = strings.Replace(adyenBody, `,"storePaymentMethod":false`, "", 1)
	if _, perr := c.checkProxy(e); perr != nil {
		t.Errorf("adyen without storePaymentMethod rejected: %+v", *perr)
	}
	// Omitting a template header is fine: the vault adds it.
	e = validEnvelope("adyen")
	e.Request.Headers = nil
	if _, perr := c.checkProxy(e); perr != nil {
		t.Errorf("adyen without X-API-Key rejected: %+v", *perr)
	}
	// Positions are allowed, not required: a card-free body passes.
	e = validEnvelope("stripe")
	e.Request.Body = "amount=1000&currency=usd"
	if p, perr := c.checkProxy(e); perr != nil || len(p.occs) != 0 || p.usesCVV || p.usesName {
		t.Errorf("stripe card-free body: plan %v, error %v", p, perr)
	}
}

func TestCheckProxyRejects(t *testing.T) {
	c := testCatalog(t, "127.0.0.1:9")
	const (
		ep  = "endpoint"
		hdr = "header"
		ph  = "placeholder"
	)
	type tc struct {
		name, base  string
		mut         func(e *proxyEnvelope)
		msg, reason string
	}
	path := func(p string) func(e *proxyEnvelope) { return func(e *proxyEnvelope) { e.Request.Path = p } }
	header := func(k, v string) func(e *proxyEnvelope) {
		return func(e *proxyEnvelope) {
			h := map[string]string{}
			maps.Copy(h, e.Request.Headers)
			h[k] = v
			e.Request.Headers = h
		}
	}
	body := func(b string) func(e *proxyEnvelope) { return func(e *proxyEnvelope) { e.Request.Body = b } }
	replace := func(base, old, new string) func(e *proxyEnvelope) {
		if !strings.Contains(base, old) {
			panic("replace: fixture lacks " + old)
		}
		return body(strings.Replace(base, old, new, 1))
	}
	cases := []tc{
		// Envelope errors: no alert reason.
		{"invalid token", "adyen", func(e *proxyEnvelope) { e.Token = "tok_ABC" }, msgInvalidToken, ""},
		{"unknown account", "adyen", func(e *proxyEnvelope) { e.Account = "nope" }, msgUnknownAccount, ""},
		{"other env account", "adyen", func(e *proxyEnvelope) { e.Account = "adyen_br_live" }, msgUnknownAccount, ""},
		{"empty account", "adyen", func(e *proxyEnvelope) { e.Account = "" }, msgUnknownAccount, ""},

		// Endpoint matching.
		{"wrong method", "adyen", func(e *proxyEnvelope) { e.Request.Method = "PUT" }, msgEndpointNotAllowed, ep},
		{"lowercase method", "adyen", func(e *proxyEnvelope) { e.Request.Method = "post" }, msgEndpointNotAllowed, ep},
		{"unknown path", "adyen", path("/v72/refunds"), msgEndpointNotAllowed, ep},
		{"other provider path", "adyen", path("/v1/card_tokens"), msgEndpointNotAllowed, ep},
		{"trailing slash", "adyen", path("/v72/payments/"), msgEndpointNotAllowed, ep},
		{"no leading slash", "adyen", path("v72/payments"), msgEndpointNotAllowed, ep},
		{"empty path", "adyen", path(""), msgEndpointNotAllowed, ep},
		{"percent-encoded slash", "stripe_get", path("/v1/payment_intents/pi%2F1"), msgEndpointNotAllowed, ep},
		{"percent-encoded literal", "adyen", path("/v72/p%61yments"), msgEndpointNotAllowed, ep},
		{"dot-dot", "stripe_get", path("/v1/payment_intents/../tokens"), msgEndpointNotAllowed, ep},
		{"dot-dot wildcard", "stripe_get", path("/v1/payment_intents/.."), msgEndpointNotAllowed, ep},
		{"double slash", "adyen", path("//v72/payments"), msgEndpointNotAllowed, ep},
		{"inner double slash", "adyen", path("/v72//payments"), msgEndpointNotAllowed, ep},
		{"wildcard bad char", "stripe_get", path("/v1/payment_intents/pi.1"), msgEndpointNotAllowed, ep},
		{"wildcard too long", "stripe_get", path("/v1/payment_intents/" + strings.Repeat("a", 129)), msgEndpointNotAllowed, ep},
		{"placeholder in path", "stripe_get", path("/v1/payment_intents/{{pan}}"), msgEndpointNotAllowed, ep},
		{"fragment", "adyen", path("/v72/payments#x"), msgEndpointNotAllowed, ep},
		{"unlisted query key", "stripe_get", path("/v1/payment_intents/pi_1?limit=3"), msgEndpointNotAllowed, ep},
		{"query on endpoint without keys", "adyen", path("/v72/payments?expand[]=a"), msgEndpointNotAllowed, ep},
		{"placeholder in query value", "stripe_get", path("/v1/payment_intents/pi_1?expand[]={{pan}}"), msgEndpointNotAllowed, ep},
		{"encoded placeholder in query value", "stripe_get", path("/v1/payment_intents/pi_1?expand[]=%7B%7Bpan%7D%7D"), msgEndpointNotAllowed, ep},
		{"bare question mark", "stripe_get", path("/v1/payment_intents/pi_1?"), msgEndpointNotAllowed, ep},
		{"query without value", "stripe_get", path("/v1/payment_intents/pi_1?expand[]"), msgEndpointNotAllowed, ep},
		{"query semicolon", "stripe_get", path("/v1/payment_intents/pi_1?expand[]=a;b"), msgEndpointNotAllowed, ep},
		{"query second question mark", "stripe_get", path("/v1/payment_intents/pi_1?expand[]=a?b"), msgEndpointNotAllowed, ep},

		// Headers.
		{"content-type header", "adyen", header("Content-Type", "text/plain"), msgHeaderNotAllowed, hdr},
		{"host header", "adyen", header("Host", "evil.example"), msgHeaderNotAllowed, hdr},
		{"x-use-mocks header", "adyen", header("X-Use-Mocks", "true"), msgHeaderNotAllowed, hdr},
		{"stripe-account header", "stripe", header("Stripe-Account", "acct_attacker"), msgHeaderNotAllowed, hdr},
		{"other endpoint's template header", "adyen", header("Authorization", "Bearer {{secret:apiKey}}"), msgHeaderNotAllowed, hdr},
		{"template header other value", "adyen", header("X-API-Key", "attacker"), msgHeaderNotAllowed, hdr},
		{"template header other secret", "stripe", header("Authorization", "Bearer {{secret:other}}"), msgHeaderNotAllowed, hdr},
		{"template header padded", "stripe", header("Authorization", "Bearer {{secret:secretKey}} "), msgHeaderNotAllowed, hdr},
		{"duplicate after canonicalization", "adyen", header("idempotency-key", "ord-2"), msgHeaderNotAllowed, hdr},
		{"duplicate template after canonicalization", "adyen", header("x-api-key", "{{secret:apiKey}}"), msgHeaderNotAllowed, hdr},
		{"pan in header value", "adyen", header("Idempotency-Key", "{{pan}}"), msgHeaderNotAllowed, hdr},
		{"pan in template header", "mercadopago", header("Authorization", "Bearer {{pan}}"), msgHeaderNotAllowed, hdr},
		{"empty header value", "adyen", header("Accept", ""), msgHeaderNotAllowed, hdr},
		{"long header value", "adyen", header("Accept", strings.Repeat("a", 1025)), msgHeaderNotAllowed, hdr},
		{"non-ascii header value", "adyen", header("Accept", "café"), msgHeaderNotAllowed, hdr},
		{"control char header value", "adyen", header("Accept", "a\r\nX-Evil: 1"), msgHeaderNotAllowed, hdr},
		{"invalid header name", "adyen", header("Accept ", "a"), msgHeaderNotAllowed, hdr},
		{"empty header name", "adyen", header("", "a"), msgHeaderNotAllowed, hdr},

		// Body parsing.
		{"invalid json", "adyen", body(`{"merchantAccount":`), msgBadBody, "body"},
		{"duplicate key", "adyen", replace(adyenBody, `"reference":"ord-1",`, `"reference":"ord-1","reference":"ord-2",`), msgBadBody, "body"},
		{"empty json body", "adyen", body(""), msgBadBody, "body"},
		{"duplicate form key", "stripe", body(stripePIBody + "&amount=1"), msgBadBody, "body"},
		{"malformed form", "stripe", body(stripePIBody + "&&x=1"), msgBadBody, "body"},

		// Placeholders.
		{"placeholder at unlisted address", "adyen", replace(adyenBody, `"reference":"ord-1"`, `"reference":"{{pan}}"`), msgPlaceholder, ph},
		{"pan twice", "adyen", replace(adyenBody, `"holderName":"{{name}}"`, `"holderName":"{{pan}}"`), msgPlaceholder, ph},
		{"secret at card position", "adyen", replace(adyenBody, `"number":"{{pan}}"`, `"number":"{{secret:apiKey}}"`), msgPlaceholder, ph},
		{"wrong modifier at position", "mercadopago", replace(mpBody, `"{{exp_month:int}}"`, `"{{exp_month}}"`), msgPlaceholder, ph},
		{"signature at unlisted address", "payu", replace(payuBody, `"description":"x"`, `"description":"{{signature}}"`), msgPlaceholder, ph},
		{"unknown placeholder", "adyen", replace(adyenBody, `"reference":"ord-1"`, `"reference":"{{foo}}"`), msgPlaceholder, ph},
		{"concatenated placeholder", "adyen", replace(adyenBody, `"reference":"ord-1"`, `"reference":"x{{pan}}"`), msgPlaceholder, ph},
		{"placeholder in key", "adyen", replace(adyenBody, `"reference"`, `"{{pan}}"`), msgPlaceholder, ph},
		{"literal credential at secret position", "payu", replace(payuBody, `"{{secret:apiKey}}"`, `"attackerKey"`), msgPlaceholder, ph},
		{"literal pan at card position", "adyen", replace(adyenBody, `"number":"{{pan}}"`, `"number":"4111111111111111"`), msgPlaceholder, ph},
		{"object at position", "mercadopago", replace(mpBody, `"security_code":"{{cvv}}"`, `"security_code":{"x":"y"}`), msgPlaceholder, ph},
		{"number at position", "mercadopago", replace(mpBody, `"{{exp_month:int}}"`, `3`), msgPlaceholder, ph},
		{"form literal at position", "stripe", replace(stripePIBody, `[cvc]={{cvv}}`, `[cvc]=123`), msgPlaceholder, ph},
		{"case-variant credential next to position", "payu", replace(payuBody, `"merchant":{`, `"Merchant":{"apiKey":"attackerKey"},"merchant":{`), msgPlaceholder, ph},
		{"case-variant credential instead of position", "payu", replace(payuBody, `"apiKey":"{{secret:apiKey}}",`, `"APIKEY":"attackerKey",`), msgPlaceholder, ph},
		{"form placeholder at unlisted key", "stripe", body(stripePIBody + "&description={{pan}}"), msgPlaceholder, ph},
		{"form encoded placeholder", "stripe", body(stripePIBody + "&description=%7B%7Bpan%7D%7D"), msgPlaceholder, ph},

		// Pins.
		{"adyen merchantAccount mismatch", "adyen", replace(adyenBody, `"AcmeBR_ECOM"`, `"AcmeBR_LIVE"`), msgPinMismatch, "pin"},
		{"adyen merchantAccount absent", "adyen", replace(adyenBody, `"merchantAccount":"AcmeBR_ECOM",`, ""), msgPinMismatch, "pin"},
		{"adyen merchantAccount not a string", "adyen", replace(adyenBody, `"AcmeBR_ECOM"`, `["AcmeBR_ECOM"]`), msgPinMismatch, "pin"},
		{"adyen merchantAccount case variant", "adyen", replace(adyenBody, `"merchantAccount":"AcmeBR_ECOM",`,
			`"merchantAccount":"AcmeBR_ECOM","MerchantAccount":"AcmeBR_LIVE",`), msgPinMismatch, "pin"},
		{"payu command CREATE_TOKEN", "payu", replace(payuBody, `"SUBMIT_TRANSACTION"`, `"CREATE_TOKEN"`), msgPinMismatch, "pin"},
		{"payu command absent", "payu", replace(payuBody, `"command":"SUBMIT_TRANSACTION",`, ""), msgPinMismatch, "pin"},
		{"payu accountId as number", "payu", replace(payuBody, `"accountId":"512321"`, `"accountId":512321`), msgPinMismatch, "pin"},
		{"payu apiLogin mismatch", "payu", replace(payuBody, `"pRRXKOl8ikMmt9u"`, `"attacker"`), msgPinMismatch, "pin"},

		// Forbid.
		{"adyen storePaymentMethod true", "adyen", replace(adyenBody, `"storePaymentMethod":false`, `"storePaymentMethod":true`), msgForbiddenField, "forbidden_field"},
		{"adyen storePaymentMethod string false", "adyen", replace(adyenBody, `"storePaymentMethod":false`, `"storePaymentMethod":"false"`), msgForbiddenField, "forbidden_field"},
		{"adyen storePaymentMethod null", "adyen", replace(adyenBody, `"storePaymentMethod":false`, `"storePaymentMethod":null`), msgForbiddenField, "forbidden_field"},
		{"adyen shopperReference present", "adyen", replace(adyenBody, `"storePaymentMethod":false`, `"shopperReference":"u1"`), msgForbiddenField, "forbidden_field"},
		{"adyen storePaymentMethod case variant", "adyen", replace(adyenBody, `"storePaymentMethod":false`,
			`"storePaymentMethod":false,"StorePaymentMethod":true`), msgForbiddenField, "forbidden_field"},
		{"stripe customer present", "stripe", body(stripePIBody + "&customer=cus_1"), msgForbiddenField, "forbidden_field"},
		{"stripe nested forbid present", "stripe", body(stripePIBody + "&payment_method_options[card][setup_future_usage]=off_session"), msgForbiddenField, "forbidden_field"},
		{"stripe forbid case variant", "stripe", body(stripePIBody + "&Customer=cus_1"), msgForbiddenField, "forbidden_field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validEnvelope(tc.base)
			tc.mut(e)
			p, perr := c.checkProxy(e)
			if perr == nil {
				t.Fatalf("accepted (plan for %s)", p.ep.id)
			}
			if p != nil {
				t.Errorf("plan returned with an error")
			}
			if perr.status != http.StatusBadRequest || perr.msg != tc.msg || perr.reason != tc.reason {
				t.Errorf("got %d %q reason %q, want 400 %q reason %q", perr.status, perr.msg, perr.reason, tc.msg, tc.reason)
			}
			// The alert names the matched endpoint once there is one (catalog text only).
			wantEP := map[string]string{"stripe": "payment_intents", "stripe_get": "get_payment_intent", "adyen": "payments",
				"mercadopago": "card_tokens", "payu": "submit_transaction", "pagarme": "orders"}[tc.base]
			if tc.reason == "" || tc.reason == ep {
				wantEP = ""
			}
			if perr.endpoint != wantEP {
				t.Errorf("endpoint = %q, want %q", perr.endpoint, wantEP)
			}
		})
	}
}

// TestCheckProxyDuplicateCardPlaceholder: a catalog listing {{pan}} at two positions still allows
// it at most once per request.
func TestCheckProxyDuplicateCardPlaceholder(t *testing.T) {
	c := testCatalog(t, "127.0.0.1:9")
	catEndpointByID(t, c, "adyen", "payments").positions["/additionalData/pan2"] = placeholder{kind: "pan"}
	e := validEnvelope("adyen")
	e.Request.Body = strings.Replace(adyenBody, `"reference":"ord-1"`, `"additionalData":{"pan2":"{{pan}}"}`, 1)
	_, perr := c.checkProxy(e)
	if perr == nil || perr.msg != msgPlaceholder || perr.reason != "placeholder" {
		t.Errorf("{{pan}} twice: got %+v", perr)
	}
	// Two expiry-year forms are the same card placeholder kind.
	catEndpointByID(t, c, "adyen", "payments").positions["/additionalData/yy"] = placeholder{kind: "exp_year", mod: "yy"}
	e.Request.Body = strings.Replace(adyenBody, `"reference":"ord-1"`, `"additionalData":{"yy":"{{exp_year:yy}}"}`, 1)
	if _, perr := c.checkProxy(e); perr == nil || perr.msg != msgPlaceholder {
		t.Errorf("{{exp_year}} and {{exp_year:yy}}: got %+v", perr)
	}
}

// TestCheckProxyArrayPosition (Review Focus 2): positions match array indexes exactly.
func TestCheckProxyArrayPosition(t *testing.T) {
	c := testCatalog(t, "127.0.0.1:9")
	e := validEnvelope("pagarme")
	e.Request.Body = strings.Replace(pagarmeBody, `"payments":[{`, `"payments":[{"payment_method":"pix"},{`, 1)
	_, perr := c.checkProxy(e)
	if perr == nil || perr.status != http.StatusBadRequest || perr.msg != msgPlaceholder || perr.reason != "placeholder" {
		t.Errorf("{{pan}} at /payments/1/...: got %+v", perr)
	}
}

// TestCheckProxyHeaderCaseVariant (Review Focus 3): a credential header under any spelling of its
// name must exactly equal the template, and is never carried into the plan.
func TestCheckProxyHeaderCaseVariant(t *testing.T) {
	c := testCatalog(t, "127.0.0.1:9")
	for _, name := range []string{"authorization", "AUTHORIZATION", "Authorization", "aUtHoRiZaTiOn"} {
		e := validEnvelope("mercadopago")
		e.Request.Headers = map[string]string{name: "Bearer sk_attacker"}
		if _, perr := c.checkProxy(e); perr == nil || perr.msg != msgHeaderNotAllowed || perr.reason != "header" {
			t.Errorf("%s: Bearer sk_attacker: got %+v", name, perr)
		}
		e.Request.Headers = map[string]string{name: "Bearer {{secret:accessToken}}", "accept": "application/json"}
		p, perr := c.checkProxy(e)
		if perr != nil {
			t.Fatalf("%s: exact template rejected: %+v", name, *perr)
		}
		if !reflect.DeepEqual(p.headers, http.Header{"Accept": {"application/json"}}) {
			t.Errorf("%s: plan headers = %v, want only Accept", name, p.headers)
		}
	}
}

// TestCheckProxySignerInputs (Review Focus 4): the payu signer's inputs must be present,
// non-placeholder strings or numbers.
func TestCheckProxySignerInputs(t *testing.T) {
	c := testCatalog(t, "127.0.0.1:9")
	cases := map[string][2]string{
		"referenceCode absent":      {`"referenceCode":"TestPayU",`, ``},
		"referenceCode placeholder": {`"referenceCode":"TestPayU"`, `"referenceCode":"{{name}}"`},
		"referenceCode object":      {`"referenceCode":"TestPayU"`, `"referenceCode":{"a":"b"}`},
		"referenceCode null":        {`"referenceCode":"TestPayU"`, `"referenceCode":null`},
		"value absent":              {`"value":3,`, ``},
		"value bool":                {`"value":3`, `"value":true`},
		"currency absent":           {`,"currency":"USD"`, ``},
		"currency array":            {`"currency":"USD"`, `"currency":["USD"]`},
	}
	for name, r := range cases {
		e := validEnvelope("payu")
		if !strings.Contains(payuBody, r[0]) {
			t.Fatalf("%s: fixture lacks %s", name, r[0])
		}
		e.Request.Body = strings.Replace(payuBody, r[0], r[1], 1)
		if _, perr := c.checkProxy(e); perr == nil || perr.status != http.StatusBadRequest || perr.msg != msgPlaceholder || perr.reason != "placeholder" {
			t.Errorf("%s: got %+v", name, perr)
		}
	}
	// Numbers and strings are both valid inputs.
	e := validEnvelope("payu")
	e.Request.Body = strings.Replace(payuBody, `"value":3`, `"value":"3.50"`, 1)
	if _, perr := c.checkProxy(e); perr != nil {
		t.Errorf("string value rejected: %+v", *perr)
	}
	// Even if a catalog listed a placeholder position at a signer input, the signer refuses it.
	catEndpointByID(t, c, "payu", "submit_transaction").positions["/transaction/order/referenceCode"] = placeholder{kind: "secret", arg: "apiKey"}
	e = validEnvelope("payu")
	e.Request.Body = strings.Replace(payuBody, `"referenceCode":"TestPayU"`, `"referenceCode":"{{secret:apiKey}}"`, 1)
	if _, perr := c.checkProxy(e); perr == nil || perr.msg != msgPlaceholder || perr.reason != "placeholder" {
		t.Errorf("listed placeholder at signer input: got %+v", perr)
	}
}

// TestCheckProxyEmptyBody: an empty body skips scanning only on an endpoint with no positions, pins
// or signer.
func TestCheckProxyEmptyBody(t *testing.T) {
	c := testCatalog(t, "127.0.0.1:9")
	ay := catEndpointByID(t, c, "adyen", "payments")
	e := validEnvelope("adyen")
	e.Request.Body = ""
	if _, perr := c.checkProxy(e); perr == nil || perr.msg != msgBadBody {
		t.Errorf("empty body with positions and pins: got %+v", perr)
	}
	ay.positions = map[string]placeholder{}
	if _, perr := c.checkProxy(e); perr == nil || perr.msg != msgBadBody {
		t.Errorf("empty body with pins: got %+v", perr)
	}
	ay.pins = map[string]catPin{}
	p, perr := c.checkProxy(e)
	if perr != nil {
		t.Fatalf("empty body, no positions/pins/signer: %+v", *perr)
	}
	if len(p.body) != 0 || len(p.occs) != 0 {
		t.Errorf("plan body/occs not empty")
	}
}

// ---------------------------------------------------------------------------
// POST /proxy and GET /healthz (§6, §9.3, §10.1, §13.1)
// ---------------------------------------------------------------------------

// fakeProvider is an httptest TLS server standing in for Stripe. It records the last request
// it received; respond (if set) writes the response, else it answers 200 {"id":"pm_123"}.
type fakeProvider struct {
	ts      *httptest.Server
	respond func(w http.ResponseWriter, r *http.Request)

	mu     sync.Mutex
	hits   int
	method string
	path   string
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
		fp.method, fp.path, fp.header, fp.body = r.Method, r.URL.Path, r.Header.Clone(), buf.Bytes()
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

// pointStripe aims the vault's stripe provider at base (copy out, set base, store back) and its
// client at a pool that trusts cert.
func pointStripe(t *testing.T, v *vault, base string, cert *x509.Certificate) {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal("bad fake provider URL")
	}
	p := v.providers["stripe"]
	p.base = u
	v.providers["stripe"] = p
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	v.client = newOutboundClient(pool)
}

// proxyVault returns a test vault whose stripe provider is the fake provider.
func proxyVault(t *testing.T, fp *fakeProvider) (*vault, *fakeStore) {
	t.Helper()
	v, s := newTestVault(t)
	pointStripe(t, v, fp.ts.URL, fp.ts.Certificate())
	return v, s
}

// seedCard seals testPAN 12/2030 under DEK 1 into the store, caches cvv if non-empty, and
// returns the token.
func seedCard(t *testing.T, v *vault, s *fakeStore, cvv string) string {
	t.Helper()
	pt, err := json.Marshal(card{PAN: testPAN, ExpMonth: "12", ExpYear: "2030"})
	if err != nil {
		t.Fatal("marshal card failed")
	}
	tok := newToken()
	s.mu.Lock()
	s.rows[tok] = fakeRow{ciphertext: seal(v.deks[1], pt), last4: "4242", keyVersion: 1}
	s.mu.Unlock()
	if cvv != "" {
		v.cvv.put(tok, cvv)
	}
	return tok
}

// proxyBody returns a /proxy JSON body.
func proxyBody(provider, op, token string, params map[string]string) string {
	m := map[string]any{"provider": provider, "op": op, "token": token}
	if params != nil {
		m["params"] = params
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic("proxyBody: marshal failed")
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

func TestProxyValidation(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := proxyVault(t, fp)
	tok := seedCard(t, v, s, testCVV)
	unseeded := "tok_" + strings.Repeat("ab", 16)
	pm := func(params map[string]string) string {
		return proxyBody("stripe", "create_payment_method", tok, params)
	}
	big := padBody(pm(nil), maxInternalBody+1)

	cases := []struct {
		name       string
		method     string // default POST
		target     string // default /proxy
		ctype      string // default application/json; omit = absent
		body       string
		idem       []string // Idempotency-Key values to add
		noCert     bool
		wantStatus int
		wantError  string
	}{
		{name: "unknown provider", body: proxyBody("adyen", "create_token", tok, nil), wantStatus: 400, wantError: msgUnknownProvider},
		{name: "provider case", body: proxyBody("Stripe", "create_token", tok, nil), wantStatus: 400, wantError: msgUnknownProvider},
		{name: "missing provider", body: `{"op":"create_token","token":"` + tok + `"}`, wantStatus: 400, wantError: msgUnknownProvider},
		{name: "unknown op", body: proxyBody("stripe", "refund", tok, nil), wantStatus: 400, wantError: msgUnknownOp},
		{name: "missing op", body: `{"provider":"stripe","token":"` + tok + `"}`, wantStatus: 400, wantError: msgUnknownOp},
		{name: "bad token", body: proxyBody("stripe", "create_token", "tok_XYZ", nil), wantStatus: 400, wantError: msgInvalidToken},
		{name: "uppercase token", body: proxyBody("stripe", "create_token", strings.ToUpper(tok), nil), wantStatus: 400, wantError: msgInvalidToken},
		{name: "missing token", body: `{"provider":"stripe","op":"create_token"}`, wantStatus: 400, wantError: msgInvalidToken},
		{name: "unseeded token", body: proxyBody("stripe", "create_token", unseeded, nil), wantStatus: 400, wantError: msgUnknownToken},
		{name: "undeclared param", body: pm(map[string]string{"amount": "1"}), wantStatus: 400, wantError: msgInvalidParams},
		{name: "param on create_token", body: proxyBody("stripe", "create_token", tok, map[string]string{"customer": "c"}), wantStatus: 400, wantError: msgInvalidParams},
		{name: "card override param", body: pm(map[string]string{"card[number]": "4000056655665556"}), wantStatus: 400, wantError: msgInvalidParams},
		{name: "customer 1025 bytes", body: pm(map[string]string{"customer": strings.Repeat("c", 1025)}), wantStatus: 400, wantError: msgInvalidParams},
		{name: "customer newline", body: pm(map[string]string{"customer": "a\nb"}), wantStatus: 400, wantError: msgInvalidParams},
		{name: "customer NUL", body: pm(map[string]string{"customer": "a\x00b"}), wantStatus: 400, wantError: msgInvalidParams},
		{name: "customer DEL", body: pm(map[string]string{"customer": "a\x7fb"}), wantStatus: 400, wantError: msgInvalidParams},
		{name: "customer C1 control", body: pm(map[string]string{"customer": "a\u0085b"}), wantStatus: 400, wantError: msgInvalidParams},
		{name: "empty customer", body: pm(map[string]string{"customer": ""}), wantStatus: 400, wantError: msgInvalidParams},
		{name: "param number", body: `{"provider":"stripe","op":"create_payment_method","token":"` + tok + `","params":{"customer":1}}`, wantStatus: 400, wantError: msgBadBody},
		{name: "params array", body: `{"provider":"stripe","op":"create_token","token":"` + tok + `","params":[]}`, wantStatus: 400, wantError: msgBadBody},
		{name: "unknown field", body: `{"provider":"stripe","op":"create_token","token":"` + tok + `","body":"x"}`, wantStatus: 400, wantError: msgBadBody},
		{name: "case-variant field", body: `{"Provider":"stripe","op":"create_token","token":"` + tok + `"}`, wantStatus: 400, wantError: msgBadBody},
		{name: "duplicate field", body: `{"provider":"adyen","provider":"stripe","op":"create_token","token":"` + tok + `"}`, wantStatus: 400, wantError: msgBadBody},
		{name: "duplicate param", body: `{"provider":"stripe","op":"create_payment_method","token":"` + tok + `","params":{"customer":"a","customer":"b"}}`, wantStatus: 400, wantError: msgBadBody},
		{name: "trailing object", body: pm(nil) + `{}`, wantStatus: 400, wantError: msgBadBody},
		{name: "not json", body: "provider=stripe", wantStatus: 400, wantError: msgBadBody},
		{name: "array body", body: `[]`, wantStatus: 400, wantError: msgBadBody},
		{name: "null body", body: `null`, wantStatus: 400, wantError: msgBadBody},
		{name: "empty body", body: "", wantStatus: 400, wantError: msgBadBody},
		{name: "body 65537", body: big, wantStatus: 413, wantError: msgTooLarge},
		{name: "text/plain", ctype: "text/plain", body: pm(nil), wantStatus: 400, wantError: msgContentType},
		{name: "missing ctype", ctype: omit, body: pm(nil), wantStatus: 400, wantError: msgContentType},
		{name: "query", target: "/proxy?x=1", body: pm(nil), wantStatus: 400, wantError: msgQuery},
		{name: "bare question mark", target: "/proxy?", body: pm(nil), wantStatus: 400, wantError: msgQuery},
		{name: "healthz query", method: "GET", target: "/healthz?x=1", wantStatus: 400, wantError: msgQuery},
		{name: "GET /proxy", method: "GET", body: pm(nil), wantStatus: 405, wantError: msgMethod},
		{name: "PUT /proxy", method: "PUT", body: pm(nil), wantStatus: 405, wantError: msgMethod},
		{name: "POST /other", target: "/other", body: pm(nil), wantStatus: 404, wantError: msgNotFound},
		{name: "POST /tokenize", target: "/tokenize", body: pm(nil), wantStatus: 404, wantError: msgNotFound},
		{name: "POST /proxy/", target: "/proxy/", body: pm(nil), wantStatus: 404, wantError: msgNotFound},
		{name: "encoded path", target: "/%70roxy", body: pm(nil), wantStatus: 404, wantError: msgNotFound},
		{name: "POST /healthz", target: "/healthz", body: pm(nil), wantStatus: 405, wantError: msgMethod},
		{name: "idempotency 256", body: pm(nil), idem: []string{strings.Repeat("k", 256)}, wantStatus: 400, wantError: msgInvalidIdempotency},
		{name: "idempotency DEL", body: pm(nil), idem: []string{"a\x7fb"}, wantStatus: 400, wantError: msgInvalidIdempotency},
		{name: "idempotency tab", body: pm(nil), idem: []string{"a\tb"}, wantStatus: 400, wantError: msgInvalidIdempotency},
		{name: "idempotency non-ASCII", body: pm(nil), idem: []string{"clé"}, wantStatus: 400, wantError: msgInvalidIdempotency},
		{name: "idempotency twice", body: pm(nil), idem: []string{"a", "b"}, wantStatus: 400, wantError: msgInvalidIdempotency},
		{name: "no client cert", body: pm(nil), noCert: true, wantStatus: 401, wantError: msgUnauthorized},
		{name: "no client cert healthz", method: "GET", target: "/healthz", noCert: true, wantStatus: 401, wantError: msgUnauthorized},

		// Check order: each case fails two checks; the earlier one wins.
		{name: "order cert>404", target: "/other", noCert: true, wantStatus: 401, wantError: msgUnauthorized},
		{name: "order 404>405", method: "PUT", target: "/x", wantStatus: 404, wantError: msgNotFound},
		{name: "order 405>query", method: "GET", target: "/proxy?x=1", wantStatus: 405, wantError: msgMethod},
		{name: "order query>ctype", target: "/proxy?x=1", ctype: "text/plain", body: pm(nil), wantStatus: 400, wantError: msgQuery},
		{name: "order ctype>size", ctype: "text/plain", body: big, wantStatus: 400, wantError: msgContentType},
		{name: "order size>shape", body: big + "x", wantStatus: 413, wantError: msgTooLarge},
		{name: "order shape>provider", body: `{"provider":"adyen","x":1}`, wantStatus: 400, wantError: msgBadBody},
		{name: "order provider>op", body: proxyBody("adyen", "refund", "x", nil), wantStatus: 400, wantError: msgUnknownProvider},
		{name: "order op>token", body: proxyBody("stripe", "refund", "x", nil), wantStatus: 400, wantError: msgUnknownOp},
		{name: "order token>params", body: proxyBody("stripe", "create_token", "x", map[string]string{"a": "b"}), wantStatus: 400, wantError: msgInvalidToken},
		{name: "order params>idempotency", body: pm(map[string]string{"a": "b"}), idem: []string{"a\x7f"}, wantStatus: 400, wantError: msgInvalidParams},
		{name: "order idempotency>store", body: proxyBody("stripe", "create_token", unseeded, nil), idem: []string{"a\x7f"}, wantStatus: 400, wantError: msgInvalidIdempotency},
	}
	for _, c := range cases {
		method, target := c.method, c.target
		if method == "" {
			method = "POST"
		}
		if target == "" {
			target = "/proxy"
		}
		r := httptest.NewRequest(method, target, strings.NewReader(c.body))
		if !c.noCert {
			withClientCert(r)
		}
		switch c.ctype {
		case "":
			r.Header.Set("Content-Type", "application/json")
		case omit:
		default:
			r.Header.Set("Content-Type", c.ctype)
		}
		for _, k := range c.idem {
			r.Header.Add("Idempotency-Key", k)
		}
		rec := serveInternal(v, r)
		if rec.Code != c.wantStatus {
			t.Errorf("%s: status %d, want %d (body len %d)", c.name, rec.Code, c.wantStatus, rec.Body.Len())
			continue
		}
		if rec.Body.String() != wantErrBody(c.wantError) {
			t.Errorf("%s: body (len %d) is not exactly the %q error body", c.name, rec.Body.Len(), c.wantError)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control not no-store", c.name)
		}
	}
	if hits, _, _, _, _ := fp.last(); hits != 0 {
		t.Fatalf("validation failures reached the provider %d times", hits)
	}
	if v.cvv.take(tok) != testCVV {
		t.Fatal("a rejected request consumed the cached CVV")
	}

	// 405 names the allowed method.
	if rec := serveInternal(v, withClientCert(httptest.NewRequest("GET", "/proxy", nil))); rec.Header().Get("Allow") != "POST" {
		t.Errorf("GET /proxy Allow %q", rec.Header().Get("Allow"))
	}
	if rec := serveInternal(v, withClientCert(httptest.NewRequest("POST", "/healthz", nil))); rec.Header().Get("Allow") != "GET" {
		t.Errorf("POST /healthz Allow %q", rec.Header().Get("Allow"))
	}

	// Boundaries that pass validation: a 1024-byte customer, a 255-char key of every printable
	// byte, a body of exactly 64 KiB, params null.
	printable := make([]byte, 0, 95)
	for b := byte(0x20); b <= 0x7e; b++ {
		printable = append(printable, b)
	}
	// HTTP trims leading/trailing spaces from header values, so the run sits inside the key.
	key := "k" + string(printable) + strings.Repeat("k", 254-len(printable))
	for i, c := range []struct {
		body string
		idem string
	}{
		{pm(map[string]string{"customer": strings.Repeat("c", 1024)}), ""},
		{pm(map[string]string{"customer": "cus_ü"}), key},
		{padBody(pm(nil), maxInternalBody), ""},
		{`{"provider":"stripe","op":"create_token","token":"` + tok + `","params":null}`, ""},
		{pm(map[string]string{}), ""},
	} {
		r := newProxyRequest(c.body)
		if c.idem != "" {
			r.Header.Set("Idempotency-Key", c.idem)
		}
		before, _, _, _, _ := fp.last()
		rec := serveInternal(v, r)
		after, _, _, hdr, _ := fp.last()
		if rec.Code != http.StatusOK || after != before+1 {
			t.Errorf("boundary case %d: status %d, provider hits +%d", i, rec.Code, after-before)
			continue
		}
		if c.idem != "" && hdr.Get("Idempotency-Key") != c.idem {
			t.Errorf("boundary case %d: Idempotency-Key not forwarded unchanged", i)
		}
	}

	// Two Content-Type headers are ambiguous and rejected.
	r := newProxyRequest(pm(nil))
	r.Header.Add("Content-Type", "application/json")
	if rec := serveInternal(v, r); rec.Code != http.StatusBadRequest || rec.Body.String() != wantErrBody(msgContentType) {
		t.Errorf("two Content-Type headers: status %d", rec.Code)
	}
}

func TestProxyCreatePaymentMethod(t *testing.T) {
	fp := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Provider-Header", "x")
		w.Header().Set("Set-Cookie", "provider=1")
		w.Write([]byte(`{"id":"pm_123"}`))
	})
	v, s := proxyVault(t, fp)
	tok := seedCard(t, v, s, testCVV)

	send := func() *httptest.ResponseRecorder {
		r := newProxyRequest(proxyBody("stripe", "create_payment_method", tok, map[string]string{"customer": "cus_123"}))
		r.Header.Set("Authorization", "Bearer sk_test_attacker")
		r.Header.Set("Idempotency-Key", "idem-1")
		r.Header.Set("Cookie", "a=b")
		r.Header.Set("X-Forwarded-For", "1.2.3.4")
		r.Header.Set("User-Agent", "platform/9")
		return serveInternal(v, r)
	}

	start := testLog.Len()
	rec := send()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (body len %d)", rec.Code, rec.Body.Len())
	}
	hits, method, path, hdr, body := fp.last()
	if hits != 1 || method != "POST" || path != "/v1/payment_methods" {
		t.Fatalf("outbound: hits %d, %s %s", hits, method, path)
	}
	const want = "card%5Bcvc%5D=9071&card%5Bexp_month%5D=12&card%5Bexp_year%5D=2030&card%5Bnumber%5D=4242424242424242&customer=cus_123&type=card"
	if string(body) != want {
		t.Errorf("outbound body mismatch (card values redacted)\n got  %s\n want %s", redactBody(body), redactBody([]byte(want)))
	}
	if got := hdr.Values("Authorization"); len(got) != 1 || got[0] != "Bearer "+testSecret {
		t.Errorf("outbound Authorization is not exactly the vault credential (%d values)", len(got)) // never print it
	}
	if hdr.Get("Idempotency-Key") != "idem-1" || hdr.Get("User-Agent") != "pan-vault/1" ||
		hdr.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Error("outbound Idempotency-Key, User-Agent or Content-Type wrong")
	}
	allowed := map[string]bool{"Authorization": true, "Content-Type": true, "Idempotency-Key": true,
		"User-Agent": true, "Content-Length": true, "Accept-Encoding": true}
	for k := range hdr {
		if !allowed[k] {
			t.Errorf("unexpected outbound header %q", k) // name only, never the value
		}
	}
	if s.lastCaller != "0A1B2C" {
		t.Errorf("getCard caller %q, want 0A1B2C", s.lastCaller)
	}

	if rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("response Content-Type or Cache-Control wrong")
	}
	if rec.Header().Get("X-Provider-Header") != "" || rec.Header().Get("Set-Cookie") != "" {
		t.Error("provider response headers forwarded")
	}
	if rec.Body.String() != `{"id":"pm_123"}` {
		t.Errorf("response body len %d is not the provider body", rec.Body.Len())
	}
	out := testLog.since(start)
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, " path=/proxy status=200 ") || !strings.HasSuffix(out, " caller=0A1B2C\n") {
		t.Errorf("success log unexpected (len %d, %d lines)", len(out), strings.Count(out, "\n"))
	}

	// Second call: the CVV was single use.
	if rec := send(); rec.Code != http.StatusOK {
		t.Fatalf("second call status %d", rec.Code)
	}
	_, _, _, _, body = fp.last()
	if bytes.Contains(body, []byte("card%5Bcvc%5D")) || bytes.Contains(body, []byte(testCVV)) {
		t.Error("second call sent a CVV")
	}
	if !bytes.Contains(body, []byte("card%5Bnumber%5D=")) {
		t.Error("second call lacks the card number")
	}
}

func TestProxyCreateToken(t *testing.T) {
	fp := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		w.Write([]byte(`card_declined`))
	})
	v, s := proxyVault(t, fp)
	tok := seedCard(t, v, s, "")
	rec := serveInternal(v, newProxyRequest(proxyBody("stripe", "create_token", tok, nil)))
	_, method, path, hdr, body := fp.last()
	if method != "POST" || path != "/v1/tokens" {
		t.Fatalf("outbound %s %s", method, path)
	}
	const want = "card%5Bexp_month%5D=12&card%5Bexp_year%5D=2030&card%5Bnumber%5D=4242424242424242"
	if string(body) != want {
		t.Errorf("outbound body mismatch (card values redacted)\n got  %s\n want %s", redactBody(body), redactBody([]byte(want)))
	}
	if hdr.Get("Idempotency-Key") != "" {
		t.Error("Idempotency-Key sent although none was given")
	}
	// The provider's status is passed through; Go sniffs a Content-Type for it, which is forwarded.
	if rec.Code != http.StatusPaymentRequired || rec.Body.String() != "card_declined" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("status %d, body len %d", rec.Code, rec.Body.Len())
	}

	// A provider response with no Content-Type gets none from the vault either.
	fp.respond = func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Content-Type"] = nil // suppress sniffing
		w.Write([]byte(`ok`))
	}
	rec = serveInternal(v, newProxyRequest(proxyBody("stripe", "create_token", tok, nil)))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "" {
		t.Errorf("no Content-Type case: status %d, Content-Type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestProxyVelocity(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := proxyVault(t, fp)
	tok := seedCard(t, v, s, testCVV)
	s.velocity = true
	start := testLog.Len()
	rec := serveInternal(v, newProxyRequest(proxyBody("stripe", "create_token", tok, nil)))
	if rec.Code != http.StatusTooManyRequests || rec.Body.String() != wantErrBody(msgVelocity) {
		t.Fatalf("status %d, body len %d, want 429 velocity", rec.Code, rec.Body.Len())
	}
	if !strings.Contains(testLog.since(start), " ALERT velocity token="+tok+" caller=0A1B2C\n") {
		t.Fatal("no ALERT velocity line with token and caller")
	}
	if hits, _, _, _, _ := fp.last(); hits != 0 || s.lastCaller != "0A1B2C" {
		t.Fatalf("hits %d, caller %q", hits, s.lastCaller)
	}
	if v.cvv.take(tok) != testCVV {
		t.Fatal("a velocity-limited request consumed the CVV")
	}
}

func TestProxyStoreError(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := proxyVault(t, fp)
	tok := seedCard(t, v, s, "")
	const marker = "store-error-marker-91ab"
	s.getErr = errors.New(marker)
	start := testLog.Len()
	rec := serveInternal(v, newProxyRequest(proxyBody("stripe", "create_token", tok, nil)))
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != wantErrBody(msgInternal) {
		t.Fatalf("status %d, body len %d, want 500 internal", rec.Code, rec.Body.Len())
	}
	if out := testLog.since(start); strings.Contains(out, marker) || strings.Contains(out, "ALERT") || strings.Count(out, "\n") != 1 {
		t.Fatalf("store error log unexpected (len %d, %d lines)", len(out), strings.Count(out, "\n"))
	}
	if hits, _, _, _, _ := fp.last(); hits != 0 {
		t.Fatal("store error reached the provider")
	}

	// A wrapped velocity/unknown error is still recognized.
	s.getErr = nil
	s.velocity = false
	v.getCard = func(context.Context, string, string) ([]byte, int, error) {
		return nil, 0, fmt.Errorf("wrapped: %w", errUnknownToken)
	}
	if rec := serveInternal(v, newProxyRequest(proxyBody("stripe", "create_token", tok, nil))); rec.Body.String() != wantErrBody(msgUnknownToken) {
		t.Fatalf("wrapped errUnknownToken: status %d", rec.Code)
	}
}

func TestProxyDecryptFailed(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := proxyVault(t, fp)
	tok := seedCard(t, v, s, testCVV)
	row := s.rows[tok]
	row.ciphertext[len(row.ciphertext)-1] ^= 0x01
	start := testLog.Len()
	rec := serveInternal(v, newProxyRequest(proxyBody("stripe", "create_token", tok, nil)))
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != wantErrBody(msgInternal) {
		t.Fatalf("status %d, body len %d, want 500 internal", rec.Code, rec.Body.Len())
	}
	if !strings.Contains(testLog.since(start), " ALERT decrypt_failed token="+tok+" key_version=1\n") {
		t.Fatal("no ALERT decrypt_failed line")
	}

	// A row whose key version has no loaded DEK is a decrypt failure too.
	tok2 := seedCard(t, v, s, "")
	row = s.rows[tok2]
	row.keyVersion = 9
	s.rows[tok2] = row
	start = testLog.Len()
	rec = serveInternal(v, newProxyRequest(proxyBody("stripe", "create_token", tok2, nil)))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(testLog.since(start), " ALERT decrypt_failed token="+tok2+" key_version=9\n") {
		t.Fatalf("missing DEK: status %d, or no alert", rec.Code)
	}

	// Authentic ciphertext whose plaintext is not a card record is a decrypt failure too.
	tok3 := newToken()
	s.rows[tok3] = fakeRow{ciphertext: seal(v.deks[1], []byte("not json")), last4: "0000", keyVersion: 1}
	start = testLog.Len()
	rec = serveInternal(v, newProxyRequest(proxyBody("stripe", "create_token", tok3, nil)))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(testLog.since(start), " ALERT decrypt_failed token="+tok3+" key_version=1\n") {
		t.Fatalf("bad plaintext: status %d, or no alert", rec.Code)
	}

	if hits, _, _, _, _ := fp.last(); hits != 0 {
		t.Fatal("decrypt failure reached the provider")
	}
}

func TestProxyEgressInvariant(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := proxyVault(t, fp)
	tok := seedCard(t, v, s, "")
	p := v.providers["stripe"]
	p.base = &url.URL{Scheme: "http", Host: strings.TrimPrefix(fp.ts.URL, "https://")}
	v.providers["stripe"] = p
	start := testLog.Len()
	rec := serveInternal(v, newProxyRequest(proxyBody("stripe", "create_token", tok, nil)))
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != wantErrBody(msgInternal) {
		t.Fatalf("status %d, body len %d, want 500 internal", rec.Code, rec.Body.Len())
	}
	if !strings.Contains(testLog.since(start), " ALERT egress_invariant provider=stripe\n") {
		t.Fatal("no ALERT egress_invariant line")
	}
	if hits, _, _, _, _ := fp.last(); hits != 0 {
		t.Fatal("egress invariant failure reached the provider")
	}
}

func TestProxyRedirectNotFollowed(t *testing.T) {
	var landed sync.Mutex
	landedHit := false
	fp := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/landed" {
			landed.Lock()
			landedHit = true
			landed.Unlock()
			return
		}
		w.Header().Set("Location", "/landed")
		w.WriteHeader(http.StatusFound)
	})
	v, s := proxyVault(t, fp)
	tok := seedCard(t, v, s, "")
	rec := serveInternal(v, newProxyRequest(proxyBody("stripe", "create_token", tok, nil)))
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, want 302 passed through", rec.Code)
	}
	landed.Lock()
	defer landed.Unlock()
	if landedHit {
		t.Fatal("redirect was followed")
	}
	if rec.Header().Get("Location") != "" {
		t.Fatal("Location header forwarded")
	}
}

func TestProxyPANEchoMasked(t *testing.T) {
	fp := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"number":"4242424242424242","f":"4242 4242 4242 4242","h":"4242-4242-4242-4242"}`))
	})
	v, s := proxyVault(t, fp)
	tok := seedCard(t, v, s, "")
	start := testLog.Len()
	rec := serveInternal(v, newProxyRequest(proxyBody("stripe", "create_token", tok, nil)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Body.String(); got != `{"number":"****4242","f":"****4242","h":"****4242"}` {
		t.Fatalf("body not masked as expected (len %d, has PAN %v)", len(got), len(luhnWindowOffsets(joinDigitSeparators(got))) > 0)
	}
	out := testLog.since(start)
	if !strings.Contains(out, " ALERT pan_echo provider=stripe op=create_token token="+tok+"\n") {
		t.Fatal("no ALERT pan_echo line")
	}
	if strings.Count(out, "ALERT") != 1 {
		t.Fatalf("%d ALERT lines, want 1", strings.Count(out, "ALERT"))
	}

	// A clean response raises no alert.
	fp.respond = nil
	start = testLog.Len()
	serveInternal(v, newProxyRequest(proxyBody("stripe", "create_token", tok, nil)))
	if strings.Contains(testLog.since(start), "ALERT") {
		t.Fatal("clean response raised an alert")
	}
}

// The transport asks for gzip itself and decompresses transparently, so maskPAN sees the
// decompressed bytes. Any Content-Encoding still present on the response means the body arrived
// encoded (and could hide a PAN from maskPAN): 502.
func TestProxyContentEncoding(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(`{"number":"4242424242424242"}`))
	zw.Close()
	var enc, payload atomic.Value
	fp := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", enc.Load().(string))
		w.Write(payload.Load().([]byte))
	})
	v, s := proxyVault(t, fp)
	tok := seedCard(t, v, s, "")

	// Valid gzip: decompressed by the transport, then masked.
	enc.Store("gzip")
	payload.Store(gz.Bytes())
	start := testLog.Len()
	rec := serveInternal(v, newProxyRequest(proxyBody("stripe", "create_token", tok, nil)))
	if rec.Code != http.StatusOK || rec.Body.String() != `{"number":"****4242"}` || rec.Header().Get("Content-Encoding") != "" {
		t.Fatalf("gzip: status %d, body len %d", rec.Code, rec.Body.Len())
	}
	if !strings.Contains(testLog.since(start), "ALERT pan_echo") {
		t.Fatal("gzip: no pan_echo alert")
	}
	if _, _, _, hdr, _ := fp.last(); hdr.Get("Accept-Encoding") != "gzip" {
		t.Fatal("transport did not request gzip itself")
	}

	for i, c := range []struct {
		enc  string
		body []byte
	}{
		{"gzip", []byte(`{"number":"4242424242424242"}`)}, // claims gzip, is not: read error
		{"br", gz.Bytes()},
		{"deflate", gz.Bytes()},
		{"identity", []byte(`{"number":"4242424242424242"}`)},
		{"gzip, gzip", gz.Bytes()},
	} {
		enc.Store(c.enc)
		payload.Store(c.body)
		rec := serveInternal(v, newProxyRequest(proxyBody("stripe", "create_token", tok, nil)))
		if rec.Code != http.StatusBadGateway || rec.Body.String() != wantErrBody(msgProvider) {
			t.Errorf("encoding case %d: status %d, body len %d, want 502", i, rec.Code, rec.Body.Len())
		}
	}
}

func TestProxyProviderUnreachable(t *testing.T) {
	closed := httptest.NewTLSServer(http.NotFoundHandler())
	closedURL, cert := closed.URL, closed.Certificate()
	closed.Close()
	v, s := newTestVault(t)
	pointStripe(t, v, closedURL, cert)
	tok := seedCard(t, v, s, "")
	start := testLog.Len()
	rec := serveInternal(v, newProxyRequest(proxyBody("stripe", "create_token", tok, nil)))
	if rec.Code != http.StatusBadGateway || rec.Body.String() != `{"error":"provider unreachable"}`+"\n" {
		t.Fatalf("status %d, body len %d, want 502 provider unreachable", rec.Code, rec.Body.Len())
	}
	if out := testLog.since(start); strings.Count(out, "\n") != 1 || strings.Contains(out, "127.0.0.1") {
		t.Fatalf("unreachable log unexpected (len %d, %d lines)", len(out), strings.Count(out, "\n"))
	}

	// A provider whose certificate is not trusted is unreachable too (TLS is verified). (All
	// httptest servers share one certificate, so trust nothing at all here.)
	fp := newFakeProvider(t, nil)
	pointStripe(t, v, fp.ts.URL, cert)
	v.client = newOutboundClient(x509.NewCertPool())
	if rec := serveInternal(v, newProxyRequest(proxyBody("stripe", "create_token", tok, nil))); rec.Code != http.StatusBadGateway {
		t.Fatalf("untrusted cert: status %d, want 502", rec.Code)
	}
}

func TestProxyOversizeProviderResponse(t *testing.T) {
	var size atomic.Int64
	fp := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		n := int(size.Load())
		b := bytes.Repeat([]byte("x"), n)
		copy(b[n-len(testPAN)-10:], testPAN)
		w.Header().Set("Content-Type", "text/plain")
		w.Write(b)
	})
	v, s := proxyVault(t, fp)
	tok := seedCard(t, v, s, "")

	size.Store(maxProviderResponse + 1)
	rec := serveInternal(v, newProxyRequest(proxyBody("stripe", "create_token", tok, nil)))
	if rec.Code != http.StatusBadGateway || rec.Body.String() != wantErrBody(msgProvider) {
		t.Fatalf("status %d, body len %d, want 502", rec.Code, rec.Body.Len())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(testPAN)) {
		t.Fatal("oversize response leaked the PAN")
	}

	// Exactly 4 MiB is accepted and masked, PAN near the end included.
	size.Store(maxProviderResponse)
	rec = serveInternal(v, newProxyRequest(proxyBody("stripe", "create_token", tok, nil)))
	if rec.Code != http.StatusOK || bytes.Contains(rec.Body.Bytes(), []byte(testPAN)) ||
		!bytes.Contains(rec.Body.Bytes(), []byte("****4242")) {
		t.Fatalf("4 MiB response: status %d, body len %d", rec.Code, rec.Body.Len())
	}
}

func TestHealthz(t *testing.T) {
	v, _ := newTestVault(t)
	var (
		mu       sync.Mutex
		deadline time.Time
		hasDL    bool
	)
	var pingErr error
	v.ping = func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		deadline, hasDL = ctx.Deadline()
		return pingErr
	}
	get := func() *httptest.ResponseRecorder {
		return serveInternal(v, withClientCert(httptest.NewRequest("GET", "/healthz", nil)))
	}

	before := time.Now()
	rec := get()
	if rec.Code != http.StatusOK || rec.Body.String() != `{"status":"ok"}`+"\n" {
		t.Fatalf("healthy: status %d, body len %d", rec.Code, rec.Body.Len())
	}
	if rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("healthz headers wrong")
	}
	mu.Lock()
	if !hasDL || deadline.After(before.Add(2*time.Second+50*time.Millisecond)) || deadline.Before(before.Add(time.Second)) {
		t.Errorf("ping deadline present=%v, %v from request start, want ≤ 2s", hasDL, deadline.Sub(before))
	}
	mu.Unlock()

	const marker = "ping-failure-marker-3c0d"
	pingErr = errors.New(marker)
	start := testLog.Len()
	rec = get()
	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != wantErrBody(msgUnavailable) {
		t.Fatalf("unhealthy: status %d, body len %d", rec.Code, rec.Body.Len())
	}
	if out := testLog.since(start); strings.Contains(out, marker) || !strings.Contains(out, " path=/healthz status=503 ") {
		t.Fatalf("unhealthy log unexpected (len %d)", len(out))
	}
}

// ---------------------------------------------------------------------------
// Integration tests (SPEC §13.2). Gated on VAULT_TEST_DB_URL; run with `make itest`.
// Tests may name tables (they check privileges and count audit rows as the owner); main.go never does.
// ---------------------------------------------------------------------------

// integrationDB connects to the test database. role "" connects as the URL's user (vault_owner);
// otherwise the URL's user is replaced with role (the test server uses trust auth).
func integrationDB(t *testing.T, role string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", integrationURL(t, role))
	if err != nil {
		t.Fatalf("open as %q: %v", role, err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// integrationURL returns VAULT_TEST_DB_URL, with the user replaced by role unless role is "", or
// skips the test when it is not set.
func integrationURL(t *testing.T, role string) string {
	t.Helper()
	raw := os.Getenv("VAULT_TEST_DB_URL")
	if raw == "" {
		t.Skip("VAULT_TEST_DB_URL not set")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal("VAULT_TEST_DB_URL does not parse")
	}
	if role != "" {
		u.User = url.User(role)
	}
	return u.String()
}

func wantPermissionDenied(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("%s: err = %v, want permission denied", what, err)
	}
}

func TestIntegrationPrivileges(t *testing.T) {
	ctx := context.Background()
	app := integrationDB(t, "vault_app")

	_, err := app.ExecContext(ctx, "SELECT * FROM vault.cards")
	wantPermissionDenied(t, "app SELECT cards", err)
	_, err = app.ExecContext(ctx, `INSERT INTO vault.cards VALUES ($1, '\x01', '4242', 1)`, newToken())
	wantPermissionDenied(t, "app INSERT cards", err)
	_, err = app.ExecContext(ctx, `SELECT vault.add_dek('\x00')`)
	wantPermissionDenied(t, "app add_dek", err)
	_, err = app.ExecContext(ctx, "SELECT * FROM vault.access_log")
	wantPermissionDenied(t, "app SELECT access_log", err)
	_, err = app.ExecContext(ctx, "SELECT * FROM vault.deks")
	wantPermissionDenied(t, "app SELECT deks", err)

	tok := newToken()
	if err := dbPutCard(ctx, app, tok, []byte{1, 2, 3}, "4242", 1); err != nil {
		t.Fatalf("app put_card: %v", err)
	}
	ct, kv, err := dbGetCard(ctx, app, tok, "0A1B2C")
	if err != nil || !bytes.Equal(ct, []byte{1, 2, 3}) || kv != 1 {
		t.Fatalf("app get_card: ct=%x kv=%d err=%v", ct, kv, err)
	}
	if _, _, err := dbGetCard(ctx, app, newToken(), "0A1B2C"); !errors.Is(err, errUnknownToken) {
		t.Errorf("app get_card unseeded: err = %v, want errUnknownToken", err)
	}
	if _, err := dbListDEKs(ctx, app); err != nil {
		t.Errorf("app list_deks: %v", err)
	}

	rot := integrationDB(t, "vault_rotator")
	// 32 bytes: Task 9's fake KMS reverses bytes and loadDEKs requires a 32-byte DEK for every row.
	wrapped := bytes.Repeat([]byte{0x07}, 32)
	v, err := dbAddDEK(ctx, rot, wrapped)
	if err != nil || v <= 0 {
		t.Fatalf("rotator add_dek: v=%d err=%v", v, err)
	}
	// 42501 = insufficient_privilege.
	if err := dbPutCard(ctx, rot, newToken(), []byte{1}, "4242", 1); err == nil || !strings.Contains(err.Error(), "42501") {
		t.Errorf("rotator put_card: err = %v, want sqlstate 42501", err)
	}
	if _, _, err := dbGetCard(ctx, rot, tok, "0A1B2C"); err == nil || !strings.Contains(err.Error(), "42501") {
		t.Errorf("rotator get_card: err = %v, want sqlstate 42501", err)
	}
	_, err = rot.ExecContext(ctx, "SELECT * FROM vault.deks")
	wantPermissionDenied(t, "rotator SELECT deks", err)
	deks, err := dbListDEKs(ctx, rot)
	if err != nil {
		t.Fatalf("rotator list_deks: %v", err)
	}
	if !bytes.Equal(deks[v], wrapped) {
		t.Errorf("list_deks[%d] = %x, want the wrapped value just added", v, deks[v])
	}
}

func countRows(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count query: %v", err)
	}
	return n
}

func TestIntegrationAccessLogCount(t *testing.T) {
	ctx := context.Background()
	owner := integrationDB(t, "")
	app := integrationDB(t, "vault_app")

	n0 := countRows(t, owner, "SELECT count(*) FROM vault.access_log")
	var toks []string
	for range 3 {
		tok := newToken()
		toks = append(toks, tok)
		if err := dbPutCard(ctx, app, tok, []byte{9}, "1111", 1); err != nil {
			t.Fatalf("put_card: %v", err)
		}
	}
	for _, tok := range toks[:2] {
		if _, _, err := dbGetCard(ctx, app, tok, "0A"); err != nil {
			t.Fatalf("get_card: %v", err)
		}
	}
	if n := countRows(t, owner, "SELECT count(*) FROM vault.access_log"); n != n0+5 {
		t.Errorf("access_log rows = %d, want %d", n, n0+5)
	}
	if n := countRows(t, owner, "SELECT count(*) FROM vault.access_log WHERE token = ANY($1) AND op = 'put' AND caller IS NULL", toks); n != 3 {
		t.Errorf("put rows = %d, want 3", n)
	}
	if n := countRows(t, owner, "SELECT count(*) FROM vault.access_log WHERE token = ANY($1) AND op = 'get' AND caller = '0A'", toks); n != 2 {
		t.Errorf("get rows = %d, want 2", n)
	}
}

func TestIntegrationSearchPathPinned(t *testing.T) {
	owner := integrationDB(t, "")
	rows, err := owner.QueryContext(context.Background(), `
		SELECT p.proname, coalesce(array_to_string(p.proconfig, E'\n'), '')
		  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		 WHERE n.nspname = 'vault'`)
	if err != nil {
		t.Fatalf("query pg_proc: %v", err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var name, config string
		if err := rows.Scan(&name, &config); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[name] = true
		if !slices.Contains(strings.Split(config, "\n"), "search_path=vault, pg_temp") {
			t.Errorf("%s proconfig = %q, want search_path=vault, pg_temp", name, config)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	want := map[string]bool{"put_card": true, "get_card": true, "list_deks": true, "add_dek": true}
	if !maps.Equal(got, want) {
		t.Errorf("vault functions = %v, want %v", slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(want)))
	}
}

func TestIntegrationVelocityPerToken(t *testing.T) {
	ctx := context.Background()
	app := integrationDB(t, "vault_app")
	tok := newToken()
	if err := dbPutCard(ctx, app, tok, []byte{5}, "4242", 1); err != nil {
		t.Fatalf("put_card: %v", err)
	}
	for i := range 20 {
		if _, _, err := dbGetCard(ctx, app, tok, "0A"); err != nil {
			t.Fatalf("get %d: %v", i+1, err)
		}
	}
	if _, _, err := dbGetCard(ctx, app, tok, "0A"); !errors.Is(err, errVelocity) {
		t.Errorf("get 21: err = %v, want errVelocity", err)
	}
}

func TestIntegrationVelocityConcurrent(t *testing.T) {
	ctx := context.Background()
	owner := integrationDB(t, "")
	app := integrationDB(t, "vault_app")
	app.SetMaxOpenConns(64)
	tok := newToken()
	if err := dbPutCard(ctx, app, tok, []byte{6}, "4242", 1); err != nil {
		t.Fatalf("put_card: %v", err)
	}

	const calls = 50
	start := make(chan struct{})
	var wg sync.WaitGroup
	var ok, velocity, other atomic.Int32
	for range calls {
		wg.Go(func() {
			<-start
			_, _, err := dbGetCard(ctx, app, tok, "0A")
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, errVelocity):
				velocity.Add(1)
			default:
				other.Add(1)
				t.Errorf("concurrent get: %v", err)
			}
		})
	}
	close(start)
	wg.Wait()
	if ok.Load() != 20 || velocity.Load() != calls-20 || other.Load() != 0 {
		t.Errorf("concurrent gets: %d ok, %d velocity, %d other; want 20, %d, 0", ok.Load(), velocity.Load(), other.Load(), calls-20)
	}
	if n := countRows(t, owner, "SELECT count(*) FROM vault.access_log WHERE token = $1 AND op = 'get'", tok); n != 20 {
		t.Errorf("get rows for token = %d, want 20", n)
	}
}

func TestIntegrationVelocityGlobal(t *testing.T) {
	ctx := context.Background()
	owner := integrationDB(t, "")
	app := integrationDB(t, "vault_app")

	var used []string
	t.Cleanup(func() {
		// Test DB only: remove this test's lookups so later tests in the same minute aren't throttled.
		if _, err := owner.ExecContext(context.Background(), "DELETE FROM vault.access_log WHERE token = ANY($1)", used); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	n := countRows(t, owner, "SELECT count(*) FROM vault.access_log WHERE op = 'get' AND at > now() - interval '1 minute'")
	if n >= 300 {
		t.Fatalf("%d recent gets already; cannot run", n)
	}
	for i := range 300 - n {
		tok := newToken()
		used = append(used, tok)
		if _, _, err := dbGetCard(ctx, app, tok, "0A"); err != nil && !errors.Is(err, errUnknownToken) {
			t.Fatalf("get %d of %d: %v", i+1, 300-n, err)
		}
	}
	tok := newToken()
	used = append(used, tok)
	if _, _, err := dbGetCard(ctx, app, tok, "0A"); !errors.Is(err, errVelocity) {
		t.Errorf("get past the global limit: err = %v, want errVelocity", err)
	}
}

// ---------------------------------------------------------------------------
// Boot: config, GCP REST access, secrets, DB pool, client CA, servers (SPEC §8.2–§8.6, §11)
// These tests replace package-level base URLs and must not call t.Parallel.
// ---------------------------------------------------------------------------

const (
	testKMSKey     = "projects/p1/locations/global/keyRings/r1/cryptoKeys/k1"
	testHMACName   = "projects/p1/secrets/session-hmac"
	testStripeName = "projects/p1/secrets/stripe-key"
	testGCPToken   = "ya29.fake-access-token"
)

// pointURL sets *p to v for the duration of the test.
func pointURL(t *testing.T, p *string, v string) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

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
		"VAULT_DEV_STRIPE_SECRET":    testSecret,
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
		"VAULT_STRIPE_SECRET":       testStripeName,
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
		{"dev SM instead of dev secrets", envWith(testDevEnv(), map[string]string{"VAULT_DEV_SESSION_HMAC_HEX": omit, "VAULT_SESSION_HMAC_SECRET": testHMACName, "VAULT_DEV_STRIPE_SECRET": omit, "VAULT_STRIPE_SECRET": testStripeName}), false, ""},
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
		{"prod missing VAULT_STRIPE_SECRET", envWith(testProdEnv(), map[string]string{"VAULT_STRIPE_SECRET": omit}), false, "VAULT_STRIPE_SECRET"},
		{"prod + VAULT_DEV_DEK_HEX", envWith(testProdEnv(), map[string]string{"VAULT_DEV_DEK_HEX": strings.Repeat("ab", 32)}), false, "VAULT_DEV_DEK_HEX"},
		{"prod + VAULT_DEV_SESSION_HMAC_HEX", envWith(testProdEnv(), map[string]string{"VAULT_DEV_SESSION_HMAC_HEX": strings.Repeat("cd", 32)}), false, "VAULT_DEV_SESSION_HMAC_HEX"},
		{"prod + VAULT_DEV_STRIPE_SECRET", envWith(testProdEnv(), map[string]string{"VAULT_DEV_STRIPE_SECRET": testSecret}), false, "VAULT_DEV_STRIPE_SECRET"},
		{"dev DEK 63 hex", envWith(testDevEnv(), map[string]string{"VAULT_DEV_DEK_HEX": strings.Repeat("ab", 31) + "a"}), false, "VAULT_DEV_DEK_HEX"},
		{"dev DEK 66 hex", envWith(testDevEnv(), map[string]string{"VAULT_DEV_DEK_HEX": strings.Repeat("ab", 33)}), false, "VAULT_DEV_DEK_HEX"},
		{"dev DEK not hex", envWith(testDevEnv(), map[string]string{"VAULT_DEV_DEK_HEX": strings.Repeat("zq", 32)}), false, "VAULT_DEV_DEK_HEX"},
		{"dev HMAC 63 hex", envWith(testDevEnv(), map[string]string{"VAULT_DEV_SESSION_HMAC_HEX": strings.Repeat("cd", 31) + "c"}), false, "VAULT_DEV_SESSION_HMAC_HEX"},
		{"dev no DEK source", envWith(testDevEnv(), map[string]string{"VAULT_DEV_DEK_HEX": omit}), false, "VAULT_KMS_KEY"},
		{"dev no HMAC source", envWith(testDevEnv(), map[string]string{"VAULT_DEV_SESSION_HMAC_HEX": omit}), false, "VAULT_SESSION_HMAC_SECRET"},
		{"dev no Stripe source", envWith(testDevEnv(), map[string]string{"VAULT_DEV_STRIPE_SECRET": omit}), false, "VAULT_STRIPE_SECRET"},
		{"KMS key bad shape", envWith(testProdEnv(), map[string]string{"VAULT_KMS_KEY": "projects/p1/locations/global/keyRings/r1/cryptoKeys/../k1"}), false, "VAULT_KMS_KEY"},
		{"KMS key with query", envWith(testProdEnv(), map[string]string{"VAULT_KMS_KEY": testKMSKey + "?x=1"}), false, "VAULT_KMS_KEY"},
		{"HMAC secret bad shape", envWith(testProdEnv(), map[string]string{"VAULT_SESSION_HMAC_SECRET": "projects/p1/secrets/s/versions/3"}), false, "VAULT_SESSION_HMAC_SECRET"},
		{"Stripe secret bad shape", envWith(testProdEnv(), map[string]string{"VAULT_STRIPE_SECRET": "https://evil.example/x"}), false, "VAULT_STRIPE_SECRET"},
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
	if !bytes.Equal(cfg.devDEK, bytes.Repeat([]byte{0xab}, 32)) || !bytes.Equal(cfg.devHMAC, bytes.Repeat([]byte{0xcd}, 32)) ||
		cfg.devStripeSecret != testSecret {
		t.Error("dev secrets not decoded")
	}
	cfg, err = loadConfig(func(k string) string { return testProdEnv()[k] }, false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.env != "prod" || cfg.kmsKey != testKMSKey || cfg.hmacSecretName != testHMACName ||
		cfg.stripeSecretName != testStripeName || cfg.devDEK != nil || cfg.devHMAC != nil || cfg.devStripeSecret != "" {
		t.Error("prod config fields wrong")
	}
	cfg, err = loadConfig(func(k string) string { return rotEnv[k] }, true)
	if err != nil || cfg.env != "prod" || cfg.kmsKey != testKMSKey || cfg.dbURL != rotEnv["VAULT_DB_URL"] {
		t.Error("rotate config fields wrong")
	}
}

// TestValidOrigin covers the serialized-origin shape check (§5.3). An origin carrying its
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

	// Dev values: no network at all (nil client and token source).
	cfg := config{env: "dev", devHMAC: hmacKey, devStripeSecret: testSecret}
	k, s, err := loadSecrets(ctx, cfg, nil, nil)
	if err != nil || !bytes.Equal(k, hmacKey) || s != testSecret {
		t.Fatalf("dev secrets wrong: %v", err)
	}
	for name, cfg := range map[string]config{
		"stripe trailing newline": {env: "dev", devHMAC: hmacKey, devStripeSecret: "sk_test_x\n"},
		"stripe inner space":      {env: "dev", devHMAC: hmacKey, devStripeSecret: "sk_test x"},
		"stripe control char":     {env: "dev", devHMAC: hmacKey, devStripeSecret: "sk_test_\x01x"},
		"HMAC 31 bytes":           {env: "dev", devHMAC: hmacKey[:31], devStripeSecret: testSecret},
		"prod with dev HMAC":      {env: "prod", devHMAC: hmacKey, devStripeSecret: testSecret, hmacSecretName: testHMACName, stripeSecretName: testStripeName},
	} {
		if _, _, err := loadSecrets(ctx, cfg, nil, nil); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "sk_test") {
			t.Errorf("%s: error contains the secret", name)
		}
	}

	// Secret Manager path.
	newFakeMetadata(t, nil)
	c := newOutboundClient(nil)
	prod := config{env: "prod", hmacSecretName: testHMACName, stripeSecretName: testStripeName}
	newFakeSecretManager(t, map[string]string{testHMACName: hex.EncodeToString(hmacKey), testStripeName: testSecret}, false)
	k, s, err = loadSecrets(ctx, prod, c, &tokenSource{client: c})
	if err != nil || !bytes.Equal(k, hmacKey) || s != testSecret {
		t.Fatalf("Secret Manager secrets wrong: %v", err)
	}
	for name, sm := range map[string]map[string]string{
		"HMAC trailing newline": {testHMACName: hex.EncodeToString(hmacKey) + "\n", testStripeName: testSecret},
		"HMAC 62 hex":           {testHMACName: hex.EncodeToString(hmacKey[:31]), testStripeName: testSecret},
		"HMAC not hex":          {testHMACName: strings.Repeat("zz", 32), testStripeName: testSecret},
		"stripe with space":     {testHMACName: hex.EncodeToString(hmacKey), testStripeName: testSecret + " "},
		"stripe empty":          {testHMACName: hex.EncodeToString(hmacKey), testStripeName: ""},
		"stripe missing":        {testHMACName: hex.EncodeToString(hmacKey)},
	} {
		newFakeSecretManager(t, sm, false)
		if _, _, err := loadSecrets(ctx, prod, c, &tokenSource{client: c}); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), testSecret) || strings.Contains(err.Error(), hex.EncodeToString(hmacKey)) {
			t.Errorf("%s: error contains secret material", name)
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

	// §14: no configuration from files. service/servicefile/passfile would make pgx read
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
	v := newVault(config{env: "dev", allowOrigin: testOrigin}, db, deks, 2, testHMACKey, testSecret, c, logger)
	if v.putCard == nil || v.getCard == nil || v.ping == nil || v.cvv == nil || v.now == nil {
		t.Fatal("function fields or CVV cache not wired")
	}
	if v.currentDEK != 2 || len(v.deks) != 2 || !bytes.Equal(v.hmacKey, testHMACKey) || v.allowOrigin != testOrigin ||
		v.client != c || v.log != logger {
		t.Error("fields not wired")
	}
	if p, ok := v.providers["stripe"]; !ok || p.secret != testSecret {
		t.Error("stripe provider secret not wired")
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
		testHMACKey, testSecret, newOutboundClient(nil), log.New(&testLog, "", 0))

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
		testHMACKey, testSecret, newOutboundClient(nil), log.New(&testLog, "", 0))
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

// TestBootFailsFastOnTLSFiles: in serve mode the certificate, key and client CA are loaded right
// after the environment is parsed (§11 "fail fast"), before the database, KMS or Secret Manager
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
	caPEM, ca, caKey := testCertPEM(t, true, nil, nil)
	leafPEM, _, leafKey := testCertPEM(t, false, ca, caKey)
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	certFile := write("cert.pem", leafPEM)
	keyFile := write("key.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	caFile := write("ca.pem", caPEM)
	missing := filepath.Join(dir, "missing.pem")
	const badDB = "postgres://vault_app@127.0.0.1:notaport/vault"
	dev := envWith(testDevEnv(), map[string]string{"VAULT_CERT": certFile, "VAULT_KEY": keyFile, "VAULT_CLIENT_CA": caFile, "VAULT_DB_URL": badDB})
	prod := envWith(testProdEnv(), map[string]string{"VAULT_CERT": certFile, "VAULT_KEY": keyFile, "VAULT_CLIENT_CA": caFile, "VAULT_DB_URL": badDB})
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

// ---------------------------------------------------------------------------
// End-to-end acceptance (SPEC §15): real listeners and TLS, real database, DEK rotation, and the
// opt-in live Stripe check. These tests replace package-level base URLs and must not call t.Parallel.
// ---------------------------------------------------------------------------

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

// roundTrip sends a request and returns status, headers and body; a transport error fails the test.
// header holds the request headers to set.
func roundTrip(t *testing.T, c *http.Client, method, target, body string, header map[string]string) (int, http.Header, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, target, rd)
	if err != nil {
		t.Fatal("building request failed")
	}
	for k, val := range header {
		req.Header.Set(k, val)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: transport error", method, req.URL.Path)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: reading response failed", method, req.URL.Path)
	}
	return resp.StatusCode, resp.Header, b
}

// hasLogLine reports whether one line of logged contains every part.
func hasLogLine(logged string, parts ...string) bool {
	for _, line := range strings.Split(logged, "\n") {
		all := true
		for _, p := range parts {
			all = all && strings.Contains(line, p)
		}
		if all {
			return true
		}
	}
	return false
}

// TestIntegrationEndToEnd boots the vault the way main does (dev config, real database as
// vault_app, DEK v1) behind both real TLS listeners, with the fake TLS provider standing in for
// Stripe, and walks the §15 flow: browser preflight + tokenize, platform proxy with a forged
// Authorization header, healthz, and the mTLS refusal of a client without a certificate.
func TestIntegrationEndToEnd(t *testing.T) {
	ctx := context.Background()
	cfg := config{
		env:          "dev",
		publicAddr:   "127.0.0.1:0",
		internalAddr: "127.0.0.1:0",
		allowOrigin:  testOrigin,
		dbURL:        integrationURL(t, "vault_app"),
		devDEK:       bytes.Repeat([]byte{0x5e}, 32),
	}
	db, err := openDB(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("database ping: %v", err)
	}
	deks, current, err := loadDEKs(ctx, cfg, db, nil, nil)
	if err != nil || current != 1 {
		t.Fatalf("loadDEKs: current=%d err=%v", current, err)
	}

	fp := newFakeProvider(t, nil)
	v := newVault(cfg, db, deks, current, testHMACKey, testSecret, newOutboundClient(nil), log.New(&testLog, "", 0))
	pointStripe(t, v, fp.ts.URL, fp.ts.Certificate())

	_, caPool, serverCert, clientCert := testPKI(t)
	public, internal := newServers(v, cfg, serverCert, caPool)
	serve := func(srv *http.Server) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go srv.ServeTLS(ln, "", "")
		t.Cleanup(func() { srv.Close() })
		return "https://" + ln.Addr().String()
	}
	pubURL, intURL := serve(public), serve(internal)
	n0 := testLog.Len()

	// Browser at VAULT_ALLOW_ORIGIN: preflight, then tokenize with a valid session token.
	browser := tlsClient(t, caPool)
	status, h, _ := roundTrip(t, browser, http.MethodOptions, pubURL+"/tokenize", "", map[string]string{
		"Origin":                         testOrigin,
		"Access-Control-Request-Method":  "POST",
		"Access-Control-Request-Headers": "authorization,content-type",
	})
	if status != http.StatusNoContent || h.Get("Access-Control-Allow-Origin") != testOrigin {
		t.Fatalf("preflight: status %d, want 204 with the allowed origin", status)
	}
	status, h, body := roundTrip(t, browser, http.MethodPost, pubURL+"/tokenize", tokBody(nil), map[string]string{
		"Origin":        testOrigin,
		"Authorization": "Bearer " + mintSession(testHMACKey, time.Now().Add(10*time.Minute)),
		"Content-Type":  "application/json",
	})
	var tr tokenizeResponse
	if status != http.StatusOK || json.Unmarshal(body, &tr) != nil {
		t.Fatalf("tokenize: status %d, want 200 with a JSON body", status)
	}
	if !tokenRe.MatchString(tr.Token) || tr.Last4 != "4242" || tr.ExpMonth != "12" || tr.ExpYear != "2030" ||
		h.Get("Access-Control-Allow-Origin") != testOrigin {
		t.Fatal("tokenize: response fields or CORS header wrong")
	}

	// Platform without a client certificate: the TLS handshake is refused, no handler runs.
	nNoCert := testLog.Len()
	req, err := http.NewRequest(http.MethodGet, intURL+"/healthz", nil)
	if err != nil {
		t.Fatal("building request failed")
	}
	if resp, err := tlsClient(t, caPool).Do(req); err == nil {
		resp.Body.Close()
		t.Fatalf("internal listener answered a client without a certificate: status %d", resp.StatusCode)
	}
	if strings.Contains(testLog.since(nNoCert), "listener=internal") {
		t.Error("a request without a client certificate reached the internal handler")
	}

	// Platform with its certificate: create_payment_method with a forged Authorization header.
	platform := tlsClient(t, caPool, clientCert)
	status, _, body = roundTrip(t, platform, http.MethodPost, intURL+"/proxy",
		proxyBody("stripe", "create_payment_method", tr.Token, nil), map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer sk_test_attacker",
		})
	if status != http.StatusOK {
		t.Fatalf("proxy: status %d, want 200", status)
	}
	if string(body) != `{"id":"pm_123"}` {
		t.Errorf("proxy: body is not the provider's body (%d bytes)", len(body))
	}
	hits, method, path, sentHeader, sent := fp.last()
	if hits != 1 || method != http.MethodPost || path != "/v1/payment_methods" {
		t.Fatalf("provider saw %d requests, last %s %s; want 1 POST /v1/payment_methods", hits, method, path)
	}
	if sentHeader.Get("Authorization") != "Bearer "+testSecret {
		t.Error("provider did not receive the vault's own secret as the credential")
	}
	if !bytes.Contains(sent, []byte("card%5Bnumber%5D="+testPAN)) {
		t.Error("provider body lacks card[number] with the tokenized PAN")
	}
	if !bytes.Contains(sent, []byte("card%5Bcvc%5D="+testCVV)) {
		t.Error("provider body lacks card[cvc] with the CVV given at tokenize")
	}

	status, _, body = roundTrip(t, platform, http.MethodGet, intURL+"/healthz", "", nil)
	if status != http.StatusOK || string(body) != "{\"status\":\"ok\"}\n" {
		t.Errorf("healthz: status %d (%d bytes), want 200 {\"status\":\"ok\"}", status, len(body))
	}

	logged := testLog.since(n0)
	for _, parts := range [][]string{
		{"req listener=public method=OPTIONS path=/tokenize status=204"},
		{"req listener=public method=POST path=/tokenize status=200"},
		{"req listener=internal method=POST path=/proxy status=200", "caller=0A1B2C"},
		{"req listener=internal method=GET path=/healthz status=200", "caller=0A1B2C"},
	} {
		if !hasLogLine(logged, parts...) {
			t.Errorf("no access-log line with %q", parts)
		}
	}
}

// TestIntegrationRotateDEK covers §8.3/§8.4 and the last §15 box: -rotate-dek (as vault_rotator,
// KMS via the fake metadata server and fake KMS) creates a new version; after a "restart" (a
// second loadDEKs as vault_app) every version loads and a token sealed under the old DEK resolves.
// The KMS settings are what prod passes (no dev DEK). The pools are opened in dev mode because
// the test database speaks trust auth without TLS; prod openDB (verified TLS + IAM token) is
// covered by TestOpenDB.
func TestIntegrationRotateDEK(t *testing.T) {
	ctx := context.Background()
	open := func(role string) *sql.DB {
		db, err := openDB(config{env: "dev", dbURL: integrationURL(t, role)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
	rotDB, appDB := open("vault_rotator"), open("vault_app")
	newFakeMetadata(t, nil)
	k := newFakeKMS(t)
	c := newOutboundClient(nil)
	ts := &tokenSource{client: c}
	kmsCfg := config{env: "prod", kmsKey: testKMSKey}

	vOld, err := rotateDEK(ctx, kmsCfg, rotDB, c, ts)
	if err != nil || vOld <= 0 {
		t.Fatalf("first rotation: version=%d err=%v", vOld, err)
	}
	deks, cur, err := loadDEKs(ctx, kmsCfg, appDB, c, ts)
	if err != nil || cur != vOld || len(deks[vOld]) != dekSize {
		t.Fatalf("load after first rotation: current=%d (want %d) err=%v", cur, vOld, err)
	}

	// A card tokenized under the then-current DEK.
	pt, err := json.Marshal(card{PAN: testPAN, ExpMonth: "12", ExpYear: "2030"})
	if err != nil {
		t.Fatal("marshal card failed")
	}
	tok := newToken()
	if err := dbPutCard(ctx, appDB, tok, seal(deks[cur], pt), "4242", cur); err != nil {
		t.Fatalf("put_card: %v", err)
	}

	vNew, err := rotateDEK(ctx, kmsCfg, rotDB, c, ts)
	if err != nil || vNew != vOld+1 {
		t.Fatalf("second rotation: version=%d err=%v, want %d", vNew, err, vOld+1)
	}

	// Restart: both versions load, current is the highest.
	deks2, cur2, err := loadDEKs(ctx, kmsCfg, appDB, c, ts)
	if err != nil {
		t.Fatalf("load after second rotation: %v", err)
	}
	maxVer := 0
	for ver := range deks2 {
		maxVer = max(maxVer, ver)
	}
	if cur2 != vNew || cur2 != maxVer {
		t.Errorf("current = %d, want %d (the highest version)", cur2, vNew)
	}
	for _, ver := range []int{vOld, vNew} {
		if len(deks2[ver]) != dekSize {
			t.Errorf("version %d not loaded as a 32-byte DEK", ver)
		}
	}
	if !bytes.Equal(deks2[vOld], deks[vOld]) {
		t.Error("the old DEK changed across restarts")
	}
	if bytes.Equal(deks2[vOld], deks2[vNew]) {
		t.Error("two rotations produced the same DEK")
	}
	// Every DEK came through KMS decrypt: the fake KMS wraps by reversing the bytes.
	wrapped, err := dbListDEKs(ctx, appDB)
	if err != nil {
		t.Fatalf("list_deks: %v", err)
	}
	if len(wrapped) != len(deks2) {
		t.Errorf("loaded %d DEKs, list_deks has %d", len(deks2), len(wrapped))
	}
	for ver, d := range deks2 {
		if !bytes.Equal(reversed(wrapped[ver]), d) {
			t.Errorf("version %d was not unwrapped by KMS decrypt", ver)
		}
	}
	if k.count() == 0 {
		t.Error("fake KMS was never called")
	}

	// The old token still resolves under its own key version.
	ct, kv, err := dbGetCard(ctx, appDB, tok, "0A1B2C")
	if err != nil || kv != vOld {
		t.Fatalf("get_card: key_version=%d (want %d) err=%v", kv, vOld, err)
	}
	got, err := unseal(deks2[kv], ct)
	var cd card
	if err != nil || json.Unmarshal(got, &cd) != nil || cd.PAN != testPAN || cd.ExpMonth != "12" || cd.ExpYear != "2030" {
		t.Error("the old token does not resolve to its card after rotation")
	}
	if _, err := unseal(deks2[vNew], ct); err == nil {
		t.Error("the old ciphertext opens under the new DEK")
	}
}

// TestStripeLive runs tokenize → create_payment_method against the real Stripe test-mode API
// (§15) with a forged inbound Authorization header. It runs only when VAULT_TEST_STRIPE_SECRET
// holds a test-mode key (sk_test_…), which is never printed. That the payment method shows up in
// the vault's Stripe dashboard is still checked by hand.
func TestStripeLive(t *testing.T) {
	secret := os.Getenv("VAULT_TEST_STRIPE_SECRET")
	if !strings.HasPrefix(secret, "sk_test_") {
		t.Skip("set VAULT_TEST_STRIPE_SECRET to a Stripe test-mode key (sk_test_…) to run")
	}
	v, _ := newTestVault(t) // in-memory store
	v.providers = newProviders(secret)
	v.client = newOutboundClient(nil)
	if base := v.providers["stripe"].base.String(); base != "https://api.stripe.com" {
		t.Fatalf("stripe base is %s, want the real API", base)
	}

	rec := serveTokenize(v, tokRequest(tokCase{body: tokBody(map[string]any{"cvv": "314"})}))
	var tr tokenizeResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &tr) != nil {
		t.Fatalf("tokenize: status %d", rec.Code)
	}

	r := newProxyRequest(proxyBody("stripe", "create_payment_method", tr.Token, nil))
	r.Header.Set("Authorization", "Bearer sk_test_attacker")
	rec = serveInternal(v, r)
	if rec.Code != http.StatusOK || !regexp.MustCompile(`"id":\s*"pm_`).Match(rec.Body.Bytes()) {
		masked, _ := maskPAN(rec.Body.Bytes(), testPAN)
		t.Fatalf("create_payment_method: status %d, body (PAN masked, key redacted): %s",
			rec.Code, strings.ReplaceAll(string(masked), secret, "<redacted>"))
	}
}

// TestStripeMock checks the vault's real outbound Stripe requests against Stripe's published API
// definition by sending them to stripe/stripe-mock (`make stripe-mock-test`). It runs only when
// VAULT_TEST_STRIPE_MOCK_URL names stripe-mock's plain-HTTP port on a loopback address.
//
// stripe-mock's built-in HTTPS certificate is an X.509 v1 cert with CN=localhost and no SANs, which
// Go cannot hostname-verify for any ServerName, and stripe-mock takes no cert flags. So the vault
// talks TLS to a test-only relay (an httptest TLS server whose certificate is the only root in the
// vault client's pool, exactly as pointStripe does for the fake provider): the vault's client is
// the unmodified, fully verifying newOutboundClient. The relay forwards method, path, headers and
// body unchanged to stripe-mock over loopback HTTP and returns its status, headers and body.
func TestStripeMock(t *testing.T) {
	raw := os.Getenv("VAULT_TEST_STRIPE_MOCK_URL")
	if raw == "" {
		t.Skip("set VAULT_TEST_STRIPE_MOCK_URL (e.g. via `make stripe-mock-test`) to run")
	}
	target, err := url.Parse(raw)
	if err != nil || target.Scheme != "http" || target.Path != "" && target.Path != "/" {
		t.Fatal("VAULT_TEST_STRIPE_MOCK_URL must be http://<loopback>:<port>")
	}
	if h := target.Hostname(); h != "localhost" && !(net.ParseIP(h) != nil && net.ParseIP(h).IsLoopback()) {
		t.Fatalf("VAULT_TEST_STRIPE_MOCK_URL host %q is not loopback", h)
	}
	const secret = "sk_test_123" // stripe-mock accepts any sk_test_ key

	// What stripe-mock received for the latest request; recorded by the relay, never printed.
	type seen struct {
		hits                       int
		method, path               string
		authOK, formOK, userAgent  bool
		hasCVC, hasCustomer, hasPM bool
	}
	var mu sync.Mutex
	var last seen
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target) // no SetXForwarded: headers reach stripe-mock as the vault sent them
		},
		Transport:     &http.Transport{Proxy: nil},
		ErrorLog:      log.New(io.Discard, "", 0),
		FlushInterval: -1,
	}
	relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "relay read failed", http.StatusBadGateway)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		form, _ := url.ParseQuery(string(body))
		mu.Lock()
		last = seen{
			hits:        last.hits + 1,
			method:      r.Method,
			path:        r.URL.Path,
			authOK:      slices.Equal(r.Header.Values("Authorization"), []string{"Bearer " + secret}),
			formOK:      r.Header.Get("Content-Type") == "application/x-www-form-urlencoded",
			userAgent:   r.Header.Get("User-Agent") == "pan-vault/1",
			hasCVC:      form.Has("card[cvc]"),
			hasCustomer: form.Get("customer") == "cus_123",
			hasPM:       form.Get("type") == "card",
		}
		mu.Unlock()
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(relay.Close)

	v, s := newTestVault(t)
	v.providers = newProviders(secret)
	pointStripe(t, v, relay.URL, relay.Certificate())

	// show makes a response body printable: PAN masked, key redacted, at most 2 KiB.
	show := func(b []byte) string {
		m, _ := maskPAN(b, testPAN)
		out := strings.ReplaceAll(string(m), secret, "<redacted>")
		if len(out) > 2048 {
			out = out[:2048] + "…"
		}
		return out
	}
	pmID := regexp.MustCompile(`"id":\s*"pm_`)
	tokID := regexp.MustCompile(`"id":\s*"tok_`)

	call := func(name, op, tok string, params map[string]string, wantPath string, wantCVC bool) (*httptest.ResponseRecorder, seen) {
		t.Helper()
		mu.Lock()
		before := last.hits
		mu.Unlock()
		rec := serveInternal(v, newProxyRequest(proxyBody("stripe", op, tok, params)))
		mu.Lock()
		got := last
		mu.Unlock()
		if got.hits != before+1 {
			t.Fatalf("%s: stripe-mock got %d requests, want 1 (vault status %d)", name, got.hits-before, rec.Code)
		}
		if got.method != "POST" || got.path != wantPath {
			t.Errorf("%s: outbound %s %s, want POST %s", name, got.method, got.path, wantPath)
		}
		if !got.authOK {
			t.Errorf("%s: stripe-mock did not receive exactly the vault credential", name) // never print it
		}
		if !got.formOK || !got.userAgent {
			t.Errorf("%s: outbound Content-Type or User-Agent wrong", name)
		}
		if got.hasCVC != wantCVC {
			t.Errorf("%s: card[cvc] sent = %v, want %v", name, got.hasCVC, wantCVC)
		}
		return rec, got
	}

	// 1. create_payment_method, no params, CVV present.
	tok1 := seedCard(t, v, s, testCVV)
	rec, got := call("create_payment_method", "create_payment_method", tok1, nil, "/v1/payment_methods", true)
	if !got.hasPM || got.hasCustomer {
		t.Error("create_payment_method: outbound type=card missing or unexpected customer")
	}
	if rec.Code != http.StatusOK || !pmID.Match(rec.Body.Bytes()) {
		t.Errorf("create_payment_method: status %d, body len %d (PAN masked): %s", rec.Code, rec.Body.Len(), show(rec.Body.Bytes()))
	}

	// 2. create_payment_method with customer: assert success if stripe-mock accepts it; a rejection
	// is a FINDING for the catalog owner, logged without card data, not a test failure.
	tok2 := seedCard(t, v, s, testCVV)
	rec, got = call("create_payment_method+customer", "create_payment_method", tok2, map[string]string{"customer": "cus_123"}, "/v1/payment_methods", true)
	if !got.hasPM || !got.hasCustomer {
		t.Error("create_payment_method+customer: outbound type=card or customer missing")
	}
	switch {
	case rec.Code == http.StatusOK:
		if !pmID.Match(rec.Body.Bytes()) {
			t.Errorf("create_payment_method+customer: 200 without a pm_ id, body len %d (PAN masked): %s", rec.Body.Len(), show(rec.Body.Bytes()))
		} else {
			t.Log("create_payment_method with customer: accepted by stripe-mock (200, pm_ id)")
		}
	default:
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &e)
		msg, _ := maskPAN([]byte(e.Error.Message), testPAN)
		t.Logf("FINDING (create_payment_method with customer): stripe-mock rejected it: status %d, message %q",
			rec.Code, strings.ReplaceAll(string(msg), secret, "<redacted>"))
	}

	// 3. create_token, CVV present.
	tok3 := seedCard(t, v, s, testCVV)
	rec, _ = call("create_token", "create_token", tok3, nil, "/v1/tokens", true)
	if rec.Code != http.StatusOK || !tokID.Match(rec.Body.Bytes()) {
		t.Errorf("create_token: status %d, body len %d (PAN masked): %s", rec.Code, rec.Body.Len(), show(rec.Body.Bytes()))
	}

	// 4. create_payment_method on tok1 again: its CVV was consumed by case 1, so no card[cvc].
	rec, _ = call("create_payment_method (CVV consumed)", "create_payment_method", tok1, nil, "/v1/payment_methods", false)
	if rec.Code != http.StatusOK || !pmID.Match(rec.Body.Bytes()) {
		t.Errorf("create_payment_method (CVV consumed): status %d, body len %d (PAN masked): %s", rec.Code, rec.Body.Len(), show(rec.Body.Bytes()))
	}
}
