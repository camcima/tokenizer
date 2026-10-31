package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Session tokens and the session_token_invalid alert
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
// guard, access log, error bodies
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
	// Byte-wise uppercase hex as `openssl x509 -serial` prints it.
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

// Every error message is one of the fixed constants with its exact text.
func TestErrorConstants(t *testing.T) {
	want := map[string]string{
		msgNotFound: "not found", msgMethod: "method not allowed", msgQuery: "query string not allowed",
		msgContentType: "content type must be application/json", msgTooLarge: "request body too large",
		msgBadBody: "invalid request body", msgInvalidPAN: "invalid pan", msgInvalidExpiry: "invalid expiry",
		msgInvalidCVV: "invalid cvv", msgInvalidName: "invalid name", msgUnauthorized: "unauthorized",
		msgOrigin: "origin not allowed", msgInvalidToken: "invalid token", msgUnknownToken: "unknown token",
		msgVelocity: "rate limit exceeded", msgInternal: "internal error", msgProvider: "provider unreachable",
		msgUnavailable: "unavailable", msgUnknownAccount: "unknown account", msgEndpointNotAllowed: "endpoint not allowed",
		msgHeaderNotAllowed: "header not allowed", msgPlaceholder: "invalid placeholder use",
		msgPinMismatch: "pinned field mismatch", msgForbiddenField: "forbidden field",
		msgCVVUnavailable: "cvv unavailable", msgNameUnavailable: "name unavailable",
	}
	if len(want) != 26 {
		t.Fatalf("%d distinct constants, want 26", len(want))
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
	if !v.now().Equal(testNow) || !v.cvv.now().Equal(testNow) || len(dekOf(v, 1)) != 32 {
		t.Fatal("test vault clock or DEK misconfigured")
	}
	a := v.catalog.accounts["stripe_t"]
	if a == nil || a.host != testCatalogHost || a.secrets["secretKey"] != testSecret ||
		v.catalog.accounts["payu_co"].secrets["apiKey"] != payuTestAPIKey {
		t.Fatal("test vault catalog or account secrets misconfigured")
	}
}

// ---------------------------------------------------------------------------
// DEK snapshot refresh
// ---------------------------------------------------------------------------

// Concurrent refreshes share one run: callers that arrive while it is in flight wait for it and
// then fall inside the rate-limit window.
func TestRefreshSingleFlight(t *testing.T) {
	v, _ := newTestVault(t)
	var calls atomic.Int32
	release := make(chan struct{})
	v.refreshDEKs = func(context.Context) error {
		calls.Add(1)
		<-release
		return nil
	}
	var wg sync.WaitGroup
	var returned atomic.Int32
	for range 20 {
		wg.Go(func() {
			v.refresh(context.Background())
			returned.Add(1)
		})
	}
	// Give every goroutine time to reach the lock before the one run finishes.
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n := returned.Load(); n != 0 {
		t.Fatalf("%d callers returned while the refresh was still in flight", n)
	}
	close(release)
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Fatalf("refresh ran %d times, want 1", n)
	}
	if n := returned.Load(); n != 20 {
		t.Fatalf("%d callers returned, want 20", n)
	}
}

// A refresh less than dekRefreshMinGap after the last completed one does not run.
func TestRefreshRateLimited(t *testing.T) {
	if dekRefreshMinGap != 10*time.Second {
		t.Fatalf("dekRefreshMinGap = %v, want 10s", dekRefreshMinGap)
	}
	v, _ := newTestVault(t)
	var calls int
	v.refreshDEKs = func(context.Context) error { calls++; return nil }
	if err := v.refresh(context.Background()); err != nil || calls != 1 {
		t.Fatalf("first refresh: calls %d, err %v; want 1 run", calls, err)
	}
	// The previous attempt completed 1s ago.
	v.lastRefresh.Store(time.Now().Add(-time.Second).UnixNano())
	if err := v.refresh(context.Background()); err != nil || calls != 1 {
		t.Fatalf("refresh 1s later: calls %d, err %v; want no new run", calls, err)
	}
	v.lastRefresh.Store(time.Now().Add(-11 * time.Second).UnixNano())
	if err := v.refresh(context.Background()); err != nil || calls != 2 {
		t.Fatalf("refresh 11s later: calls %d, err %v; want a second run", calls, err)
	}
	// A wall clock that stepped backwards does not suppress refreshes until it catches up.
	v.lastRefresh.Store(time.Now().Add(time.Hour).UnixNano())
	if err := v.refresh(context.Background()); err != nil || calls != 3 {
		t.Fatalf("refresh after a clock step back: calls %d, err %v; want a third run", calls, err)
	}
}

// Without a refresh function, refresh is a no-op.
func TestRefreshNilFunc(t *testing.T) {
	v, _ := newTestVault(t)
	before := v.keys.Load()
	if err := v.refresh(context.Background()); err != nil || v.keys.Load() != before {
		t.Fatal("refresh without a refresh function changed something")
	}
}

// Cancelling the loop's context while a refresh is in flight ends the loop once that call
// returns: shutdown is never held up by more than the call in progress.
func TestRefreshStopsOnCancel(t *testing.T) {
	v, _ := newTestVault(t)
	started := make(chan struct{}, 1)
	v.refreshDEKs = func(context.Context) error {
		select {
		case started <- struct{}{}:
		default:
		}
		time.Sleep(200 * time.Millisecond)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		v.refreshLoop(ctx, time.Millisecond)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("the loop never refreshed")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("refreshLoop did not return within 1s of cancel")
	}
	if dekRefreshEvery != 5*time.Minute {
		t.Errorf("dekRefreshEvery = %v, want 5m", dekRefreshEvery)
	}
}

// A failed refresh leaves the snapshot as it was, logs nothing, and still counts as an attempt
// for the rate limit.
func TestRefreshFailureKeepsSnapshot(t *testing.T) {
	v, _ := newTestVault(t)
	before := v.keys.Load()
	v.refreshDEKs = func(context.Context) error {
		return errors.New("kms decrypt: status 503 projects/p1/locations/global/keyRings/r1")
	}
	start := testLog.Len()
	if err := v.refresh(context.Background()); err == nil {
		t.Fatal("refresh error not returned")
	}
	if v.keys.Load() != before {
		t.Fatal("a failed refresh replaced the snapshot")
	}
	if got := testLog.since(start); got != "" {
		t.Fatalf("a failed refresh logged %d bytes", len(got))
	}
	if since := time.Now().UnixNano() - v.lastRefresh.Load(); since < 0 || since > int64(time.Minute) {
		t.Fatal("a failed refresh was not recorded as an attempt")
	}
}

// The refresh function runs under its own deadline and is not cancelled with the caller: a
// caller that goes away mid-refresh neither fails the attempt nor holds queued callers beyond
// dekRefreshTimeout.
func TestRefreshTimeout(t *testing.T) {
	if dekRefreshTimeout != 30*time.Second {
		t.Fatalf("dekRefreshTimeout = %v, want 30s", dekRefreshTimeout)
	}
	v, _ := newTestVault(t)
	type ctxKey struct{}
	started, callerGone := make(chan struct{}), make(chan struct{})
	var errAfterCancel error
	var left time.Duration
	var hasDeadline, hasValue bool
	v.refreshDEKs = func(ctx context.Context) error {
		dl, ok := ctx.Deadline()
		left, hasDeadline = time.Until(dl), ok
		hasValue = ctx.Value(ctxKey{}) != nil
		close(started)
		<-callerGone
		errAfterCancel = ctx.Err()
		return nil
	}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), ctxKey{}, true))
	done := make(chan error, 1)
	go func() { done <- v.refresh(ctx) }()
	<-started
	cancel()
	close(callerGone)
	if err := <-done; err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !hasDeadline || left > dekRefreshTimeout || left < dekRefreshTimeout-5*time.Second {
		t.Errorf("refresh context deadline ok=%v %v away, want ≤%v", hasDeadline, left, dekRefreshTimeout)
	}
	if errAfterCancel != nil {
		t.Errorf("the caller's cancellation reached the refresh context: %v", errAfterCancel)
	}
	if !hasValue {
		t.Error("the refresh context is not derived from the caller's context")
	}
}
