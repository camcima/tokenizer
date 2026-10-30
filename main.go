package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {}

// ---------------------------------------------------------------------------
// Card primitives (SPEC §5.5, §5.6, §8.1, §8.5)
// ---------------------------------------------------------------------------

// card is the encrypted record: plaintext is json.Marshal(card{...}) (§8.1).
// CVV is never part of it. Keep values of this type scoped to a single request.
type card struct {
	PAN      string `json:"pan"`
	ExpMonth string `json:"exp_month"`
	ExpYear  string `json:"exp_year"`
}

var (
	expMonthRe = regexp.MustCompile(`^(0[1-9]|1[0-2])$`)
	expYearRe  = regexp.MustCompile(`^[0-9]{4}$`)
	tokenRe    = regexp.MustCompile(`^tok_[0-9a-f]{32}$`)
)

// luhnValid reports whether digits is a non-empty ASCII digit string passing the Luhn check.
func luhnValid(digits string) bool {
	if digits == "" {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		c := digits[i]
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// normalizePAN strips spaces and hyphens, then requires ASCII digits only, length 13–19,
// and a passing Luhn check (§5.5). On failure it returns ("", false).
// SPEC-DECISION: only ' ' and '-' are stripped; any other separator (tab, dot, NBSP) or
// non-ASCII digit (e.g. full-width) rejects the PAN.
func normalizePAN(s string) (string, bool) {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ' || c == '-':
			continue
		case c >= '0' && c <= '9':
			b = append(b, c)
		default:
			zero(b)
			return "", false
		}
	}
	defer zero(b)
	if len(b) < 13 || len(b) > 19 || !luhnValid(string(b)) {
		return "", false
	}
	return string(b), true
}

// validExpiry checks exp_month (exactly "01"–"12") and exp_year (exactly four digits), and
// requires (year, month) >= the current month in UTC (§5.5).
func validExpiry(month, year string, now time.Time) bool {
	if !expMonthRe.MatchString(month) || !expYearRe.MatchString(year) {
		return false
	}
	// Both strings are validated ASCII digits, so this cannot overflow or misparse.
	m := int(month[0]-'0')*10 + int(month[1]-'0')
	y := 0
	for i := 0; i < len(year); i++ {
		y = y*10 + int(year[i]-'0')
	}
	u := now.UTC()
	cy, cm := u.Year(), int(u.Month())
	return y > cy || (y == cy && m >= cm)
}

// validCVV reports whether s is 3–4 ASCII digits (§5.5). Presence is the caller's concern.
func validCVV(s string) bool {
	if len(s) < 3 || len(s) > 4 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// newToken returns "tok_" + 32 lowercase hex chars from 16 bytes of crypto/rand (§5.6).
func newToken() string {
	var b [16]byte
	// crypto/rand.Read is deliberately called without error handling: since Go 1.24 it never
	// returns an error and irrecoverably crashes the process if the OS RNG fails, which is
	// exactly §8.1's "a crypto/rand failure panics; it is not recoverable".
	rand.Read(b[:])
	return "tok_" + hex.EncodeToString(b[:])
}

const (
	gcmNonceSize = 12
	gcmTagSize   = 16
	dekSize      = 32 // AES-256
)

var errUnseal = errors.New("unseal failed")

// newGCM builds AES-256-GCM for dek.
// SPEC-DECISION: only 32-byte keys are accepted (AES-256 per §8.1); aes.NewCipher would
// otherwise silently accept 16/24-byte keys and downgrade to AES-128/192.
func newGCM(dek []byte) (cipher.AEAD, error) {
	if len(dek) != dekSize {
		return nil, errUnseal
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, errUnseal
	}
	gcm, err := cipher.NewGCM(block) // 12-byte nonce, 16-byte tag
	if err != nil {
		return nil, errUnseal
	}
	return gcm, nil
}

// seal encrypts plaintext under dek with AES-256-GCM and a fresh random 12-byte nonce, no
// additional data, returning nonce || ciphertext || tag (§8.1).
// A DEK that is not 32 bytes is a programming error (DEKs are length-checked at load) and panics.
func seal(dek, plaintext []byte) []byte {
	gcm, err := newGCM(dek)
	if err != nil {
		panic("seal: invalid DEK")
	}
	out := make([]byte, gcmNonceSize, gcmNonceSize+len(plaintext)+gcmTagSize)
	rand.Read(out) // never fails; see newToken
	return gcm.Seal(out, out, plaintext, nil)
}

// unseal reverses seal. Any failure (bad key length, short blob, authentication failure)
// returns the same static error, never key or data material.
func unseal(dek, blob []byte) ([]byte, error) {
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, errUnseal
	}
	if len(blob) < gcmNonceSize+gcmTagSize {
		return nil, errUnseal
	}
	pt, err := gcm.Open(nil, blob[:gcmNonceSize], blob[gcmNonceSize:], nil)
	if err != nil {
		return nil, errUnseal
	}
	return pt, nil
}

// zero overwrites b with zeros. Best effort only (§8.5): Go may have copied the data
// elsewhere (string conversions, GC moves, register spills), so this narrows exposure but
// cannot guarantee the bytes are gone from memory.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ---------------------------------------------------------------------------
// Vault core: state, logging, guard, errors (SPEC §5.7, §10.1)
// ---------------------------------------------------------------------------

// Errors returned by vault.getCard. Any other error is an internal failure.
var (
	errVelocity     = errors.New("velocity")
	errUnknownToken = errors.New("unknown token")
)

// Error response strings: the complete fixed set (§5.7). Error bodies use only these; they never
// carry user input, token values, provider error text, or Go error strings.
const (
	msgNotFound           = "not found"
	msgMethod             = "method not allowed"
	msgQuery              = "query string not allowed"
	msgContentType        = "content type must be application/json"
	msgTooLarge           = "request body too large"
	msgBadBody            = "invalid request body"
	msgInvalidPAN         = "invalid pan"
	msgInvalidExpiry      = "invalid expiry"
	msgInvalidCVV         = "invalid cvv"
	msgUnauthorized       = "unauthorized"
	msgOrigin             = "origin not allowed"
	msgUnknownProvider    = "unknown provider"
	msgUnknownOp          = "unknown op"
	msgInvalidToken       = "invalid token"
	msgUnknownToken       = "unknown token"
	msgInvalidParams      = "invalid params"
	msgInvalidIdempotency = "invalid idempotency key"
	msgVelocity           = "rate limit exceeded"
	msgInternal           = "internal error"
	msgProvider           = "provider unreachable"
	msgUnavailable        = "unavailable"
)

// vault holds all process state. The function fields are the only seam: production wires them
// to the database, tests to an in-memory fake.
type vault struct {
	putCard func(ctx context.Context, token string, ciphertext []byte, last4 string, keyVersion int) error
	// getCard returns errVelocity or errUnknownToken for those conditions; any other error is internal.
	getCard func(ctx context.Context, token, caller string) (ciphertext []byte, keyVersion int, err error)
	ping    func(ctx context.Context) error

	deks        map[int][]byte // key version → 32-byte DEK
	currentDEK  int
	hmacKey     []byte
	allowOrigin string
	cvv         *cvvCache
	now         func() time.Time
	log         *log.Logger

	lastSessionAlert atomic.Int64 // unix second of last session_token_invalid alert
}

// logf writes one line: "<RFC3339 UTC timestamp> " + message. Callers pass only fixed format
// strings and non-sensitive values (tokens, serials, provider/op names, statuses).
func (v *vault) logf(format string, args ...any) {
	v.log.Print(v.now().UTC().Format(time.RFC3339) + " " + fmt.Sprintf(format, args...))
}

// statusWriter records the status code sent to the client.
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status = code
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status = http.StatusOK
		w.wrote = true
	}
	return w.ResponseWriter.Write(b)
}

// logPath and logMethod keep request-controlled text out of the access log.
// SPEC-DECISION: only known routes are logged literally, everything else as path=other, so a
// PAN typed into a URL path (POST /4242…) can never reach the log; likewise method=other for
// anything but GET/POST/OPTIONS.
func logPath(p string) string {
	switch p {
	case "/tokenize", "/proxy", "/healthz":
		return p
	}
	return "other"
}

func logMethod(m string) string {
	switch m {
	case http.MethodGet, http.MethodPost, http.MethodOptions:
		return m
	}
	return "other"
}

// guard wraps every handler on both listeners: exactly one access-log line per request (§10.1)
// and panic recovery. A panic becomes 500 {"error":"internal error"}; the panic value is never
// logged (it could carry card data). If the response had already started, the connection is
// aborted instead (http.ErrAbortHandler) so the client never receives a truncated success.
func (v *vault) guard(listener string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		abort := false
		defer func() {
			if p := recover(); p != nil {
				if sw.wrote {
					abort = true
				} else {
					writeError(sw, http.StatusInternalServerError, msgInternal)
				}
				sw.status = http.StatusInternalServerError
			}
			line := fmt.Sprintf("req listener=%s method=%s path=%s status=%d dur=%dms",
				listener, logMethod(r.Method), logPath(r.URL.Path), sw.status, time.Since(start).Milliseconds())
			if listener == "internal" {
				line += " caller=" + callerSerial(r)
			}
			v.logf("%s", line)
			if abort {
				panic(http.ErrAbortHandler)
			}
		}()
		h.ServeHTTP(sw, r)
	})
}

// writeJSON writes body as JSON followed by a newline, with Cache-Control: no-store. A body
// that cannot be marshalled yields 500 internal error instead.
func writeJSON(w http.ResponseWriter, status int, body any) {
	b, err := json.Marshal(body)
	if err != nil {
		status = http.StatusInternalServerError
		b, _ = json.Marshal(struct {
			Error string `json:"error"`
		}{msgInternal})
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	w.Write(append(b, '\n'))
}

// writeError writes {"error":msg}; msg must be one of the msg* constants.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{msg})
}

// callerSerial returns the verified client certificate's serial number as uppercase hex, or ""
// if there is none.
func callerSerial(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	leaf := r.TLS.PeerCertificates[0]
	if leaf == nil || leaf.SerialNumber == nil {
		return ""
	}
	return fmt.Sprintf("%X", leaf.SerialNumber)
}

// ---------------------------------------------------------------------------
// Session tokens (SPEC §5.4)
// ---------------------------------------------------------------------------

const sessionMaxAhead = 15 * 60 // seconds

var (
	sessionExpRe = regexp.MustCompile(`^[0-9]{1,19}$`)
	sessionMACRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// checkSession validates "Authorization: Bearer v1.<expires_unix>.<hex HMAC-SHA256(key,
// "v1."+expires_unix)>" and returns "" if valid, else the alert reason "format", "hmac" or
// "expired". Checks run format → HMAC → window, so "expired" is reported only for authentic
// tokens. expires_unix <= now is expired; > now+15m is also rejected as "expired".
// SPEC-DECISION: the scheme prefix is exactly "Bearer " (case-sensitive, one space), the MAC is
// exactly 64 lowercase hex chars, and a key shorter than 32 bytes authenticates nothing.
func checkSession(key []byte, authz string, now time.Time) string {
	tok, ok := strings.CutPrefix(authz, "Bearer ")
	if !ok {
		return "format"
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] != "v1" || !sessionExpRe.MatchString(parts[1]) || !sessionMACRe.MatchString(parts[2]) {
		return "format"
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "format"
	}
	got, err := hex.DecodeString(parts[2])
	if err != nil {
		return "format"
	}
	if len(key) < 32 {
		return "hmac"
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("v1." + parts[1]))
	if !hmac.Equal(got, m.Sum(nil)) {
		return "hmac"
	}
	n := now.Unix()
	if exp <= n || exp > n+sessionMaxAhead {
		return "expired"
	}
	return ""
}

// alertSession logs "ALERT session_token_invalid reason=<reason>" at most once per second
// (§10.1). reason is checkSession's result.
func (v *vault) alertSession(reason string) {
	sec := v.now().Unix()
	old := v.lastSessionAlert.Load()
	if old == sec || !v.lastSessionAlert.CompareAndSwap(old, sec) {
		return
	}
	v.logf("ALERT session_token_invalid reason=%s", reason)
}

// ---------------------------------------------------------------------------
// CVV cache (SPEC §3.2, §8.5): in memory only, single use, TTL, swept on every write
// ---------------------------------------------------------------------------

type cvvEntry struct {
	cvv string
	exp time.Time
}

type cvvCache struct {
	mu  sync.Mutex
	m   map[string]cvvEntry
	ttl time.Duration
	now func() time.Time
}

func newCVVCache(ttl time.Duration, now func() time.Time) *cvvCache {
	return &cvvCache{m: make(map[string]cvvEntry), ttl: ttl, now: now}
}

// put caches cvv for token until now+ttl, first deleting every expired entry.
// SPEC-DECISION: an entry is expired from exactly put+ttl onward.
func (c *cvvCache) put(token, cvv string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for k, e := range c.m {
		if !now.Before(e.exp) {
			delete(c.m, k)
		}
	}
	c.m[token] = cvvEntry{cvv: cvv, exp: now.Add(c.ttl)}
}

// take removes and returns token's CVV; "" if absent or expired. Single use: concurrent
// callers for the same token get it at most once.
func (c *cvvCache) take(token string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[token]
	if !ok {
		return ""
	}
	delete(c.m, token)
	if !c.now().Before(e.exp) {
		return ""
	}
	return e.cvv
}
