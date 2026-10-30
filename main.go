package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"maps"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// ---------------------------------------------------------------------------
// Card primitives (SPEC §5.5, §5.6, §8.1, §8.5)
// ---------------------------------------------------------------------------

// card is the encrypted record: plaintext is json.Marshal(card{...}) (§8.1).
// CVV is never part of it. Keep values of this type scoped to a single request.
// Name is the optional cardholder name (D§5.8). omitempty keeps the plaintext of a card stored
// without a name byte-identical to before, and old rows decode with Name == "".
type card struct {
	PAN      string `json:"pan"`
	ExpMonth string `json:"exp_month"`
	ExpYear  string `json:"exp_year"`
	Name     string `json:"name,omitempty"`
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

// validName reports whether s is an acceptable cardholder name (D§5.8): 1–100 runes, valid
// UTF-8, and no control rune (unicode.IsControl: C0, DEL, C1). Presence is the caller's concern.
// SPEC-DECISION: U+FFFD is rejected too. encoding/json silently replaces invalid UTF-8 in a
// string with U+FFFD, so without this a body carrying invalid UTF-8 would be stored, not
// rejected. No real name contains the replacement character.
func validName(s string) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > 100 {
		return false
	}
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) {
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
	msgInvalidName        = "invalid name"
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
	providers   map[string]provider // the catalog (§6.3); see newProviders
	client      *http.Client        // the single shared outbound client (§9.2)

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

// callerSerial returns the verified client certificate's serial number as byte-wise uppercase
// hex, the way `openssl x509 -serial` prints it (serial 0x0A1B2C → "0A1B2C", zero → "00"), or ""
// if there is none (§10.1).
// SPEC-DECISION: a negative serial (invalid per RFC 5280; its magnitude would collide with a
// positive serial) yields "", i.e. it is treated as no caller identity at all.
func callerSerial(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	leaf := r.TLS.PeerCertificates[0]
	if leaf == nil || leaf.SerialNumber == nil || leaf.SerialNumber.Sign() < 0 {
		return ""
	}
	b := leaf.SerialNumber.Bytes()
	if len(b) == 0 {
		return "00"
	}
	return strings.ToUpper(hex.EncodeToString(b))
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

// ---------------------------------------------------------------------------
// Public API: POST /tokenize and CORS (SPEC §3.2, §5)
// ---------------------------------------------------------------------------

const maxPublicBody = 4 << 10 // §5.2: 4 KiB request body limit

type tokenizeRequest struct {
	PAN      string `json:"pan"`
	ExpMonth string `json:"exp_month"`
	ExpYear  string `json:"exp_year"`
	// SPEC-DECISION: nil means the key is absent (no CVV). encoding/json also decodes JSON null
	// to nil, so handleTokenize detects "cvv": null separately and rejects it with
	// msgInvalidCVV, like "" (controller ruling 2026-10-30: the stricter reading).
	CVV *string `json:"cvv"`
	// Name follows CVV exactly: nil means absent, and "name": null is detected separately and
	// rejected with msgInvalidName (D§5.8; the same stricter reading as "cvv": null).
	Name *string `json:"name"`
}

type tokenizeResponse struct {
	Token    string `json:"token"`
	Last4    string `json:"last4"`
	ExpMonth string `json:"exp_month"`
	ExpYear  string `json:"exp_year"`
}

// publicHandler is the complete handler for the public listener.
func (v *vault) publicHandler() http.Handler {
	return v.guard("public", http.HandlerFunc(v.handleTokenize))
}

// singleHeader returns the value of header name if it is present exactly once.
// SPEC-DECISION: a repeated Origin, Authorization or Content-Type header is ambiguous (proxies
// and Go's Header.Get may disagree on which one counts) and is treated as invalid.
func singleHeader(h http.Header, name string) (string, bool) {
	vals := h.Values(name)
	if len(vals) != 1 {
		return "", false
	}
	return vals[0], true
}

// jsonContentType reports whether h carries exactly one Content-Type and it is application/json.
// SPEC-DECISION: the media type must be application/json (case-insensitive, per RFC 9110);
// the only parameter allowed is charset=utf-8, since JSON is UTF-8 (RFC 8259).
func jsonContentType(h http.Header) bool {
	ct, ok := singleHeader(h, "Content-Type")
	if !ok {
		return false
	}
	mt, params, err := mime.ParseMediaType(ct)
	return err == nil && mt == "application/json" && len(params) <= 1 &&
		(len(params) == 0 || strings.EqualFold(params["charset"], "utf-8"))
}

// tokenizeFields is the exact set of keys a /tokenize body may contain.
var tokenizeFields = map[string]bool{"pan": true, "exp_month": true, "exp_year": true, "cvv": true, "name": true}

// exactKeys reports whether body is a JSON object whose keys are all in fields (any key if fields
// is nil), spelled exactly, each at most once.
// SPEC-DECISION: encoding/json matches keys case-insensitively and keeps the last of duplicate
// keys, so DisallowUnknownFields alone accepts {"PAN":…} and {"pan":A,"pan":B}. Both are
// rejected as unknown fields: a body that different JSON parsers would read differently is
// never tokenized.
func exactKeys(body []byte, fields map[string]bool) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool, len(fields))
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return false
		}
		k, ok := t.(string)
		if !ok || (fields != nil && !fields[k]) || seen[k] {
			return false
		}
		seen[k] = true
		var val json.RawMessage
		err = dec.Decode(&val)
		zero(val)
		if err != nil {
			return false
		}
	}
	t, err := dec.Token()
	return err == nil && t == json.Delim('}')
}

// handleTokenize implements POST /tokenize (§3.2, §5). The checks run in a fixed order and each
// failing check returns immediately; error bodies use only the msg* constants. Nothing from the
// request is logged.
func (v *vault) handleTokenize(w http.ResponseWriter, r *http.Request) {
	// SPEC-DECISION: a percent-encoded spelling of the path (e.g. /%74okenize) decodes to
	// "/tokenize" but is not the exact path, so it is 404 (RawPath is set only for such forms).
	if r.URL.Path != "/tokenize" || r.URL.RawPath != "" {
		writeError(w, http.StatusNotFound, msgNotFound)
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodOptions {
		w.Header().Set("Allow", "POST, OPTIONS")
		writeError(w, http.StatusMethodNotAllowed, msgMethod)
		return
	}
	// SPEC-DECISION: a bare trailing "?" (empty but present query) is rejected like any query.
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeError(w, http.StatusBadRequest, msgQuery)
		return
	}
	// The Origin must match exactly on POST as well as on the preflight (globals ruling 3). An
	// unset allow-origin matches nothing.
	if origin, ok := singleHeader(r.Header, "Origin"); !ok || v.allowOrigin == "" || origin != v.allowOrigin {
		writeError(w, http.StatusForbidden, msgOrigin)
		return
	}
	h := w.Header()
	if r.Method == http.MethodOptions {
		h.Set("Access-Control-Allow-Origin", v.allowOrigin)
		h.Set("Access-Control-Allow-Methods", "POST")
		h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		h.Set("Access-Control-Max-Age", "600")
		h.Set("Vary", "Origin")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// From here on every response, errors included, is readable by the checkout page.
	h.Set("Access-Control-Allow-Origin", v.allowOrigin)
	h.Set("Vary", "Origin")

	authz, ok := singleHeader(r.Header, "Authorization")
	reason := "format"
	if ok {
		reason = checkSession(v.hmacKey, authz, v.now())
	}
	if reason != "" {
		v.alertSession(reason)
		writeError(w, http.StatusUnauthorized, msgUnauthorized)
		return
	}

	if !jsonContentType(r.Header) {
		writeError(w, http.StatusBadRequest, msgContentType)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxPublicBody+1))
	defer zero(body) // best effort (§8.5)
	if len(body) > maxPublicBody {
		writeError(w, http.StatusRequestEntityTooLarge, msgTooLarge)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, msgBadBody)
		return
	}

	var req tokenizeRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, msgBadBody)
		return
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF || !exactKeys(body, tokenizeFields) {
		writeError(w, http.StatusBadRequest, msgBadBody)
		return
	}

	pan, ok := normalizePAN(req.PAN)
	if !ok {
		writeError(w, http.StatusBadRequest, msgInvalidPAN)
		return
	}
	if !validExpiry(req.ExpMonth, req.ExpYear, v.now()) {
		writeError(w, http.StatusBadRequest, msgInvalidExpiry)
		return
	}
	if req.CVV == nil {
		// Present-but-null shows up as a non-nil RawMessage ("null"); a missing key stays nil.
		// exactKeys has already guaranteed "cvv" appears at most once, spelled exactly.
		var raw struct {
			CVV json.RawMessage `json:"cvv"`
		}
		if json.Unmarshal(body, &raw) != nil || raw.CVV != nil {
			writeError(w, http.StatusBadRequest, msgInvalidCVV)
			return
		}
	} else if !validCVV(*req.CVV) {
		writeError(w, http.StatusBadRequest, msgInvalidCVV)
		return
	}
	name := ""
	if req.Name == nil {
		// As for cvv: present-but-null is a non-nil RawMessage ("null"); a missing key stays nil.
		var raw struct {
			Name json.RawMessage `json:"name"`
		}
		if json.Unmarshal(body, &raw) != nil || raw.Name != nil {
			writeError(w, http.StatusBadRequest, msgInvalidName)
			return
		}
	} else if !validName(*req.Name) {
		writeError(w, http.StatusBadRequest, msgInvalidName)
		return
	} else {
		name = *req.Name
	}

	dek, ok := v.deks[v.currentDEK]
	if !ok {
		writeError(w, http.StatusInternalServerError, msgInternal)
		return
	}
	plaintext, err := json.Marshal(card{PAN: pan, ExpMonth: req.ExpMonth, ExpYear: req.ExpYear, Name: name})
	if err != nil {
		writeError(w, http.StatusInternalServerError, msgInternal)
		return
	}
	ciphertext := seal(dek, plaintext)
	zero(plaintext) // best effort (§8.5)

	token := newToken()
	last4 := pan[len(pan)-4:]
	if err := v.putCard(r.Context(), token, ciphertext, last4, v.currentDEK); err != nil {
		// The error is never logged or returned: it could carry driver or query detail.
		writeError(w, http.StatusInternalServerError, msgInternal)
		return
	}
	if req.CVV != nil {
		v.cvv.put(token, *req.CVV)
	}
	writeJSON(w, http.StatusOK, tokenizeResponse{Token: token, Last4: last4, ExpMonth: req.ExpMonth, ExpYear: req.ExpYear})
}

// ---------------------------------------------------------------------------
// Provider catalog, egress invariant, PAN masking, outbound client (SPEC §6.3, §6.4, §9)
// ---------------------------------------------------------------------------

// opBuilder constructs the ENTIRE provider request for one op: path, content type and body.
// The PAN, expiry and CVV appear only where the builder puts them; nothing from the caller but
// declared param values ever reaches the body (§6.3).
type opBuilder func(params map[string]string, c card, cvv string) (path string, contentType string, body []byte, err error)

type provider struct {
	base   *url.URL                             // e.g. https://api.stripe.com
	secret string                               // loaded at boot; never from a request
	auth   func(r *http.Request, secret string) // how to attach the credential
	ops    map[string]op
}

type op struct {
	params map[string]bool // allowed param keys
	build  opBuilder
}

const (
	maxProviderResponse = 4 << 20 // §6.4 step 9: provider response body limit
	formContentType     = "application/x-www-form-urlencoded"
)

var (
	errBuild  = errors.New("invalid params")
	errEgress = errors.New("egress invariant")
)

// newProviders returns the provider catalog (§6.3 v1). It is being replaced by catalog.json (see
// parseCatalog), whose account hosts egress-hosts.<env>.txt must list (TestEgressHostsMatchCatalog).
func newProviders(stripeSecret string) map[string]provider {
	return map[string]provider{
		"stripe": {
			base:   &url.URL{Scheme: "https", Host: "api.stripe.com"},
			secret: stripeSecret,
			auth:   stripeAuth,
			ops: map[string]op{
				"create_payment_method": {params: map[string]bool{"customer": true}, build: stripeCreatePaymentMethod},
				"create_token":          {params: map[string]bool{}, build: stripeCreateToken},
			},
		},
	}
}

// stripeAuth attaches "Authorization: Bearer <secret>", replacing any value already present.
func stripeAuth(r *http.Request, secret string) {
	r.Header.Set("Authorization", "Bearer "+secret)
}

// stripeCard returns the card fields shared by both Stripe ops: card[number], card[exp_month],
// card[exp_year], and card[cvc] only if a CVV is available.
func stripeCard(c card, cvv string) url.Values {
	v := url.Values{
		"card[number]":    {c.PAN},
		"card[exp_month]": {c.ExpMonth},
		"card[exp_year]":  {c.ExpYear},
	}
	if cvv != "" {
		v.Set("card[cvc]", cvv)
	}
	return v
}

// stripeCreatePaymentMethod builds POST /v1/payment_methods (§6.3): type=card, the card fields,
// and customer if given.
// SPEC-DECISION: the builder re-checks its params even though the handler already enforced
// op.params: any undeclared key, or a customer that is present but empty, is an error rather
// than being dropped or sent.
func stripeCreatePaymentMethod(params map[string]string, c card, cvv string) (string, string, []byte, error) {
	for k := range params {
		if k != "customer" {
			return "", "", nil, errBuild
		}
	}
	v := stripeCard(c, cvv)
	v.Set("type", "card")
	if cus, ok := params["customer"]; ok {
		if cus == "" {
			return "", "", nil, errBuild
		}
		v.Set("customer", cus)
	}
	return "/v1/payment_methods", formContentType, []byte(v.Encode()), nil
}

// stripeCreateToken builds POST /v1/tokens (§6.3): the card fields only. It takes no params.
func stripeCreateToken(params map[string]string, c card, cvv string) (string, string, []byte, error) {
	if len(params) != 0 {
		return "", "", nil, errBuild
	}
	return "/v1/tokens", formContentType, []byte(stripeCard(c, cvv).Encode()), nil
}

// providerURL is the egress invariant (§6.4 step 6): it builds https://<base.Host><path> and
// returns errEgress unless the scheme is https and the host is exactly base.Host, both on the
// constructed URL and on a reparse of its string form (what the transport actually dials).
// SPEC-DECISION: also refused: a path not starting with "/", a base that is not https with a
// host, and a reparse that gains userinfo, a query or a fragment or changes the path.
func providerURL(base *url.URL, path string) (*url.URL, error) {
	if base == nil || base.Scheme != "https" || base.Host == "" || !strings.HasPrefix(path, "/") {
		return nil, errEgress
	}
	u := &url.URL{Scheme: "https", Host: base.Host, Path: path}
	if u.Scheme != "https" || u.Host != base.Host {
		return nil, errEgress
	}
	re, err := url.Parse(u.String())
	if err != nil || re.Scheme != "https" || re.Host != base.Host || re.User != nil ||
		re.RawQuery != "" || re.ForceQuery || re.Fragment != "" || re.Path != path {
		return nil, errEgress
	}
	return u, nil
}

// maskPAN replaces every occurrence of pan, and of pan grouped in fours from the left with single
// spaces ("4242 4242 4242 4242", "3782 8224 6310 005") or single hyphens ("4242-4242-4242-4242"),
// with "****"+last4 (§6.4 step 9). found reports whether anything was replaced; if not, body is
// returned unchanged.
// SPEC-DECISION: the hyphen-grouped form is masked too (§6.4 names only the exact and spaced
// forms; hyphens are the other separator normalizePAN accepts). The replacement repeats until no
// form remains: one bytes.ReplaceAll pass over pan+pan[4:] leaves a full PAN when the last 4
// digits equal the first 4 ("4242…4242" + "4242…" → "****4242" + "4242…"). Each pass replaces a
// needle of >= 13 bytes with an 8-byte mask, so the body strictly shrinks and the loop ends.
func maskPAN(body []byte, pan string) ([]byte, bool) {
	if len(pan) < 13 { // never a real PAN (§5.5); keeps every needle longer than the mask
		return body, false
	}
	var spaced, hyphen strings.Builder
	for i := 0; i < len(pan); i++ {
		if i > 0 && i%4 == 0 {
			spaced.WriteByte(' ')
			hyphen.WriteByte('-')
		}
		spaced.WriteByte(pan[i])
		hyphen.WriteByte(pan[i])
	}
	forms := [][]byte{[]byte(pan), []byte(spaced.String()), []byte(hyphen.String())}
	mask := []byte("****" + pan[len(pan)-4:])
	found := false
	for again := true; again; {
		again = false
		for _, form := range forms {
			if bytes.Contains(body, form) {
				body = bytes.ReplaceAll(body, form, mask)
				found, again = true, true
			}
		}
	}
	return body, found
}

// newOutboundClient returns the single shared provider client (§6.4 step 8, §9.2): 30s hard
// timeout, redirects never followed, no proxy from the environment, TLS >= 1.2 verified against
// roots (nil = system roots; tests pass an httptest server's CA), 16 idle conns per host.
func newOutboundClient(roots *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy:               nil, // never HTTP_PROXY/HTTPS_PROXY
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 16,
			TLSHandshakeTimeout: 10 * time.Second,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

// ---------------------------------------------------------------------------
// Placeholders and strict body scanners (D§5.3, D§5.4)
// ---------------------------------------------------------------------------

// placeholder is one entry of the fixed D§5.3 vocabulary: kind is pan, cvv, name, exp_month,
// exp_year, exp, secret, basic or signature; mod is the format modifier (int, yy, yyyy/mm,
// mm/yy) and arg the secret NAME of secret/basic.
type placeholder struct{ kind, mod, arg string }

// parsePlaceholder parses s, which must be exactly the whole "{{...}}" text of one vocabulary
// placeholder: no whitespace, no other kinds or modifiers, NAME matching [A-Za-z0-9_]{1,64}.
func parsePlaceholder(s string) (placeholder, bool) {
	inner, ok := strings.CutPrefix(s, "{{")
	if !ok {
		return placeholder{}, false
	}
	inner, ok = strings.CutSuffix(inner, "}}")
	if !ok {
		return placeholder{}, false
	}
	kind, mod, hasMod := strings.Cut(inner, ":")
	switch kind {
	case "pan", "cvv", "name", "signature":
		if !hasMod {
			return placeholder{kind: kind}, true
		}
	case "exp_month":
		if !hasMod || mod == "int" {
			return placeholder{kind: kind, mod: mod}, true
		}
	case "exp_year":
		if !hasMod || mod == "yy" || mod == "int" {
			return placeholder{kind: kind, mod: mod}, true
		}
	case "exp":
		if hasMod && (mod == "yyyy/mm" || mod == "mm/yy") {
			return placeholder{kind: kind, mod: mod}, true
		}
	case "secret", "basic":
		if hasMod && validSecretName(mod) {
			return placeholder{kind: kind, arg: mod}, true
		}
	}
	return placeholder{}, false
}

// validSecretName reports whether s matches [A-Za-z0-9_]{1,64}.
func validSecretName(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// isCard reports whether p is filled from card data (pan, cvv, name and the expiry forms).
func (p placeholder) isCard() bool {
	switch p.kind {
	case "pan", "cvv", "name", "exp_month", "exp_year", "exp":
		return true
	}
	return false
}

// isNumber reports whether p is replaced, quotes included, by a bare number (the :int forms).
func (p placeholder) isNumber() bool { return p.mod == "int" }

// String returns the canonical "{{kind[:mod|:arg]}}" text; parsePlaceholder(p.String()) == p.
func (p placeholder) String() string {
	s := p.kind
	if p.mod != "" {
		s += ":" + p.mod
	}
	if p.arg != "" {
		s += ":" + p.arg
	}
	return "{{" + s + "}}"
}

// occurrence is one placeholder found in a body by scanBody.
type occurrence struct {
	addr       string // JSON Pointer (json) or decoded field name (form)
	ph         placeholder
	start, end int // byte span of the raw value (JSON: including the quotes)
}

// fieldValue is a body field read by readField. kind is string, number, bool, null, object or
// array; text is the decoded string, or the raw JSON text of anything else (numbers exactly as
// written, so "3.50" stays "3.50").
type fieldValue struct{ kind, text string }

var (
	errBody        = errors.New("invalid body")            // parse/strictness failure
	errPlaceholder = errors.New("invalid placeholder use") // placeholder-looking text where it is not allowed
)

// SPEC-DECISION: JSON nesting deeper than 64 objects/arrays is rejected. Provider bodies nest a
// handful of levels; the cap bounds work on pathological input well below encoding/json's own.
const maxJSONDepth = 64

// jsonNode is one token of a JSON body as walked by jsonWalk, in document order. Values carry the
// JSON Pointer of the value; a "key" node carries the pointer of the member it names. text is the
// decoded string (string, key) or the raw text (number, bool, null, object, array); [start, end)
// is the raw span, strings including their quotes.
type jsonNode struct {
	ptr        string
	kind       string // key string number bool null object array
	text       string
	start, end int
}

// jsonPointerEscaper escapes one RFC 6901 reference token ("~" first, then "/").
var jsonPointerEscaper = strings.NewReplacer("~", "~0", "/", "~1")

// jsonWalk parses b strictly and returns every key and value with its pointer and raw span. b must
// be valid UTF-8 holding exactly one JSON value (whitespace around it only), with no duplicate keys
// in any object (compared after decoding escapes) and at most maxJSONDepth levels of nesting.
// Any failure is errBody.
// SPEC-DECISION: a string or key whose decoded text contains U+FFFD is rejected. encoding/json
// silently decodes a lone surrogate escape ("\ud800") to U+FFFD, which other parsers reject or
// keep, so such a body could be read differently by the provider; a literal or escaped U+FFFD is
// indistinguishable after decoding and goes with it. A UTF-8 BOM is invalid JSON and rejected.
// SPEC-DECISION: a key whose decoded text contains a control character (U+0000-U+001F) is
// rejected, so a provider parser that truncates at NUL or strips control characters cannot alias
// "merchantAccount\u0000" to "merchantAccount" and bypass a pin or forbid rule.
//
// Raw spans: Token() leaves InputOffset at the end of the token it returned, and the separators
// before the next token (whitespace, ':' and ',') are consumed only by the next call. So a token
// starts at the first byte after the previous token's end that is not whitespace, ':' or ',', and
// ends at the new InputOffset. Each span is checked against the token (quotes, delimiter byte,
// number text) and any mismatch fails closed.
func jsonWalk(b []byte) ([]jsonNode, error) {
	if !utf8.Valid(b) {
		return nil, errBody
	}
	type frame struct {
		ptr   string
		array bool
		index int             // next array index
		keys  map[string]bool // object keys seen
		key   string          // pending member key (object)
		node  int             // index of the container's node
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var nodes []jsonNode
	var stack []*frame
	prev := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, errBody
		}
		end := int(dec.InputOffset())
		start := prev
		for start < end && (b[start] == ' ' || b[start] == '\t' || b[start] == '\n' || b[start] == '\r' || b[start] == ':' || b[start] == ',') {
			start++
		}
		prev = end
		if start >= end || end > len(b) {
			return nil, errBody
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}

		// An object member key.
		if top != nil && !top.array && top.key == "" && tok != json.Delim('}') {
			k, ok := tok.(string)
			if !ok || !jsonStringSpan(b, start, end) || strings.ContainsRune(k, utf8.RuneError) ||
				strings.ContainsFunc(k, func(r rune) bool { return r < 0x20 }) || top.keys[k] {
				return nil, errBody
			}
			top.keys[k] = true
			top.key = "/" + jsonPointerEscaper.Replace(k) // non-empty even for the "" key
			nodes = append(nodes, jsonNode{ptr: top.ptr + top.key, kind: "key", text: k, start: start, end: end})
			continue
		}

		// A closing delimiter ends the top frame's container.
		if tok == json.Delim('}') || tok == json.Delim(']') {
			if top == nil || end != start+1 || b[start] != byte(tok.(json.Delim)) {
				return nil, errBody
			}
			stack = stack[:len(stack)-1]
			nodes[top.node].end = end
			nodes[top.node].text = string(b[nodes[top.node].start:end])
		} else {
			// A value: its pointer comes from the enclosing container.
			ptr := ""
			if top != nil {
				if top.array {
					ptr = top.ptr + "/" + strconv.Itoa(top.index)
					top.index++
				} else {
					ptr = top.ptr + top.key
					top.key = ""
				}
			}
			n := jsonNode{ptr: ptr, start: start, end: end}
			switch t := tok.(type) {
			case json.Delim:
				if end != start+1 || b[start] != byte(t) || len(stack) >= maxJSONDepth {
					return nil, errBody
				}
				n.kind = "object"
				f := &frame{ptr: ptr, node: len(nodes), keys: map[string]bool{}}
				if t == json.Delim('[') {
					n.kind, f.array, f.keys = "array", true, nil
				}
				stack = append(stack, f)
			case string:
				if !jsonStringSpan(b, start, end) || strings.ContainsRune(t, utf8.RuneError) {
					return nil, errBody
				}
				n.kind, n.text = "string", t
			case json.Number:
				n.kind, n.text = "number", string(t)
			case bool:
				n.kind, n.text = "bool", strconv.FormatBool(t)
			case nil:
				n.kind, n.text = "null", "null"
			default:
				return nil, errBody
			}
			if n.kind != "string" && n.kind != "object" && n.kind != "array" && string(b[start:end]) != n.text {
				return nil, errBody
			}
			nodes = append(nodes, n)
		}

		// The root value is complete: only whitespace may follow.
		if len(stack) == 0 {
			if len(bytes.TrimLeft(b[end:], " \t\r\n")) != 0 {
				return nil, errBody
			}
			return nodes, nil
		}
	}
}

// jsonStringSpan reports whether b[start:end] looks like one complete JSON string token: it starts
// and ends with a quote and has no unescaped quote in between.
func jsonStringSpan(b []byte, start, end int) bool {
	if end-start < 2 || b[start] != '"' || b[end-1] != '"' {
		return false
	}
	for i := start + 1; i < end-1; i++ {
		switch b[i] {
		case '\\':
			i++
		case '"':
			return false
		}
	}
	return true
}

// jsonStrict checks that b is valid UTF-8 holding exactly one JSON value with no trailing data and
// no duplicate keys at any depth (see jsonWalk). It returns errBody or nil.
func jsonStrict(b []byte) error {
	_, err := jsonWalk(b)
	return err
}

// formField is one key=value pair of a form body, decoded, with the raw value's byte span.
type formField struct {
	key, value string
	start, end int
}

// formFields parses a form body strictly into its fields, in order. Keys must be canonical (see
// validFormKey) and unique unless they end in "[]". Any failure is errBody, except that a body
// whose only failure is a key containing "{{" is errPlaceholder (strictness failures win).
// SPEC-DECISION: stricter than url.ParseQuery, so no two parsers can split the body differently:
// every raw byte must be visible ASCII (0x21-0x7E; spaces as "+", everything else percent-encoded),
// ';' is rejected outright (some parsers treat it as a separator), every '&'-separated segment must
// be key=value with a non-empty key (no empty segments, no bare keys), percent-escapes must be
// valid and the decoded key and value must be valid UTF-8. An empty body is zero fields.
func formFields(b []byte) ([]formField, error) {
	if len(b) == 0 {
		return nil, nil
	}
	for _, c := range b {
		if c < 0x21 || c > 0x7e || c == ';' {
			return nil, errBody
		}
	}
	var fields []formField
	seen := map[string]bool{}
	placeholderKey := false
	pos := 0
	for _, seg := range strings.Split(string(b), "&") {
		rawKey, rawVal, ok := strings.Cut(seg, "=")
		if !ok || rawKey == "" {
			return nil, errBody
		}
		key, err1 := url.QueryUnescape(rawKey)
		val, err2 := url.QueryUnescape(rawVal)
		if err1 != nil || err2 != nil || !utf8.ValidString(key) || !utf8.ValidString(val) {
			return nil, errBody
		}
		if !validFormKey(key) {
			if !strings.Contains(key, "{{") {
				return nil, errBody
			}
			placeholderKey = true
		}
		if seen[key] && !strings.HasSuffix(key, "[]") {
			return nil, errBody
		}
		seen[key] = true
		vstart := pos + len(rawKey) + 1
		fields = append(fields, formField{key: key, value: val, start: vstart, end: vstart + len(rawVal)})
		pos += len(seg) + 1
	}
	if placeholderKey {
		return nil, errPlaceholder
	}
	return fields, nil
}

// formKeyRe is the canonical form key grammar: a name, then [segment] groups, then an optional
// final "[]".
var formKeyRe = regexp.MustCompile(`^[A-Za-z0-9_-]+(\[[A-Za-z0-9_-]+\])*(\[\])?$`)

// validFormKey reports whether a decoded form key is canonical.
// SPEC-DECISION: bracket-parsing servers (Rack, PHP, qs) normalize malformed keys, mapping
// "customer]", "[customer" or "a[b]c" onto other names, and NUL or control bytes can truncate a
// key. Such aliases would bypass duplicate detection and the pin/forbid rules, which match the
// flat decoded name. So a key must be a name of [A-Za-z0-9_-] followed by zero or more non-empty
// [segment] groups of the same characters and at most one trailing "[]". Stricter than a plain
// bracket grammar: "." is excluded (PHP rewrites "a.b" to "a_b") and "[]" is allowed only last
// (a mid-key "[]" appends to an array whose element a name cannot address uniquely).
func validFormKey(k string) bool {
	return formKeyRe.MatchString(k)
}

// scanBody parses body strictly in format ("json" or "form") and returns every placeholder
// occurrence, sorted by start. Text containing "{{" anywhere a placeholder is not allowed is
// errPlaceholder, never passed through: every decoded JSON string or form value containing "{{"
// is either an occurrence or an error, so no placeholder can skip the position check.
//   - json: a string value containing "{{" (after decoding escapes) must be raw-exactly '"' + a
//     vocabulary placeholder + '"'; a key containing "{{" is always an error.
//   - form: a value containing "{{" (after percent-decoding) must be raw-exactly a vocabulary
//     placeholder, and never under a "[]" key (repeatable, so not a unique position); a key
//     containing "{{" is always an error.
//
// Strictness failures (errBody) take precedence over placeholder failures.
func scanBody(format string, body []byte) ([]occurrence, error) {
	var occs []occurrence
	switch format {
	case "json":
		nodes, err := jsonWalk(body)
		if err != nil {
			return nil, err
		}
		for _, n := range nodes {
			if !strings.Contains(n.text, "{{") || (n.kind != "key" && n.kind != "string") {
				continue
			}
			if n.kind == "key" {
				return nil, errPlaceholder
			}
			raw := string(body[n.start+1 : n.end-1])
			ph, ok := parsePlaceholder(raw)
			if !ok || raw != n.text {
				return nil, errPlaceholder
			}
			occs = append(occs, occurrence{addr: n.ptr, ph: ph, start: n.start, end: n.end})
		}
	case "form":
		fields, err := formFields(body)
		if err != nil {
			return nil, err
		}
		for _, f := range fields {
			if strings.Contains(f.key, "{{") {
				return nil, errPlaceholder
			}
			if !strings.Contains(f.value, "{{") {
				continue
			}
			raw := string(body[f.start:f.end])
			ph, ok := parsePlaceholder(raw)
			if !ok || raw != f.value || strings.HasSuffix(f.key, "[]") {
				return nil, errPlaceholder
			}
			occs = append(occs, occurrence{addr: f.key, ph: ph, start: f.start, end: f.end})
		}
	default:
		return nil, errBody
	}
	return occs, nil
}

// readField returns the value at addr (a JSON Pointer for json, a decoded field name for form).
// found is false when the body is valid but has no such field. A body failing the strict parse is
// errBody (errPlaceholder for a form key containing "{{"). Form values are always kind "string".
// SPEC-DECISION: a form key that appears more than once (only possible for "[]" keys) has no single
// value, so reading it is errBody rather than picking one.
func readField(format string, body []byte, addr string) (fieldValue, bool, error) {
	switch format {
	case "json":
		nodes, err := jsonWalk(body)
		if err != nil {
			return fieldValue{}, false, err
		}
		for _, n := range nodes {
			if n.kind != "key" && n.ptr == addr {
				return fieldValue{kind: n.kind, text: n.text}, true, nil
			}
		}
		return fieldValue{}, false, nil
	case "form":
		fields, err := formFields(body)
		if err != nil {
			return fieldValue{}, false, err
		}
		var v fieldValue
		found := false
		for _, f := range fields {
			if f.key == addr {
				if found {
					return fieldValue{}, false, errBody
				}
				v, found = fieldValue{kind: "string", text: f.value}, true
			}
		}
		return v, found, nil
	}
	return fieldValue{}, false, errBody
}

// encodeValue encodes v for substitution in format: json as a quoted JSON string, or as a bare
// number when number is set; form as url.QueryEscape(v).
// SPEC-DECISION: a number is emitted bare only when v is 1-18 ASCII digits, and then in canonical
// form ("03" → 3; a leading zero is invalid JSON). Anything else is encoded as a string, so the
// output is always a valid JSON value or form value; callers only pass digits. An unknown format is
// a programming error and panics.
func encodeValue(format string, v string, number bool) []byte {
	if number && len(v) >= 1 && len(v) <= 18 && strings.Trim(v, "0123456789") == "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			v = strconv.FormatInt(n, 10)
			if format == "json" {
				return []byte(v)
			}
		}
	}
	switch format {
	case "json":
		out, err := json.Marshal(v)
		if err != nil {
			panic("encodeValue: marshal failed")
		}
		return out
	case "form":
		return []byte(url.QueryEscape(v))
	}
	panic("encodeValue: unknown format")
}

// substitute returns a copy of body with each span occs[i] replaced by repl[i]; every other byte is
// unchanged. occs must be sorted by start, non-overlapping and within body, with one repl each;
// anything else is a programming error and panics (a fixed message, never body bytes).
func substitute(body []byte, occs []occurrence, repl [][]byte) []byte {
	if len(occs) != len(repl) {
		panic("substitute: invalid spans")
	}
	out := make([]byte, 0, len(body))
	prev := 0
	for i, o := range occs {
		if o.start < prev || o.end < o.start || o.end > len(body) {
			panic("substitute: invalid spans")
		}
		out = append(out, body[prev:o.start]...)
		out = append(out, repl[i]...)
		prev = o.end
	}
	return append(out, body[prev:]...)
}

// ---------------------------------------------------------------------------
// Provider catalog: catalog.json (D§5.1, D§5.5-5.7, D§5.10)
// ---------------------------------------------------------------------------

// catalogJSON is the reviewed provider catalog, compiled into the binary (D§5.1). It is never read
// from disk at runtime, so the image digest attests the exact catalog. Adding a provider, endpoint
// or account is a PR that also updates egress-hosts.<env>.txt and the egress firewall rule;
// TestEgressHostsMatchCatalog keeps the files and the catalog in step.
//
//go:embed catalog.json
var catalogJSON []byte

// catalog is the parsed catalog.json: every provider, and the accounts of one environment.
type catalog struct {
	providers map[string]*catProvider
	accounts  map[string]*catAccount // only accounts whose env == the env passed to parseCatalog
}

type catProvider struct {
	name, format string
	endpoints    []*catEndpoint
}

// catEndpoint is one allowed provider call.
type catEndpoint struct {
	id, method string
	path       []string        // segments; "{name}" = wildcard [A-Za-z0-9_-]{1,128}
	query      map[string]bool // allowed query keys (usually empty)
	cardData   bool
	headers    map[string]string       // canonical header name → exact value template
	positions  map[string]placeholder  // address → the one placeholder allowed there
	pins       map[string]catPin       // address → required value
	forbid     map[string][]fieldValue // address → allowed literals; empty slice = must be absent
	signer     string                  // "" or "payu"
}

// catPin is a pinned body field: it must equal the named account value, or a fixed literal.
type catPin struct {
	account string      // name of an account value, or
	literal *fieldValue // a fixed literal
}

// catAccount is one of our provider accounts.
type catAccount struct {
	name, provider, env, host, basePath string
	secretNames                         map[string]string // name → Secret Manager resource
	values                              map[string]string
	secrets                             map[string]string // filled at boot (Task 7)
}

// Raw decode targets. Their JSON names are the catalog.json schema:
//
//	{"providers": {NAME: {"format": "json"|"form", "endpoints": [{"id", "method", "path", "query": [KEY],
//	   "card_data": BOOL, "headers": {NAME: TEMPLATE}, "positions": {ADDR: PLACEHOLDER},
//	   "pins": {ADDR: {"account": VALUE_NAME} | {"literal": SCALAR}}, "forbid": {ADDR: [SCALAR]},
//	   "signer": "payu"}]}},
//	 "accounts": {NAME: {"provider", "env": "dev"|"prod", "host", "base_path",
//	   "secrets": {NAME: RESOURCE}, "values": {NAME: VALUE}}}}
type rawCatalog struct {
	Providers map[string]rawProvider `json:"providers"`
	Accounts  map[string]rawAccount  `json:"accounts"`
}

type rawProvider struct {
	Format    string        `json:"format"`
	Endpoints []rawEndpoint `json:"endpoints"`
}

type rawEndpoint struct {
	ID        string                     `json:"id"`
	Method    string                     `json:"method"`
	Path      string                     `json:"path"`
	Query     []string                   `json:"query"`
	CardData  bool                       `json:"card_data"`
	Headers   map[string]string          `json:"headers"`
	Positions map[string]string          `json:"positions"`
	Pins      map[string]rawPin          `json:"pins"`
	Forbid    map[string]json.RawMessage `json:"forbid"`
	Signer    string                     `json:"signer"`
}

type rawPin struct {
	Account *string         `json:"account"`
	Literal json.RawMessage `json:"literal"`
}

type rawAccount struct {
	Provider string            `json:"provider"`
	Env      string            `json:"env"`
	Host     string            `json:"host"`
	BasePath string            `json:"base_path"`
	Secrets  map[string]string `json:"secrets"`
	Values   map[string]string `json:"values"`
}

// The exact key sets of each catalog.json object that decodes into a struct.
var (
	catRootKeys     = map[string]bool{"providers": true, "accounts": true}
	catProviderKeys = map[string]bool{"format": true, "endpoints": true}
	catEndpointKeys = map[string]bool{"id": true, "method": true, "path": true, "query": true, "card_data": true,
		"headers": true, "positions": true, "pins": true, "forbid": true, "signer": true}
	catPinKeys     = map[string]bool{"account": true, "literal": true}
	catAccountKeys = map[string]bool{"provider": true, "env": true, "host": true, "base_path": true, "secrets": true, "values": true}
)

// SPEC-DECISION: provider names, endpoint ids and account names are [a-z0-9_]{1,64}. They appear in
// logs and alerts (account=<a> endpoint=<id>), so a restricted alphabet rules out log injection.
var catNameRe = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// catHostRe is the account host shape: a lowercase DNS name or IPv4 address, optional port.
var catHostRe = regexp.MustCompile(`^[a-z0-9.-]+(:[0-9]{1,5})?$`)

// catSegmentRe is a literal path segment: RFC 3986 unreserved characters only.
// SPEC-DECISION: no percent-escapes, sub-delims or ':' in catalog paths, so a rule path has one
// spelling and cannot be normalized into another by the provider.
var catSegmentRe = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

// SPEC-DECISION: catalog header templates may not name the headers the vault sets (Host,
// Content-Type, Content-Length, User-Agent), transfer and hop-by-hop headers, or the platform
// allowlist (Accept, Idempotency-Key, X-Idempotency-Key): a template there would compete with the
// vault's own value or with the platform's.
var catReservedHeaders = map[string]bool{
	"Host": true, "Content-Type": true, "Content-Length": true, "User-Agent": true, "Transfer-Encoding": true,
	"Connection": true, "Keep-Alive": true, "Proxy-Authorization": true, "Proxy-Connection": true, "Te": true,
	"Trailer": true, "Upgrade": true, "Content-Encoding": true,
	"Accept": true, "Idempotency-Key": true, "X-Idempotency-Key": true,
}

var catHeaderNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)

// parseCatalog parses and validates catalog.json. Every provider and every account in every
// environment is validated; only the accounts of env ("dev" or "prod") are kept. Errors name the
// provider, endpoint, account or address at fault, never a secret resource or account value.
// The rules are those of D§5.1-5.7 and D§5.10; the SPEC-DECISION comments on the helpers below
// record where they are stricter.
func parseCatalog(data []byte, env string) (*catalog, error) {
	if env != "dev" && env != "prod" {
		return nil, errors.New("catalog: environment must be dev or prod")
	}
	// jsonWalk is jsonStrict's parser: one value, no duplicate keys at any depth, no trailing data,
	// valid UTF-8. Its nodes also give every key's position for the exact-key check below.
	nodes, err := jsonWalk(data)
	if err != nil || nodes[0].kind != "object" {
		return nil, errors.New("catalog: not strict JSON (one object, no duplicate keys or trailing data, valid UTF-8)")
	}
	if err := catExactKeys(nodes); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var raw rawCatalog
	if err := dec.Decode(&raw); err != nil {
		// Never the decoder's message: an UnmarshalTypeError's Value can hold the offending number.
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) {
			return nil, fmt.Errorf("catalog: wrong type at %q", te.Field)
		}
		return nil, errors.New("catalog: invalid structure")
	}

	c := &catalog{providers: map[string]*catProvider{}, accounts: map[string]*catAccount{}}
	for _, name := range slices.Sorted(maps.Keys(raw.Providers)) {
		p, err := parseCatProvider(name, raw.Providers[name])
		if err != nil {
			return nil, err
		}
		c.providers[name] = p
	}
	for _, name := range slices.Sorted(maps.Keys(raw.Accounts)) {
		a, err := parseCatAccount(name, raw.Accounts[name], c.providers)
		if err != nil {
			return nil, err
		}
		if a.env == env {
			c.accounts[name] = a
		}
	}
	return c, nil
}

// catExactKeys checks every key of an object that decodes into a struct against that struct's
// exact key set. The struct objects sit at fixed depths: the root, /providers/P,
// /providers/P/endpoints/I, /providers/P/endpoints/I/pins/A and /accounts/A.
// SPEC-DECISION: encoding/json matches struct keys case-insensitively, so DisallowUnknownFields
// alone accepts "Format" for "format", and {"format":"json","Format":"form"} passes the
// duplicate-key check yet decodes as "form". Keys must be spelled exactly.
func catExactKeys(nodes []jsonNode) error {
	for _, n := range nodes {
		if n.kind != "key" {
			continue
		}
		// n.ptr is the parent's pointer plus one escaped token; tokens contain no raw "/".
		parentPtr := n.ptr[:strings.LastIndex(n.ptr, "/")]
		parent := strings.Split(parentPtr, "/")[1:]
		var allowed map[string]bool
		switch {
		case parentPtr == "":
			allowed = catRootKeys
		case len(parent) == 2 && parent[0] == "providers":
			allowed = catProviderKeys
		case len(parent) == 4 && parent[0] == "providers" && parent[2] == "endpoints":
			allowed = catEndpointKeys
		case len(parent) == 6 && parent[0] == "providers" && parent[2] == "endpoints" && parent[4] == "pins":
			allowed = catPinKeys
		case len(parent) == 2 && parent[0] == "accounts":
			allowed = catAccountKeys
		default:
			continue // a map key (names, addresses, headers) or inside a literal
		}
		if !allowed[n.text] {
			return fmt.Errorf("catalog: unknown key %q in %q", n.text, parentPtr)
		}
	}
	return nil
}

// parseCatProvider validates one provider and its endpoints.
// SPEC-DECISION: a provider must have at least one endpoint, and no two of its endpoints may share
// a method and overlapping paths (equal segment by segment, a wildcard matching anything), so a
// request path matches at most one rule.
func parseCatProvider(name string, rp rawProvider) (*catProvider, error) {
	if !catNameRe.MatchString(name) {
		return nil, fmt.Errorf("catalog: provider %q: invalid name", name)
	}
	if rp.Format != "json" && rp.Format != "form" {
		return nil, fmt.Errorf("catalog: provider %q: format must be json or form", name)
	}
	if len(rp.Endpoints) == 0 {
		return nil, fmt.Errorf("catalog: provider %q: no endpoints", name)
	}
	p := &catProvider{name: name, format: rp.Format}
	for i, re := range rp.Endpoints {
		e, err := parseCatEndpoint(p.format, i, re)
		if err != nil {
			return nil, fmt.Errorf("catalog: provider %q: %w", name, err)
		}
		for _, o := range p.endpoints {
			if o.id == e.id {
				return nil, fmt.Errorf("catalog: provider %q: endpoint %q: duplicate id", name, e.id)
			}
			if o.method == e.method && catPathsOverlap(o.path, e.path) {
				return nil, fmt.Errorf("catalog: provider %q: endpoints %q and %q overlap", name, o.id, e.id)
			}
		}
		p.endpoints = append(p.endpoints, e)
	}
	return p, nil
}

// parseCatEndpoint validates one endpoint rule of a provider with body format format.
// SPEC-DECISION: beyond D§5.3, (1) {{basic:}} is header-only, (2) an endpoint with card_data must
// list at least one card position, (3) the payu signer needs a json provider (it reads body fields
// by JSON Pointer), (4) the whole-document address "" and empty JSON Pointer tokens are rejected,
// and (5) form positions and pins may not use a repeatable "[]" key (it names no single value).
func parseCatEndpoint(format string, i int, re rawEndpoint) (*catEndpoint, error) {
	if !catNameRe.MatchString(re.ID) {
		return nil, fmt.Errorf("endpoint #%d: invalid id", i)
	}
	id := re.ID
	switch re.Method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
	default:
		return nil, fmt.Errorf("endpoint %q: method %q not allowed", id, re.Method)
	}
	path, ok := parseCatPath(re.Path, true)
	if !ok {
		return nil, fmt.Errorf("endpoint %q: invalid path", id)
	}
	e := &catEndpoint{id: id, method: re.Method, path: path, cardData: re.CardData, query: map[string]bool{},
		headers: map[string]string{}, positions: map[string]placeholder{}, pins: map[string]catPin{},
		forbid: map[string][]fieldValue{}, signer: re.Signer}

	for _, k := range re.Query {
		if !validFormKey(k) || e.query[k] {
			return nil, fmt.Errorf("endpoint %q: query key %q invalid or repeated", id, k)
		}
		e.query[k] = true
	}

	usesSignature := false
	for _, k := range slices.Sorted(maps.Keys(re.Headers)) {
		if !catHeaderNameRe.MatchString(k) {
			return nil, fmt.Errorf("endpoint %q: invalid header name %q", id, k)
		}
		name := http.CanonicalHeaderKey(k)
		if catReservedHeaders[name] {
			return nil, fmt.Errorf("endpoint %q: header %q: vault-owned or platform header", id, name)
		}
		if _, dup := e.headers[name]; dup {
			return nil, fmt.Errorf("endpoint %q: duplicate header %q", id, name)
		}
		ph, ok := parseHeaderTemplate(re.Headers[k])
		if ok && ph.isCard() {
			return nil, fmt.Errorf("endpoint %q: header %q: card placeholder in header", id, name)
		}
		if !ok || (ph.kind != "secret" && ph.kind != "basic" && ph.kind != "signature") {
			return nil, fmt.Errorf("endpoint %q: header %q: template must hold exactly one {{secret:NAME}}, {{basic:NAME}} or {{signature}} in printable ASCII", id, name)
		}
		usesSignature = usesSignature || ph.kind == "signature"
		e.headers[name] = re.Headers[k]
	}

	hasCard := false
	for _, addr := range slices.Sorted(maps.Keys(re.Positions)) {
		if !validCatAddress(format, addr) || (format == "form" && strings.HasSuffix(addr, "[]")) {
			return nil, fmt.Errorf("endpoint %q: position %q: invalid address", id, addr)
		}
		ph, ok := parsePlaceholder(re.Positions[addr])
		if !ok {
			return nil, fmt.Errorf("endpoint %q: position %q: unknown placeholder", id, addr)
		}
		if ph.kind == "basic" {
			return nil, fmt.Errorf("endpoint %q: position %q: {{basic:}} is only allowed in headers", id, addr)
		}
		if ph.isCard() && !re.CardData {
			return nil, fmt.Errorf("endpoint %q: position %q: card placeholder without card_data", id, addr)
		}
		hasCard = hasCard || ph.isCard()
		usesSignature = usesSignature || ph.kind == "signature"
		e.positions[addr] = ph
	}
	if re.CardData && !hasCard {
		return nil, fmt.Errorf("endpoint %q: card_data without a card position", id)
	}

	for _, addr := range slices.Sorted(maps.Keys(re.Pins)) {
		if !validCatAddress(format, addr) || (format == "form" && strings.HasSuffix(addr, "[]")) {
			return nil, fmt.Errorf("endpoint %q: pin %q: invalid address", id, addr)
		}
		if _, dup := e.positions[addr]; dup {
			return nil, fmt.Errorf("endpoint %q: address %q appears in more than one of positions, pins and forbid", id, addr)
		}
		rp := re.Pins[addr]
		hasLiteral := len(rp.Literal) != 0 && string(rp.Literal) != "null"
		if (rp.Account != nil) == hasLiteral {
			return nil, fmt.Errorf("endpoint %q: pin %q: needs exactly one of account and literal", id, addr)
		}
		if rp.Account != nil {
			if !validSecretName(*rp.Account) {
				return nil, fmt.Errorf("endpoint %q: pin %q: invalid account value name", id, addr)
			}
			e.pins[addr] = catPin{account: *rp.Account}
			continue
		}
		v, ok := catLiteral(format, rp.Literal, false)
		if !ok {
			return nil, fmt.Errorf("endpoint %q: pin %q: invalid literal", id, addr)
		}
		e.pins[addr] = catPin{literal: &v}
	}

	for _, addr := range slices.Sorted(maps.Keys(re.Forbid)) {
		if !validCatAddress(format, addr) {
			return nil, fmt.Errorf("endpoint %q: forbid %q: invalid address", id, addr)
		}
		_, inPositions := e.positions[addr]
		_, inPins := e.pins[addr]
		if inPositions || inPins {
			return nil, fmt.Errorf("endpoint %q: address %q appears in more than one of positions, pins and forbid", id, addr)
		}
		var elems []json.RawMessage
		if !bytes.HasPrefix(bytes.TrimSpace(re.Forbid[addr]), []byte("[")) || json.Unmarshal(re.Forbid[addr], &elems) != nil {
			return nil, fmt.Errorf("endpoint %q: forbid %q: must be a list of allowed literals", id, addr)
		}
		allowed := []fieldValue{} // non-nil: an empty list means "must be absent"
		for _, el := range elems {
			v, ok := catLiteral(format, el, true)
			if !ok {
				return nil, fmt.Errorf("endpoint %q: forbid %q: invalid literal", id, addr)
			}
			allowed = append(allowed, v)
		}
		e.forbid[addr] = allowed
	}

	switch e.signer {
	case "":
		if usesSignature {
			return nil, fmt.Errorf("endpoint %q: {{signature}} without signer", id)
		}
	case "payu":
		if format != "json" {
			return nil, fmt.Errorf("endpoint %q: signer payu needs a json provider", id)
		}
		if !usesSignature {
			return nil, fmt.Errorf("endpoint %q: signer without {{signature}} position or header", id)
		}
	default:
		return nil, fmt.Errorf("endpoint %q: unknown signer %q", id, e.signer)
	}
	return e, nil
}

// parseCatPath splits a rule path ("/a/{name}/b") or a base path into segments. Every segment must
// be a literal of RFC 3986 unreserved characters other than "." and "..", or, if wildcards is set,
// "{name}" with name [A-Za-z0-9_]{1,64}, each name at most once.
func parseCatPath(p string, wildcards bool) ([]string, bool) {
	rest, ok := strings.CutPrefix(p, "/")
	if !ok || len(p) > 1024 {
		return nil, false
	}
	segs := strings.Split(rest, "/")
	names := map[string]bool{}
	for _, s := range segs {
		if inner, ok := strings.CutPrefix(s, "{"); ok && wildcards {
			name, ok := strings.CutSuffix(inner, "}")
			if !ok || !validSecretName(name) || names[name] {
				return nil, false
			}
			names[name] = true
			continue
		}
		if s == "." || s == ".." || !catSegmentRe.MatchString(s) {
			return nil, false
		}
	}
	return segs, true
}

// catIsWildcard reports whether a parsed path segment is a "{name}" wildcard.
func catIsWildcard(s string) bool { return strings.HasPrefix(s, "{") }

// catPathsOverlap reports whether some request path matches both segment patterns a and b.
func catPathsOverlap(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] && !catIsWildcard(a[i]) && !catIsWildcard(b[i]) {
			return false
		}
	}
	return true
}

// parseHeaderTemplate checks a header value template: 1-1024 bytes of printable ASCII holding
// exactly one vocabulary placeholder and no other '{' or '}'. It returns that placeholder; the
// caller decides which kinds are allowed.
func parseHeaderTemplate(t string) (placeholder, bool) {
	if len(t) == 0 || len(t) > 1024 {
		return placeholder{}, false
	}
	for i := 0; i < len(t); i++ {
		if t[i] < 0x20 || t[i] > 0x7e {
			return placeholder{}, false
		}
	}
	i := strings.Index(t, "{{")
	if i < 0 {
		return placeholder{}, false
	}
	j := strings.Index(t[i:], "}}")
	if j < 0 {
		return placeholder{}, false
	}
	ph, ok := parsePlaceholder(t[i : i+j+2])
	if !ok || strings.ContainsAny(t[:i]+t[i+j+2:], "{}") {
		return placeholder{}, false
	}
	return ph, true
}

// validCatAddress reports whether addr is a valid field address for format: a canonical form key
// (validFormKey) or a JSON Pointer (validJSONPointer).
func validCatAddress(format, addr string) bool {
	switch format {
	case "form":
		return validFormKey(addr)
	case "json":
		return validJSONPointer(addr)
	}
	return false
}

// validJSONPointer reports whether p is an RFC 6901 JSON Pointer naming a field: "/"-prefixed,
// "~" only as "~0" or "~1", valid UTF-8 at most 1 KiB, and (stricter than the RFC) not "" and with
// no empty token, control character or U+FFFD, which jsonWalk never produces for a body field.
func validJSONPointer(p string) bool {
	if !strings.HasPrefix(p, "/") || len(p) > 1024 || !utf8.ValidString(p) || strings.ContainsRune(p, utf8.RuneError) {
		return false
	}
	for _, tok := range strings.Split(p[1:], "/") {
		if tok == "" {
			return false
		}
		for i := 0; i < len(tok); i++ {
			switch {
			case tok[i] < 0x20 || tok[i] == 0x7f:
				return false
			case tok[i] == '~':
				if i+1 >= len(tok) || (tok[i+1] != '0' && tok[i+1] != '1') {
					return false
				}
				i++
			}
		}
	}
	return true
}

// catLiteral decodes one pin or forbid literal, a JSON scalar, into the fieldValue readField
// produces for that value: kind string with the decoded text, or kind number/bool/null with the raw
// JSON text. null is accepted only if allowNull (forbid lists).
// SPEC-DECISION: a string literal containing "{{" is rejected (a body field holding it would be a
// placeholder or rejected anyway), and form providers accept only string literals, since a form
// field is always a string and any other literal could never match.
func catLiteral(format string, raw json.RawMessage, allowNull bool) (fieldValue, bool) {
	nodes, err := jsonWalk(raw)
	if err != nil || len(nodes) != 1 {
		return fieldValue{}, false
	}
	n := nodes[0]
	switch n.kind {
	case "string":
		if strings.Contains(n.text, "{{") {
			return fieldValue{}, false
		}
	case "number", "bool":
		if format != "json" {
			return fieldValue{}, false
		}
	case "null":
		if format != "json" || !allowNull {
			return fieldValue{}, false
		}
	default:
		return fieldValue{}, false
	}
	return fieldValue{kind: n.kind, text: n.text}, true
}

// validCatHost reports whether h is a valid account host: catHostRe, DNS labels of 1-63 characters
// not starting or ending with '-', at most 253 characters, and a port (if any) in 1-65535.
// SPEC-DECISION: stricter than the bare pattern, so the host has one spelling for url.URL, the TLS
// ServerName and the egress firewall list.
func validCatHost(h string) bool {
	if !catHostRe.MatchString(h) {
		return false
	}
	name, port, hasPort := strings.Cut(h, ":")
	if len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	if hasPort {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return true
}

// validCatValue reports whether an account value is 1-256 bytes of printable ASCII with no "{{".
// SPEC-DECISION: values are identifiers (merchant accounts, account IDs, hash names) compared with
// body fields and fed to signers, so anything else is a catalog mistake.
func validCatValue(s string) bool {
	if len(s) < 1 || len(s) > 256 || strings.Contains(s, "{{") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// parseCatAccount validates one account against the parsed providers. Its errors name the
// account, endpoint and secret or value name, never a Secret Manager resource or a value.
func parseCatAccount(name string, ra rawAccount, providers map[string]*catProvider) (*catAccount, error) {
	if !catNameRe.MatchString(name) {
		return nil, fmt.Errorf("catalog: account %q: invalid name", name)
	}
	if ra.Env != "dev" && ra.Env != "prod" {
		return nil, fmt.Errorf("catalog: account %q: env must be dev or prod", name)
	}
	p := providers[ra.Provider]
	if p == nil {
		return nil, fmt.Errorf("catalog: account %q: unknown provider %q", name, ra.Provider)
	}
	if !validCatHost(ra.Host) {
		return nil, fmt.Errorf("catalog: account %q: invalid host", name)
	}
	if ra.BasePath != "" {
		if _, ok := parseCatPath(ra.BasePath, false); !ok {
			return nil, fmt.Errorf("catalog: account %q: invalid base_path", name)
		}
	}
	a := &catAccount{name: name, provider: ra.Provider, env: ra.Env, host: ra.Host, basePath: ra.BasePath,
		secretNames: map[string]string{}, values: map[string]string{}, secrets: map[string]string{}}
	for _, k := range slices.Sorted(maps.Keys(ra.Secrets)) {
		if !validSecretName(k) {
			return nil, fmt.Errorf("catalog: account %q: invalid secret name %q", name, k)
		}
		if !secretNameRe.MatchString(ra.Secrets[k]) {
			return nil, fmt.Errorf("catalog: account %q: secret %q: invalid Secret Manager resource name", name, k)
		}
		a.secretNames[k] = ra.Secrets[k]
	}
	for _, k := range slices.Sorted(maps.Keys(ra.Values)) {
		if !validSecretName(k) {
			return nil, fmt.Errorf("catalog: account %q: invalid value name %q", name, k)
		}
		if !validCatValue(ra.Values[k]) {
			return nil, fmt.Errorf("catalog: account %q: value %q: invalid", name, k)
		}
		a.values[k] = ra.Values[k]
	}

	// Every secret and value the provider's rules reference must exist.
	payu := false
	for _, e := range p.endpoints {
		var phs []placeholder
		for _, h := range slices.Sorted(maps.Keys(e.headers)) {
			ph, _ := parseHeaderTemplate(e.headers[h]) // validated by parseCatEndpoint
			phs = append(phs, ph)
		}
		for _, addr := range slices.Sorted(maps.Keys(e.positions)) {
			phs = append(phs, e.positions[addr])
		}
		for _, ph := range phs {
			if (ph.kind == "secret" || ph.kind == "basic") && a.secretNames[ph.arg] == "" {
				return nil, fmt.Errorf("catalog: account %q: endpoint %q: missing secret %q", name, e.id, ph.arg)
			}
		}
		for _, addr := range slices.Sorted(maps.Keys(e.pins)) {
			if v := e.pins[addr].account; v != "" && a.values[v] == "" {
				return nil, fmt.Errorf("catalog: account %q: endpoint %q: missing value %q", name, e.id, v)
			}
		}
		payu = payu || e.signer == "payu"
	}
	if h := a.values["hash"]; payu && (a.secretNames["apiKey"] == "" || a.values["merchantId"] == "" || (h != "md5" && h != "sha1" && h != "sha256")) {
		return nil, fmt.Errorf("catalog: account %q: payu needs secret apiKey, value merchantId and hash md5, sha1 or sha256", name)
	}
	return a, nil
}

// ---------------------------------------------------------------------------
// Internal API: POST /proxy and GET /healthz (SPEC §3.2, §6, §9.3, §10.1)
// ---------------------------------------------------------------------------

const (
	maxInternalBody = 64 << 10 // §6.2: 64 KiB request body limit
	maxParamValue   = 1 << 10  // §6.2: 1 KiB per param value
	maxIdempotency  = 255      // §6.2: Idempotency-Key length limit
	healthzTimeout  = 2 * time.Second
)

type proxyRequest struct {
	Provider string            `json:"provider"`
	Op       string            `json:"op"`
	Token    string            `json:"token"`
	Params   map[string]string `json:"params"`
}

// proxyFields is the exact set of keys a /proxy body may contain.
var proxyFields = map[string]bool{"provider": true, "op": true, "token": true, "params": true}

// internalHandler is the complete handler for the internal listener: /proxy (POST) and /healthz
// (GET). Checks run client certificate (401) → path (404) → method (405) → query (400).
// SPEC-DECISION: the client certificate is checked first, so a caller without one (impossible
// behind RequireAndVerifyClientCert; this is defence in depth) learns nothing about routing. A
// certificate with no usable serial (callerSerial == "") counts as no certificate.
func (v *vault) internalHandler() http.Handler {
	return v.guard("internal", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if callerSerial(r) == "" {
			writeError(w, http.StatusUnauthorized, msgUnauthorized)
			return
		}
		var method string
		var h http.HandlerFunc
		switch r.URL.Path {
		case "/proxy":
			method, h = http.MethodPost, v.handleProxy
		case "/healthz":
			method, h = http.MethodGet, v.handleHealthz
		}
		// SPEC-DECISION: as on /tokenize, a percent-encoded spelling of a route is 404.
		if h == nil || r.URL.RawPath != "" {
			writeError(w, http.StatusNotFound, msgNotFound)
			return
		}
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeError(w, http.StatusMethodNotAllowed, msgMethod)
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			writeError(w, http.StatusBadRequest, msgQuery)
			return
		}
		h(w, r)
	}))
}

// validParamValue reports whether s is at most 1 KiB of valid UTF-8 without control characters.
// SPEC-DECISION: an empty value is invalid too. No op gives "" a meaning, and rejecting it here
// (rather than in the builder, after the single-use CVV has been taken) keeps the CVV intact.
func validParamValue(s string) bool {
	if s == "" || len(s) > maxParamValue || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

// validIdempotencyKey reports whether k is 1–255 bytes of printable ASCII (0x20–0x7E).
func validIdempotencyKey(k string) bool {
	if k == "" || len(k) > maxIdempotency {
		return false
	}
	for i := 0; i < len(k); i++ {
		if k[i] < 0x20 || k[i] > 0x7e {
			return false
		}
	}
	return true
}

// handleProxy implements POST /proxy (§3.2, §6.4). Routing, method, query and client certificate
// were checked by internalHandler. The checks run in a fixed order and each failing check returns
// immediately; error bodies use only the msg* constants. Nothing from the request or the provider
// response is logged; the only log lines are the ALERTs of §10.1.
func (v *vault) handleProxy(w http.ResponseWriter, r *http.Request) {
	if !jsonContentType(r.Header) {
		writeError(w, http.StatusBadRequest, msgContentType)
		return
	}
	reqBody, err := io.ReadAll(io.LimitReader(r.Body, maxInternalBody+1))
	if len(reqBody) > maxInternalBody {
		writeError(w, http.StatusRequestEntityTooLarge, msgTooLarge)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, msgBadBody)
		return
	}

	// Strict decode: one object, no unknown/case-variant/duplicate top-level keys, no duplicate
	// params keys, params a string→string map.
	// SPEC-DECISION: as on /tokenize, encoding/json's case-insensitive key matching and
	// last-duplicate-wins are closed off, at the top level and inside params: a body that
	// different JSON parsers would read differently is never acted on.
	var req proxyRequest
	dec := json.NewDecoder(bytes.NewReader(reqBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, msgBadBody)
		return
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF || !exactKeys(reqBody, proxyFields) {
		writeError(w, http.StatusBadRequest, msgBadBody)
		return
	}
	var raw struct {
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(reqBody, &raw); err != nil ||
		(len(raw.Params) > 0 && string(raw.Params) != "null" && !exactKeys(raw.Params, nil)) {
		writeError(w, http.StatusBadRequest, msgBadBody)
		return
	}

	p, ok := v.providers[req.Provider]
	if !ok {
		writeError(w, http.StatusBadRequest, msgUnknownProvider)
		return
	}
	o, ok := p.ops[req.Op]
	if !ok {
		writeError(w, http.StatusBadRequest, msgUnknownOp)
		return
	}
	if !tokenRe.MatchString(req.Token) {
		writeError(w, http.StatusBadRequest, msgInvalidToken)
		return
	}
	for k, val := range req.Params {
		if !o.params[k] || !validParamValue(val) {
			writeError(w, http.StatusBadRequest, msgInvalidParams)
			return
		}
	}
	// SPEC-DECISION: more than one Idempotency-Key header is ambiguous and rejected; a single
	// empty one is treated as absent.
	idem := ""
	if vals := r.Header.Values("Idempotency-Key"); len(vals) > 1 {
		writeError(w, http.StatusBadRequest, msgInvalidIdempotency)
		return
	} else if len(vals) == 1 && vals[0] != "" {
		if !validIdempotencyKey(vals[0]) {
			writeError(w, http.StatusBadRequest, msgInvalidIdempotency)
			return
		}
		idem = vals[0]
	}

	// §6.4 step 3. The caller serial is passed for the database audit trail (§10.2).
	ctx := r.Context()
	ciphertext, keyVersion, err := v.getCard(ctx, req.Token, callerSerial(r))
	switch {
	case errors.Is(err, errVelocity):
		v.logf("ALERT velocity token=%s caller=%s", req.Token, callerSerial(r))
		writeError(w, http.StatusTooManyRequests, msgVelocity)
		return
	case errors.Is(err, errUnknownToken):
		writeError(w, http.StatusBadRequest, msgUnknownToken)
		return
	case err != nil:
		// Never logged or returned: it could carry driver or query detail.
		writeError(w, http.StatusInternalServerError, msgInternal)
		return
	}

	// §6.4 step 4.
	// SPEC-DECISION: authentic plaintext that is not a card record is reported as decrypt_failed
	// as well: it can only mean key or data corruption.
	var c card
	plaintext, err := unseal(v.deks[keyVersion], ciphertext) // a missing DEK (nil) fails unseal
	if err == nil {
		err = json.Unmarshal(plaintext, &c)
	}
	zero(plaintext) // best effort (§8.5)
	if err != nil {
		v.logf("ALERT decrypt_failed token=%s key_version=%d", req.Token, keyVersion)
		writeError(w, http.StatusInternalServerError, msgInternal)
		return
	}

	// §6.4 steps 5–6. Absence of a CVV is not an error; the op decides.
	cvv := v.cvv.take(req.Token)
	path, contentType, outBody, err := o.build(req.Params, c, cvv)
	defer zero(outBody) // best effort (§8.5); after the response has been read
	if err != nil {
		writeError(w, http.StatusBadRequest, msgInvalidParams)
		return
	}
	u, err := providerURL(p.base, path)
	if err != nil {
		v.logf("ALERT egress_invariant provider=%s", req.Provider)
		writeError(w, http.StatusInternalServerError, msgInternal)
		return
	}

	// §6.4 step 7. A fresh header set: no inbound header but Idempotency-Key reaches the
	// provider, and the credential comes only from the catalog (§9.3).
	// Accept-Encoding is deliberately not set: the transport then requests gzip itself and
	// decompresses transparently, so maskPAN always sees plain bytes.
	out, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(outBody))
	if err != nil {
		writeError(w, http.StatusInternalServerError, msgInternal)
		return
	}
	out.Header.Set("Content-Type", contentType)
	p.auth(out, p.secret)
	if idem != "" {
		out.Header.Set("Idempotency-Key", idem)
	}
	out.Header.Set("User-Agent", "pan-vault/1")

	// §6.4 steps 8–9. Transport errors are never logged or returned (they name hosts and causes).
	resp, err := v.client.Do(out)
	if err != nil {
		writeError(w, http.StatusBadGateway, msgProvider)
		return
	}
	defer resp.Body.Close()
	// SPEC-DECISION: a Content-Encoding still present means the transport did not decode the
	// body; maskPAN cannot see a PAN inside compressed bytes, so the response is refused (502).
	for _, ce := range resp.Header.Values("Content-Encoding") {
		if ce != "" {
			writeError(w, http.StatusBadGateway, msgProvider)
			return
		}
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderResponse+1))
	defer zero(respBody) // best effort; runs after the masked copy has been written
	if err != nil || len(respBody) > maxProviderResponse {
		// Never a truncated (and so possibly partially masked) body (globals decision 6).
		writeError(w, http.StatusBadGateway, msgProvider)
		return
	}
	masked, found := maskPAN(respBody, c.PAN)
	if found {
		v.logf("ALERT pan_echo provider=%s op=%s token=%s", req.Provider, req.Op, req.Token)
	}

	// §6.4 step 10: status, Content-Type and the scrubbed body; no other provider header.
	h := w.Header()
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		h.Set("Content-Type", ct)
	} else {
		h["Content-Type"] = nil // the provider sent none: stop net/http from sniffing one
	}
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(resp.StatusCode)
	w.Write(masked)
}

// handleHealthz implements GET /healthz (§6.5): 200 {"status":"ok"} if the database answers a
// ping within 2 seconds, else 503 {"error":"unavailable"}. The ping error is never revealed.
func (v *vault) handleHealthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), healthzTimeout)
	defer cancel()
	if err := v.ping(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, msgUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Status string `json:"status"`
	}{"ok"})
}

// ---------------------------------------------------------------------------
// Database access (SPEC §7). Go calls only the four SECURITY DEFINER functions; it never names a
// table. Every call is a single autocommit statement, so get_card's audit row commits with it.
// ---------------------------------------------------------------------------

// dbErr turns a database error into one that neither wraps nor quotes the original: a pgx error
// can carry argument values (encode errors format them; a unique-violation Detail names the
// token), and callers must never be able to reach a token or ciphertext through an error.
// Only the function name and SQLSTATE survive.
func dbErr(fn string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return errors.New(fn + ": sqlstate " + pgErr.Code)
	}
	return errors.New(fn + ": failed")
}

// dbPutCard stores an encrypted card via vault.put_card (which also writes the 'put' audit row).
func dbPutCard(ctx context.Context, db *sql.DB, token string, ciphertext []byte, last4 string, keyVersion int) error {
	if _, err := db.ExecContext(ctx, "SELECT vault.put_card($1, $2, $3, $4)", token, ciphertext, last4, keyVersion); err != nil {
		return dbErr("vault.put_card", err)
	}
	return nil
}

// dbGetCard fetches a card via vault.get_card, which enforces the velocity limits and writes the
// 'get' audit row (§6.4 step 3): SQLSTATE P0001 → errVelocity; no row → errUnknownToken.
func dbGetCard(ctx context.Context, db *sql.DB, token, caller string) ([]byte, int, error) {
	var ciphertext []byte
	var keyVersion int
	err := db.QueryRowContext(ctx, "SELECT ciphertext, key_version FROM vault.get_card($1, $2)", token, caller).
		Scan(&ciphertext, &keyVersion)
	var pgErr *pgconn.PgError
	switch {
	case err == nil:
		return ciphertext, keyVersion, nil
	case errors.Is(err, sql.ErrNoRows):
		return nil, 0, errUnknownToken
	case errors.As(err, &pgErr) && pgErr.Code == "P0001":
		return nil, 0, errVelocity
	default:
		return nil, 0, dbErr("vault.get_card", err)
	}
}

// dbListDEKs returns every wrapped DEK by version via vault.list_deks.
func dbListDEKs(ctx context.Context, db *sql.DB) (map[int][]byte, error) {
	rows, err := db.QueryContext(ctx, "SELECT version, wrapped FROM vault.list_deks()")
	if err != nil {
		return nil, dbErr("vault.list_deks", err)
	}
	defer rows.Close()
	deks := map[int][]byte{}
	for rows.Next() {
		var version int
		var wrapped []byte
		if err := rows.Scan(&version, &wrapped); err != nil {
			return nil, dbErr("vault.list_deks", err)
		}
		deks[version] = wrapped
	}
	if err := rows.Err(); err != nil {
		return nil, dbErr("vault.list_deks", err)
	}
	return deks, nil
}

// dbAddDEK stores a new KMS-wrapped DEK via vault.add_dek and returns its version.
func dbAddDEK(ctx context.Context, db *sql.DB, wrapped []byte) (int, error) {
	var version int
	if err := db.QueryRowContext(ctx, "SELECT vault.add_dek($1)", wrapped).Scan(&version); err != nil {
		return 0, dbErr("vault.add_dek", err)
	}
	return version, nil
}

// ---------------------------------------------------------------------------
// Boot: configuration, GCP REST access, DEKs, secrets, rotation, listeners, shutdown
// (SPEC §5.1, §6.1, §8.2–§8.6, §10.1, §11)
// ---------------------------------------------------------------------------

// config is the parsed environment (§11). Secret values held here (dev mode only) are never logged.
type config struct {
	env, publicAddr, internalAddr, certFile, keyFile, clientCAFile, allowOrigin, dbURL string
	kmsKey, hmacSecretName, stripeSecretName                                           string
	devDEK, devHMAC                                                                    []byte
	devStripeSecret                                                                    string
}

// devVars are the dev-mode secret variables; each is refused when VAULT_ENV=prod.
var devVars = []string{"VAULT_DEV_DEK_HEX", "VAULT_DEV_SESSION_HMAC_HEX", "VAULT_DEV_STRIPE_SECRET"}

// SPEC-DECISION: KMS key and Secret Manager names must have exactly the documented shape, with
// segments of [A-Za-z0-9_-] only. They are concatenated into request URLs, so "..", "?", "#",
// ":" or an extra "/versions/N" could otherwise redirect the call to another resource. (Domain-
// scoped project IDs like "example.com:p" are therefore not supported.)
var (
	kmsKeyRe     = regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/locations/[A-Za-z0-9_-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+$`)
	secretNameRe = regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/secrets/[A-Za-z0-9_-]+$`)
)

// loadConfig parses the environment (§11). Errors name the variable, never its value.
// rotate selects -rotate-dek mode, which needs only VAULT_ENV, VAULT_DB_URL and VAULT_KMS_KEY.
// SPEC-DECISION: an empty variable counts as unset. With VAULT_ENV=prod each VAULT_DEV_* variable
// refuses boot (main additionally refuses any other VAULT_DEV_* name, see devVarSet), in rotate
// mode too.
func loadConfig(getenv func(string) string, rotate bool) (config, error) {
	cfg := config{env: getenv("VAULT_ENV")}
	if cfg.env != "dev" && cfg.env != "prod" {
		return config{}, errors.New("VAULT_ENV must be dev or prod")
	}
	if cfg.env == "prod" {
		for _, k := range devVars {
			if getenv(k) != "" {
				return config{}, errors.New(k + " is refused when VAULT_ENV=prod")
			}
		}
	}
	if !rotate {
		for _, f := range []struct {
			name string
			dst  *string
		}{
			{"VAULT_CERT", &cfg.certFile},
			{"VAULT_KEY", &cfg.keyFile},
			{"VAULT_CLIENT_CA", &cfg.clientCAFile},
			{"VAULT_ALLOW_ORIGIN", &cfg.allowOrigin},
		} {
			if *f.dst = getenv(f.name); *f.dst == "" {
				return config{}, errors.New(f.name + " is required")
			}
		}
		if !validOrigin(cfg.allowOrigin, cfg.env == "prod") {
			return config{}, errors.New("VAULT_ALLOW_ORIGIN must be an exact origin (scheme://host[:port], https in prod)")
		}
	}
	if cfg.dbURL = getenv("VAULT_DB_URL"); cfg.dbURL == "" {
		return config{}, errors.New("VAULT_DB_URL is required")
	}
	cfg.kmsKey = getenv("VAULT_KMS_KEY")
	if cfg.kmsKey != "" && !kmsKeyRe.MatchString(cfg.kmsKey) {
		return config{}, errors.New("VAULT_KMS_KEY must be projects/P/locations/L/keyRings/R/cryptoKeys/K")
	}
	if rotate {
		if cfg.kmsKey == "" {
			return config{}, errors.New("VAULT_KMS_KEY is required for -rotate-dek")
		}
		return cfg, nil
	}

	cfg.publicAddr = getenv("VAULT_PUBLIC_ADDR")
	if cfg.publicAddr == "" {
		cfg.publicAddr = ":8443"
	}
	cfg.internalAddr = getenv("VAULT_INTERNAL_ADDR")
	if cfg.internalAddr == "" {
		cfg.internalAddr = ":9443"
	}

	cfg.hmacSecretName = getenv("VAULT_SESSION_HMAC_SECRET")
	cfg.stripeSecretName = getenv("VAULT_STRIPE_SECRET")
	for _, f := range []struct{ name, val string }{
		{"VAULT_SESSION_HMAC_SECRET", cfg.hmacSecretName},
		{"VAULT_STRIPE_SECRET", cfg.stripeSecretName},
	} {
		if f.val != "" && !secretNameRe.MatchString(f.val) {
			return config{}, errors.New(f.name + " must be projects/P/secrets/S")
		}
	}

	// In prod every secret comes from KMS / Secret Manager (dev vars were refused above); in dev
	// each comes from its VAULT_DEV_* variable when set, otherwise from KMS / Secret Manager.
	if s := getenv("VAULT_DEV_DEK_HEX"); s != "" {
		b, ok := decodeKey64(s)
		if !ok {
			return config{}, errors.New("VAULT_DEV_DEK_HEX must be exactly 64 hex chars")
		}
		cfg.devDEK = b
	} else if cfg.kmsKey == "" {
		return config{}, errors.New("VAULT_KMS_KEY is required (or VAULT_DEV_DEK_HEX in dev)")
	}
	if s := getenv("VAULT_DEV_SESSION_HMAC_HEX"); s != "" {
		b, ok := decodeKey64(s)
		if !ok {
			return config{}, errors.New("VAULT_DEV_SESSION_HMAC_HEX must be exactly 64 hex chars")
		}
		cfg.devHMAC = b
	} else if cfg.hmacSecretName == "" {
		return config{}, errors.New("VAULT_SESSION_HMAC_SECRET is required (or VAULT_DEV_SESSION_HMAC_HEX in dev)")
	}
	if cfg.devStripeSecret = getenv("VAULT_DEV_STRIPE_SECRET"); cfg.devStripeSecret == "" && cfg.stripeSecretName == "" {
		return config{}, errors.New("VAULT_STRIPE_SECRET is required (or VAULT_DEV_STRIPE_SECRET in dev)")
	}
	return cfg, nil
}

// devVarSet returns the name of the first VAULT_DEV_* variable present in environ (os.Environ
// form), even if empty. main refuses prod boot if there is one, whatever its name.
func devVarSet(environ []string) (string, bool) {
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "VAULT_DEV_") {
			return name, true
		}
	}
	return "", false
}

// decodeKey64 decodes exactly 64 hex chars into 32 bytes.
func decodeKey64(s string) ([]byte, bool) {
	if len(s) != 64 {
		return nil, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

// validOrigin reports whether s is exactly a serialized origin: scheme://host[:port] with no
// userinfo, path, query or fragment, in canonical form (lowercase scheme and host).
// SPEC-DECISION: the browser's Origin header is compared byte-for-byte (§5.3), so a value that
// could never match one (trailing slash, uppercase host, "*") refuses boot; prod requires https.
// The same goes for a port a browser never serializes: the scheme's default (https :443, http
// :80, which browsers omit), an empty port ("host:"), a leading zero, or one outside 1–65535.
func validOrigin(s string, requireHTTPS bool) bool {
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || u.Host != strings.ToLower(u.Host) || u.String() != s {
		return false
	}
	if strings.HasSuffix(u.Host, ":") {
		return false
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || p[0] == '0' || n < 1 || n > 65535 ||
			(u.Scheme == "https" && n == 443) || (u.Scheme == "http" && n == 80) {
			return false
		}
	}
	return u.Scheme == "https" || (!requireHTTPS && u.Scheme == "http")
}

// Google endpoints (§8.3, §8.6). Variables only so tests can point them at fakes.
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
	defer zero(body) // may hold secret material; best effort (§8.5)
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

// tokenSource fetches the service account's access token from the metadata server (§8.3 step 1)
// and caches it until 60s before it expires.
type tokenSource struct {
	client *http.Client
	mu     sync.Mutex
	tok    string
	exp    time.Time
}

// token returns a cached or freshly fetched access token.
// SPEC-DECISION: the token must be 1–4096 printable non-space ASCII chars (it goes into an
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

// kmsPost calls POST {kmsBaseURL}{key}:{verb} with {field: base64(data)} (§8.3 step 2).
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
	// marshalled body is zeroed best effort (§8.5).
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

// accessSecret reads the latest version of a Secret Manager secret (§8.6):
// GET {secretManagerBaseURL}{name}/versions/latest:access → payload.data (base64).
// SPEC-DECISION: when the response carries payload.dataCrc32c it must match the data.
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

// openDB opens the pool (it connects lazily). dev uses VAULT_DB_URL as is; prod authenticates
// with Cloud SQL IAM: before every new connection the password is set to a fresh metadata
// access token (globals decision 8). The pool is capped at 16 open connections in both modes
// (user decision 2026-10-30, §7 notes). Errors never contain the URL (it can hold credentials).
// SPEC-DECISION: in prod every connection path must use TLS with server certificate
// verification (sslmode=verify-ca or verify-full, or require with sslrootcert): the password is
// an OAuth token that also authorizes KMS decrypt, so it must not be sent in clear text or to an
// unverified server. sslmode=prefer/allow/require-without-root-cert/disable refuse boot.
//
// SPEC-DECISION: §14 forbids configuration from files, and pgx reads pg_service.conf when the
// URL sets service/servicefile and a password file when it sets passfile, during ParseConfig.
// Those keys (any letter case, percent-encoded or not) refuse boot before pgx sees the URL. To
// make that check complete, VAULT_DB_URL must be the URL form (§11 "Postgres URL"): the
// keyword/value form ("host=… dbname=…") is refused, as is a query string that does not parse
// strictly (pgx would silently drop such pairs). Accepted residue: pgx's PG* environment
// fallbacks (PGHOST, PGSERVICE, …; the deployment sets none), and its default ~/.pgpass lookup
// when the URL has no password, which in the scratch image resolves to /.pgpass (HOME=/ from
// /etc/passwd), a file that does not exist.
func openDB(cfg config, ts *tokenSource) (*sql.DB, error) {
	if !strings.HasPrefix(cfg.dbURL, "postgres://") && !strings.HasPrefix(cfg.dbURL, "postgresql://") {
		return nil, errors.New("VAULT_DB_URL must be a postgres:// or postgresql:// URL")
	}
	u, err := url.Parse(cfg.dbURL)
	if err != nil {
		return nil, errors.New("VAULT_DB_URL cannot be parsed")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("VAULT_DB_URL cannot be parsed")
	}
	for k := range query {
		if strings.EqualFold(k, "service") || strings.EqualFold(k, "servicefile") || strings.EqualFold(k, "passfile") {
			return nil, errors.New("VAULT_DB_URL must not set service, servicefile or passfile")
		}
	}
	pc, err := pgx.ParseConfig(cfg.dbURL)
	if err != nil {
		return nil, errors.New("VAULT_DB_URL cannot be parsed")
	}
	var db *sql.DB
	switch cfg.env {
	case "dev":
		db = stdlib.OpenDB(*pc)
	case "prod":
		if ts == nil {
			return nil, errors.New("prod database access needs a token source")
		}
		verified := func(tc *tls.Config) bool {
			return tc != nil && (!tc.InsecureSkipVerify || tc.VerifyPeerCertificate != nil)
		}
		ok := verified(pc.TLSConfig)
		for _, fb := range pc.Fallbacks {
			ok = ok && verified(fb.TLSConfig)
		}
		if !ok {
			return nil, errors.New("VAULT_DB_URL must use sslmode=verify-ca or verify-full in prod")
		}
		db = stdlib.OpenDB(*pc, stdlib.OptionBeforeConnect(func(ctx context.Context, cc *pgx.ConnConfig) error {
			tok, err := ts.token(ctx)
			if err != nil {
				return err
			}
			cc.Password = tok
			return nil
		}))
	default:
		return nil, errors.New("VAULT_ENV must be dev or prod")
	}
	db.SetMaxOpenConns(16)
	return db, nil
}

// errNoDEKs is the §8.3 step 4 boot failure.
var errNoDEKs = errors.New("no DEKs found; run vault -rotate-dek first")

// loadDEKs returns every DEK by version and the current (highest) version (§8.3). In dev with
// VAULT_DEV_DEK_HEX the dev DEK is version 1 and neither the database nor KMS is used.
// Otherwise every vault.list_deks() row is unwrapped via KMS; any failure fails the whole load.
func loadDEKs(ctx context.Context, cfg config, db *sql.DB, c *http.Client, ts *tokenSource) (map[int][]byte, int, error) {
	if cfg.devDEK != nil {
		if cfg.env != "dev" {
			return nil, 0, errors.New("a dev DEK is refused when VAULT_ENV=prod")
		}
		if len(cfg.devDEK) != dekSize {
			return nil, 0, errors.New("VAULT_DEV_DEK_HEX must decode to 32 bytes")
		}
		return map[int][]byte{1: bytes.Clone(cfg.devDEK)}, 1, nil
	}
	if cfg.kmsKey == "" {
		return nil, 0, errors.New("VAULT_KMS_KEY is required")
	}
	wrapped, err := dbListDEKs(ctx, db)
	if err != nil {
		return nil, 0, err
	}
	if len(wrapped) == 0 {
		return nil, 0, errNoDEKs
	}
	deks := make(map[int][]byte, len(wrapped))
	current := 0
	for version, w := range wrapped {
		dek, err := kmsDecrypt(ctx, c, ts, cfg.kmsKey, w)
		if err != nil {
			for _, d := range deks {
				zero(d)
			}
			return nil, 0, fmt.Errorf("DEK version %d: %s", version, err.Error())
		}
		deks[version] = dek
		current = max(current, version)
	}
	return deks, current, nil
}

// dekVersions lists the map's versions in ascending order, comma-separated, for the boot log.
func dekVersions(deks map[int][]byte) string {
	vs := make([]int, 0, len(deks))
	for v := range deks {
		vs = append(vs, v)
	}
	slices.Sort(vs)
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ",")
}

// validSecretValue reports whether s is a non-empty run of printable, non-space ASCII.
// SPEC-DECISION: stricter than "no whitespace or control chars": provider keys are ASCII and go
// into an HTTP header, so any non-ASCII byte refuses boot too.
func validSecretValue(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// loadSecrets returns the session HMAC key (32 bytes) and the Stripe secret (§8.6): from the
// VAULT_DEV_* values in dev when set, otherwise from Secret Manager. The HMAC payload must be
// exactly 64 hex chars. Errors name the variable, never the value.
func loadSecrets(ctx context.Context, cfg config, c *http.Client, ts *tokenSource) (hmacKey []byte, stripeSecret string, err error) {
	if cfg.env != "dev" && (cfg.devHMAC != nil || cfg.devStripeSecret != "") {
		return nil, "", errors.New("dev secrets are refused when VAULT_ENV=prod")
	}
	if cfg.devHMAC != nil {
		hmacKey = bytes.Clone(cfg.devHMAC)
	} else {
		raw, err := accessSecret(ctx, c, ts, cfg.hmacSecretName)
		if err != nil {
			return nil, "", errors.New("VAULT_SESSION_HMAC_SECRET: " + err.Error())
		}
		var ok bool
		hmacKey, ok = decodeKey64(string(raw))
		zero(raw)
		if !ok {
			return nil, "", errors.New("VAULT_SESSION_HMAC_SECRET: payload must be exactly 64 hex chars")
		}
	}
	if len(hmacKey) != 32 {
		zero(hmacKey)
		return nil, "", errors.New("session HMAC key must be 32 bytes")
	}

	name := "VAULT_DEV_STRIPE_SECRET"
	stripeSecret = cfg.devStripeSecret
	if stripeSecret == "" {
		name = "VAULT_STRIPE_SECRET"
		raw, err := accessSecret(ctx, c, ts, cfg.stripeSecretName)
		if err != nil {
			zero(hmacKey)
			return nil, "", errors.New(name + ": " + err.Error())
		}
		stripeSecret = string(raw)
		zero(raw)
	}
	if !validSecretValue(stripeSecret) {
		zero(hmacKey)
		return nil, "", errors.New(name + ": secret must be non-empty printable ASCII without whitespace")
	}
	return hmacKey, stripeSecret, nil
}

// rotateDEK generates a 32-byte DEK, wraps it via KMS encrypt, checks that KMS decrypt returns it,
// stores it via vault.add_dek and returns the new version (§8.4).
// SPEC-DECISION: the unwrap check runs before anything is stored, so a wrapped value that boot
// could not unwrap (which would make every later boot fail) never reaches the database.
func rotateDEK(ctx context.Context, cfg config, db *sql.DB, c *http.Client, ts *tokenSource) (int, error) {
	if cfg.kmsKey == "" {
		return 0, errors.New("VAULT_KMS_KEY is required")
	}
	dek := make([]byte, dekSize)
	defer zero(dek)
	rand.Read(dek) // never fails; see newToken
	wrapped, err := kmsEncrypt(ctx, c, ts, cfg.kmsKey, dek)
	if err != nil {
		return 0, err
	}
	back, err := kmsDecrypt(ctx, c, ts, cfg.kmsKey, wrapped)
	if err != nil {
		return 0, err
	}
	same := hmac.Equal(back, dek)
	zero(back)
	if !same {
		return 0, errors.New("kms: wrapped DEK does not unwrap to the generated DEK")
	}
	return dbAddDEK(ctx, db, wrapped)
}

// loadClientCA reads the mTLS client CA (§6.1): the file must contain exactly one PEM block, of
// type CERTIFICATE, holding a CA certificate.
// SPEC-DECISION: any second PEM block (another certificate, a private key) refuses boot, as does
// a certificate without basicConstraints CA:TRUE.
func loadClientCA(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("client CA: cannot read file")
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return nil, errors.New("client CA: first PEM block is not a CERTIFICATE")
	}
	if extra, _ := pem.Decode(rest); extra != nil {
		return nil, errors.New("client CA: file must contain exactly one PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("client CA: certificate does not parse")
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, errors.New("client CA: certificate is not a CA")
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
}

// dbCallTimeout bounds each request's database call (waiting for a pool slot included), so a
// saturated pool (16 connections, get_card serialized by its advisory lock) or a stalled server
// fails the request with 500 instead of holding it until the listener's WriteTimeout.
const dbCallTimeout = 5 * time.Second

// newVault wires the vault to the database and the loaded key material. Each putCard/getCard
// call runs under dbCallTimeout, derived from the request context (an earlier request deadline
// or a client disconnect still wins).
func newVault(cfg config, db *sql.DB, deks map[int][]byte, current int, hmacKey []byte, stripeSecret string, client *http.Client, logger *log.Logger) *vault {
	return &vault{
		putCard: func(ctx context.Context, token string, ciphertext []byte, last4 string, keyVersion int) error {
			ctx, cancel := context.WithTimeout(ctx, dbCallTimeout)
			defer cancel()
			return dbPutCard(ctx, db, token, ciphertext, last4, keyVersion)
		},
		getCard: func(ctx context.Context, token, caller string) ([]byte, int, error) {
			ctx, cancel := context.WithTimeout(ctx, dbCallTimeout)
			defer cancel()
			return dbGetCard(ctx, db, token, caller)
		},
		ping:        db.PingContext,
		deks:        deks,
		currentDEK:  current,
		hmacKey:     hmacKey,
		allowOrigin: cfg.allowOrigin,
		cvv:         newCVVCache(15*time.Minute, time.Now),
		now:         time.Now,
		log:         logger,
		providers:   newProviders(stripeSecret),
		client:      client,
	}
}

// newServers builds both listeners (§5.1, §6.1). net/http's own error lines are discarded
// (globals decision 5): they are neither boot nor ALERT lines and can quote client input.
func newServers(v *vault, cfg config, cert tls.Certificate, clientCAs *x509.CertPool) (public, internal *http.Server) {
	public = &http.Server{
		Addr:              cfg.publicAddr,
		Handler:           v.publicHandler(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	internal = &http.Server{
		Addr:    cfg.internalAddr,
		Handler: v.internalHandler(),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCAs,
		},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	return public, internal
}

const (
	bootDBTimeout   = 5 * time.Second
	bootGCPTimeout  = 60 * time.Second
	shutdownTimeout = 20 * time.Second
)

// main runs the boot sequence of §11, or -rotate-dek (§8.4). Every log line goes through logf;
// failures log "boot failed: <reason>" with reasons built only from variable names, fixed
// phrases, status codes and SQLSTATEs, and exit 1.
func main() {
	rotate := flag.Bool("rotate-dek", false, "generate, wrap and store a new DEK, print its version, and exit")
	flag.Parse()
	logger := log.New(os.Stderr, "", 0)
	boot := &vault{log: logger, now: time.Now} // logging only, until the real vault exists
	fail := func(reason string) {
		boot.logf("boot failed: %s", reason)
		os.Exit(1)
	}

	// 1. Parse env and fail fast.
	cfg, err := loadConfig(os.Getenv, *rotate)
	if err != nil {
		fail(err.Error())
	}
	if name, ok := devVarSet(os.Environ()); ok && cfg.env == "prod" {
		fail(name + " is refused when VAULT_ENV=prod")
	}
	boot.logf("config loaded env=%s", cfg.env)

	// 1b. Serve mode: load the certificate, key and client CA now, before the database, KMS or
	// Secret Manager is touched (§11 "fail fast"), so a bad file costs no network round trip and
	// never boots half way. -rotate-dek has no listeners and never reads them.
	var cert tls.Certificate
	var clientCAs *x509.CertPool
	if !*rotate {
		cert, err = tls.LoadX509KeyPair(cfg.certFile, cfg.keyFile)
		if err != nil {
			fail("VAULT_CERT/VAULT_KEY: cannot load key pair")
		}
		clientCAs, err = loadClientCA(cfg.clientCAFile)
		if err != nil {
			fail("VAULT_CLIENT_CA: " + err.Error())
		}
	}

	client := newOutboundClient(nil) // the single shared client: metadata, KMS, SM, providers
	ts := &tokenSource{client: client}

	// 2. Open the DB (the error never contains the URL).
	db, err := openDB(cfg, ts)
	if err != nil {
		fail(err.Error())
	}

	if *rotate {
		ctx, cancel := context.WithTimeout(context.Background(), bootGCPTimeout)
		version, err := rotateDEK(ctx, cfg, db, client, ts)
		cancel()
		if err != nil {
			fail("rotate: " + err.Error())
		}
		db.Close()
		fmt.Println(version)
		os.Exit(0)
	}

	// SPEC-DECISION: the ping error is not logged: pgx connect errors name the host, user and
	// database from VAULT_DB_URL.
	ctx, cancel := context.WithTimeout(context.Background(), bootDBTimeout)
	err = db.PingContext(ctx)
	cancel()
	if err != nil {
		fail("database ping failed")
	}

	// 3. Load DEKs.
	ctx, cancel = context.WithTimeout(context.Background(), bootGCPTimeout)
	deks, current, err := loadDEKs(ctx, cfg, db, client, ts)
	cancel()
	if errors.Is(err, errNoDEKs) {
		boot.logf("%s", errNoDEKs.Error())
		os.Exit(1)
	}
	if err != nil {
		fail(err.Error())
	}
	boot.logf("deks loaded versions=%s current=%d", dekVersions(deks), current)

	// 4. Load secrets.
	ctx, cancel = context.WithTimeout(context.Background(), bootGCPTimeout)
	hmacKey, stripeSecret, err := loadSecrets(ctx, cfg, client, ts)
	cancel()
	if err != nil {
		fail(err.Error())
	}

	// 5. Build the vault (and with it the provider catalog).
	v := newVault(cfg, db, deks, current, hmacKey, stripeSecret, client, logger)

	// 6. Start both listeners (certificate and client CA were loaded in step 1b).
	// SPEC-DECISION: each socket is bound with net.Listen before serving (ServeTLS("", "") is what
	// ListenAndServeTLS("", "") does after binding), so a bind failure exits 1 before "ready".
	public, internal := newServers(v, cfg, cert, clientCAs)
	pubLn, err := net.Listen("tcp", cfg.publicAddr)
	if err != nil {
		fail("VAULT_PUBLIC_ADDR: cannot listen")
	}
	intLn, err := net.Listen("tcp", cfg.internalAddr)
	if err != nil {
		fail("VAULT_INTERNAL_ADDR: cannot listen")
	}
	serveErr := make(chan string, 2)
	go func() {
		if err := public.ServeTLS(pubLn, "", ""); !errors.Is(err, http.ErrServerClosed) {
			serveErr <- "public"
		}
	}()
	go func() {
		if err := internal.ServeTLS(intLn, "", ""); !errors.Is(err, http.ErrServerClosed) {
			serveErr <- "internal"
		}
	}()
	v.logf("listening public=%s internal=%s", cfg.publicAddr, cfg.internalAddr)

	// 7. Ready.
	v.logf("ready")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-sig:
		// Stop accepting and drain both listeners concurrently within one 20s budget (§11).
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		var wg sync.WaitGroup
		for _, srv := range []*http.Server{public, internal} {
			wg.Go(func() { srv.Shutdown(ctx) })
		}
		wg.Wait()
		cancel()
		db.Close()
		os.Exit(0)
	case name := <-serveErr:
		v.logf("listener failed listener=%s", name)
		os.Exit(1)
	}
}
