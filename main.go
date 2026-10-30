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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
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
	// SPEC-DECISION: nil means absent; JSON null also decodes to nil and is treated as absent
	// (the plan's *string + "validate if non-nil"). "" is present and fails validation.
	CVV *string `json:"cvv"`
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

// tokenizeFields is the exact set of keys a /tokenize body may contain.
var tokenizeFields = map[string]bool{"pan": true, "exp_month": true, "exp_year": true, "cvv": true}

// exactKeys reports whether body is a JSON object whose keys are all in tokenizeFields, spelled
// exactly, each at most once.
// SPEC-DECISION: encoding/json matches keys case-insensitively and keeps the last of duplicate
// keys, so DisallowUnknownFields alone accepts {"PAN":…} and {"pan":A,"pan":B}. Both are
// rejected as unknown fields: a body that different JSON parsers would read differently is
// never tokenized.
func exactKeys(body []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool, len(tokenizeFields))
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return false
		}
		k, ok := t.(string)
		if !ok || !tokenizeFields[k] || seen[k] {
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

	// SPEC-DECISION: the media type must be application/json (case-insensitive, per RFC 9110);
	// the only parameter allowed is charset=utf-8, since JSON is UTF-8 (RFC 8259).
	ct, ok := singleHeader(r.Header, "Content-Type")
	if !ok {
		writeError(w, http.StatusBadRequest, msgContentType)
		return
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil || mt != "application/json" || len(params) > 1 ||
		(len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8")) {
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
	if err := dec.Decode(&extra); err != io.EOF || !exactKeys(body) {
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
	if req.CVV != nil && !validCVV(*req.CVV) {
		writeError(w, http.StatusBadRequest, msgInvalidCVV)
		return
	}

	dek, ok := v.deks[v.currentDEK]
	if !ok {
		writeError(w, http.StatusInternalServerError, msgInternal)
		return
	}
	plaintext, err := json.Marshal(card{PAN: pan, ExpMonth: req.ExpMonth, ExpYear: req.ExpYear})
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

// newProviders returns the provider catalog (§6.3 v1). Adding a provider or op is a PR that also
// updates egress-hosts.txt and the egress firewall rule (§9.1, §12.4); TestCatalogMatchesEgressHosts
// keeps the catalog and egress-hosts.txt in step.
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
// spaces ("4242 4242 4242 4242", "3782 8224 6310 005"), with "****"+last4 (§6.4 step 9). found
// reports whether anything was replaced; if not, body is returned unchanged.
func maskPAN(body []byte, pan string) ([]byte, bool) {
	if len(pan) < 4 { // never a real PAN; also keeps an empty needle out of bytes.ReplaceAll
		return body, false
	}
	var spaced strings.Builder
	for i := 0; i < len(pan); i++ {
		if i > 0 && i%4 == 0 {
			spaced.WriteByte(' ')
		}
		spaced.WriteByte(pan[i])
	}
	mask := []byte("****" + pan[len(pan)-4:])
	found := false
	for _, form := range []string{pan, spaced.String()} {
		if bytes.Contains(body, []byte(form)) {
			body = bytes.ReplaceAll(body, []byte(form), mask)
			found = true
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
