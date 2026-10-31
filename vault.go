package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Vault core: state, logging, guard, errors
// ---------------------------------------------------------------------------

// Errors returned by vault.getCard. Any other error is an internal failure.
var (
	errVelocity     = errors.New("velocity")
	errUnknownToken = errors.New("unknown token")
)

// Error response strings: the complete fixed set. Error bodies use only these; they never
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
	msgInvalidToken       = "invalid token"
	msgUnknownToken       = "unknown token"
	msgVelocity           = "rate limit exceeded"
	msgInternal           = "internal error"
	msgProvider           = "provider unreachable"
	msgUnavailable        = "unavailable"
	msgUnknownAccount     = "unknown account"
	msgEndpointNotAllowed = "endpoint not allowed"
	msgHeaderNotAllowed   = "header not allowed"
	msgPlaceholder        = "invalid placeholder use"
	msgPinMismatch        = "pinned field mismatch"
	msgForbiddenField     = "forbidden field"
	msgCVVUnavailable     = "cvv unavailable"
	msgNameUnavailable    = "name unavailable"
)

// vault holds all process state. The function fields are the only seam: production wires them
// to the database, tests to an in-memory fake.
type vault struct {
	putCard func(ctx context.Context, token string, ciphertext []byte, last4 string, keyVersion int) error
	// getCard returns errVelocity or errUnknownToken for those conditions; any other error is internal.
	getCard func(ctx context.Context, token, caller string) (ciphertext []byte, keyVersion int, err error)
	ping    func(ctx context.Context) error

	hmacKey     []byte
	allowOrigin string
	cvv         *cvvCache
	now         func() time.Time
	log         *log.Logger
	catalog     *catalog     // the compiled-in catalog.json, this environment's accounts
	client      *http.Client // the single shared outbound client

	lastSessionAlert atomic.Int64 // unix second of last session_token_invalid alert
	lastPolicyAlert  atomic.Int64 // unix second of last proxy_policy alert
	lastCVVAlert     atomic.Int64 // unix second of last cvv_cache_full alert

	// keys is the current DEK snapshot; readers load it without locking. refreshDEKs (wired by
	// main, nil = nothing to refresh) publishes a new one; refresh serializes and rate-limits it.
	keys        atomic.Pointer[dekSet]
	refreshDEKs func(ctx context.Context) error
	refreshMu   sync.Mutex
	lastRefresh atomic.Int64 // unix nanos at which the last refresh attempt completed
}

// dekSet is one snapshot of the key material: every DEK by version and the version new cards are
// sealed under. A published set is never modified; a refresh publishes a new one, which shares
// the DEK slices it already held.
type dekSet struct {
	deks    map[int][]byte // key version → 32-byte DEK
	current int
}

const (
	// dekRefreshEvery is the period of the background refresh, so that an instance usually
	// learns a newly rotated key before any request needs it.
	dekRefreshEvery = 5 * time.Minute
	// dekRefreshMinGap bounds refreshes to one per window, however many requests carry an
	// unknown (possibly forged) key version: each costs a list_deks call and possibly KMS calls.
	dekRefreshMinGap = 10 * time.Second
	// dekRefreshTimeout bounds one refresh: the list_deks call plus the KMS unwrap of every new
	// version, and so how long calls queued behind it wait.
	dekRefreshTimeout = 30 * time.Second
)

// dek returns the DEK for version from the current snapshot.
func (v *vault) dek(version int) ([]byte, bool) {
	ks := v.keys.Load()
	if ks == nil {
		return nil, false
	}
	d, ok := ks.deks[version]
	return d, ok
}

// currentDEK returns the version new cards are sealed under and its DEK (nil if missing).
func (v *vault) currentDEK() (version int, dek []byte) {
	ks := v.keys.Load()
	if ks == nil {
		return 0, nil
	}
	return ks.current, ks.deks[ks.current]
}

// refresh runs refreshDEKs at most once at a time and at most once per dekRefreshMinGap,
// counted from the end of the previous attempt, successful or not. Calls that queue on refreshMu
// behind a refresh in flight reach the rate-limit check after it completes and return nil without
// running again; the snapshot it published is already in place. A failed refresh keeps the
// current snapshot.
//
// refreshDEKs runs detached from ctx's cancellation, so a caller that disconnects does not fail
// the attempt (which would suppress refreshes for every request for the rest of the window), and
// under dekRefreshTimeout, which bounds how long queued calls can be held.
func (v *vault) refresh(ctx context.Context) error {
	if v.refreshDEKs == nil {
		return nil
	}
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()
	// A negative gap means the wall clock stepped back; it does not suppress the refresh.
	if gap := time.Now().UnixNano() - v.lastRefresh.Load(); gap >= 0 && gap < int64(dekRefreshMinGap) {
		return nil
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dekRefreshTimeout)
	err := v.refreshDEKs(rctx)
	cancel()
	v.lastRefresh.Store(time.Now().UnixNano())
	return err
}

// refreshLoop refreshes the DEK snapshot every period until ctx is cancelled. Errors are not
// logged (they could carry KMS or database detail); the snapshot simply stays as it was. A
// refresh in flight at cancellation finishes first (refresh detaches it from ctx and bounds it by
// dekRefreshTimeout); main does not wait for this loop, so it never delays shutdown.
func (v *vault) refreshLoop(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = v.refresh(ctx)
		}
	}
}

// logf writes one line: "<RFC3339 UTC timestamp> " + message. Callers pass only fixed format
// strings and non-sensitive values (tokens, serials, catalog account and endpoint names, statuses).
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
// Only known routes are logged literally, everything else as path=other, so a
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

// guard wraps every handler on both listeners: exactly one access-log line per request
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
// if there is none.
// A negative serial (invalid per RFC 5280; its magnitude would collide with a
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
