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

	deks        map[int][]byte // key version → 32-byte DEK
	currentDEK  int
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
