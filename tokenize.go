package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Session tokens
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
// The scheme prefix is exactly "Bearer " (case-sensitive, one space), the MAC is
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

// alertSession logs "ALERT session_token_invalid reason=<reason>" at most once per second.
// reason is checkSession's result.
func (v *vault) alertSession(reason string) {
	sec := v.now().Unix()
	old := v.lastSessionAlert.Load()
	if old == sec || !v.lastSessionAlert.CompareAndSwap(old, sec) {
		return
	}
	v.logf("ALERT session_token_invalid reason=%s", reason)
}

// alertPolicy logs "ALERT proxy_policy account=<a> endpoint=<id|-> reason=<r>" at most once per
// second, on its own limiter so that a flood of policy violations cannot hide a session
// alert or the other way round. account and endpoint are catalog names ("" endpoint → "-") and
// reason a fixed checkProxy reason; the offending request value is never logged.
func (v *vault) alertPolicy(account, endpoint, reason string) {
	sec := v.now().Unix()
	old := v.lastPolicyAlert.Load()
	if old == sec || !v.lastPolicyAlert.CompareAndSwap(old, sec) {
		return
	}
	if endpoint == "" {
		endpoint = "-"
	}
	v.logf("ALERT proxy_policy account=%s endpoint=%s reason=%s", account, endpoint, reason)
}

// ---------------------------------------------------------------------------
// Public API: POST /tokenize and CORS
// ---------------------------------------------------------------------------

const maxPublicBody = 4 << 10 // 4 KiB request body limit

type tokenizeRequest struct {
	PAN      string `json:"pan"`
	ExpMonth string `json:"exp_month"`
	ExpYear  string `json:"exp_year"`
	// nil means the key is absent (no CVV). encoding/json also decodes JSON null
	// to nil, so handleTokenize detects "cvv": null separately and rejects it with
	// msgInvalidCVV, like "": an explicit null is not treated as absent.
	CVV *string `json:"cvv"`
	// Name follows CVV exactly: nil means absent, and "name": null is detected separately and
	// rejected with msgInvalidName, just like "cvv": null.
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
// A repeated Origin, Authorization or Content-Type header is ambiguous (proxies
// and Go's Header.Get may disagree on which one counts) and is treated as invalid.
func singleHeader(h http.Header, name string) (string, bool) {
	vals := h.Values(name)
	if len(vals) != 1 {
		return "", false
	}
	return vals[0], true
}

// jsonContentType reports whether h carries exactly one Content-Type and it is application/json.
// The media type must be application/json (case-insensitive, per RFC 9110);
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
// encoding/json matches keys case-insensitively and keeps the last of duplicate
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

// handleTokenize implements POST /tokenize. The checks run in a fixed order and each
// failing check returns immediately; error bodies use only the msg* constants. Nothing from the
// request is logged.
func (v *vault) handleTokenize(w http.ResponseWriter, r *http.Request) {
	// A percent-encoded spelling of the path (e.g. /%74okenize) decodes to
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
	// A bare trailing "?" (empty but present query) is rejected like any query.
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeError(w, http.StatusBadRequest, msgQuery)
		return
	}
	// The Origin must match exactly on POST as well as on the preflight. An
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
	defer zero(body) // best effort
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
	zero(plaintext) // best effort

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
