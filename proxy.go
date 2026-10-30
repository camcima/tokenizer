package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

// ---------------------------------------------------------------------------
// Internal API: POST /proxy and GET /healthz
// ---------------------------------------------------------------------------

const (
	maxInternalBody = 64 << 10 // 64 KiB request body limit
	healthzTimeout  = 2 * time.Second
)

// envelopeFields and envelopeRequestFields are the exact keys of a /proxy envelope and of its
// "request" object (proxyEnvelope).
var (
	envelopeFields        = map[string]bool{"account": true, "token": true, "request": true}
	envelopeRequestFields = map[string]bool{"method": true, "path": true, "headers": true, "body": true}
)

// internalHandler is the complete handler for the internal listener: /proxy (POST) and /healthz
// (GET). Checks run client certificate (401) → path (404) → method (405) → query (400).
// The client certificate is checked first, so a caller without one (impossible
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
		// As on /tokenize, a percent-encoded spelling of a route is 404.
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

// handleProxy implements POST /proxy. Routing, method, query and client
// certificate were checked by internalHandler. The steps run in a fixed order and each failing step
// returns immediately; error bodies use only the msg* constants:
//
//  1. Content-Type application/json, body at most 64 KiB.
//  2. Strict decode into proxyEnvelope: jsonStrict, one object, no unknown, case-variant or duplicate
//     keys at the top level or in "request".
//  3. checkProxy (no network, no database). A policy rejection raises ALERT proxy_policy.
//  4. get_card (velocity and audit).
//  5. Decrypt.
//  6. {{name}} with a card stored without a name: 409.
//  7. {{cvv}}: the CVV is taken here, after every other check, and none cached is 409.
//  8. renderRequest (account URL with the egress invariant, substitutions, headers).
//  9. Send; read at most 4 MiB; refuse a Content-Encoding; mask the PAN.
//  10. Respond with the provider's status, Content-Type and masked body.
//
// Nothing from the request or the provider response is logged; the only log lines are ALERTs with
// fixed reasons, tokens, serials and catalog names.
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

	// Strict decode.
	// As on /tokenize, encoding/json's case-insensitive key matching is closed off:
	// the top-level keys and the keys of "request" must be spelled exactly ({"Account":…} and
	// {"Method":…} are unknown fields), and "request" must be an object. jsonStrict already refuses
	// duplicate keys at any depth (so a repeated header name), invalid UTF-8 and trailing data.
	if jsonStrict(reqBody) != nil || !exactKeys(reqBody, envelopeFields) {
		writeError(w, http.StatusBadRequest, msgBadBody)
		return
	}
	var env proxyEnvelope
	dec := json.NewDecoder(bytes.NewReader(reqBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		writeError(w, http.StatusBadRequest, msgBadBody)
		return
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		writeError(w, http.StatusBadRequest, msgBadBody)
		return
	}
	var rawReq struct {
		Request json.RawMessage `json:"request"`
	}
	if err := json.Unmarshal(reqBody, &rawReq); err != nil || !exactKeys(rawReq.Request, envelopeRequestFields) {
		writeError(w, http.StatusBadRequest, msgBadBody)
		return
	}

	// The alert names the account as the catalog spells it, never as the request
	// does. checkProxy only sets a reason once the account is known, so the "-" fallback is defence
	// in depth.
	plan, perr := v.catalog.checkProxy(&env)
	if perr != nil {
		writeError(w, perr.status, perr.msg)
		if perr.reason != "" {
			account := "-"
			if a := v.catalog.accounts[env.Account]; a != nil {
				account = a.name
			}
			v.alertPolicy(account, perr.endpoint, perr.reason)
		}
		return
	}
	account, endpoint := plan.acct.name, plan.ep.id

	// 4. get_card. The caller serial is passed for the database audit trail.
	ctx := r.Context()
	ciphertext, keyVersion, err := v.getCard(ctx, env.Token, callerSerial(r))
	switch {
	case errors.Is(err, errVelocity):
		v.logf("ALERT velocity token=%s caller=%s account=%s", env.Token, callerSerial(r), account)
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

	// 5. Decrypt.
	// Authentic plaintext that is not a card record is reported as decrypt_failed
	// as well: it can only mean key or data corruption.
	var c card
	plaintext, err := unseal(v.deks[keyVersion], ciphertext) // a missing DEK (nil) fails unseal
	if err == nil {
		err = json.Unmarshal(plaintext, &c)
	}
	zero(plaintext) // best effort
	if err != nil {
		v.logf("ALERT decrypt_failed token=%s key_version=%d account=%s", env.Token, keyVersion, account)
		writeError(w, http.StatusInternalServerError, msgInternal)
		return
	}

	// 6–7. The name is checked first so that a name-unavailable request leaves the
	// single-use CVV cached; the CVV is taken last, once nothing but rendering and sending is left.
	// The vault never edits the body to drop a field: the platform resends without it.
	if plan.usesName && c.Name == "" {
		writeError(w, http.StatusConflict, msgNameUnavailable)
		return
	}
	cvv := ""
	if plan.usesCVV {
		if cvv = v.cvv.take(env.Token); cvv == "" {
			writeError(w, http.StatusConflict, msgCVVUnavailable)
			return
		}
	}

	// 8. renderRequest builds the whole outgoing request: account URL (egress
	// invariant), substituted body, the endpoint's credential headers, the allowlisted platform
	// headers, Content-Type and User-Agent. No inbound HTTP header of this request is used.
	// A render failure after the CVV was taken loses the CVV (single use, never put
	// back); it can only follow a catalog or boot defect, never platform input.
	out, err := renderRequest(ctx, plan, c, cvv)
	if err != nil {
		if errors.Is(err, errEgress) {
			v.logf("ALERT egress_invariant account=%s", account)
		}
		writeError(w, http.StatusInternalServerError, msgInternal)
		return
	}
	defer zero(plan.sent) // best effort; after the response has been read

	// 9. Send and read. Transport errors are never logged or returned (they name hosts and causes).
	resp, err := v.client.Do(out)
	if err != nil {
		writeError(w, http.StatusBadGateway, msgProvider)
		return
	}
	defer resp.Body.Close()
	// A Content-Encoding still present means the transport did not decode the
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
		// Never a truncated (and so possibly partially masked) body.
		writeError(w, http.StatusBadGateway, msgProvider)
		return
	}
	masked, found := maskPAN(respBody, c.PAN)
	if found {
		v.logf("ALERT pan_echo account=%s endpoint=%s token=%s", account, endpoint, env.Token)
	}

	// 10. Status, Content-Type and the scrubbed body; no other provider header.
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

// handleHealthz implements GET /healthz: 200 {"status":"ok"} if the database answers a
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
