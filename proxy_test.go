package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// POST /proxy and GET /healthz
// ---------------------------------------------------------------------------

// proxyVault returns a test vault whose stripe_t account is the fake provider.
func proxyVault(t *testing.T, fp *fakeProvider) (*vault, *fakeStore) {
	t.Helper()
	v, s := newTestVault(t)
	pointAccount(t, v, "stripe_t", fp.ts)
	return v, s
}

// tokensRequest returns POST /proxy asking for stripe_t POST /v1/tokens with body on tok.
func tokensRequest(tok, body string) *http.Request {
	e := newEnvelope("stripe_t", "POST", "/v1/tokens", nil, body)
	e.Token = tok
	return newProxyRequest(envelopeJSON(e))
}

func TestProxyValidation(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := proxyVault(t, fp)
	tok := seedCard(t, v, s, testCVV)
	unseeded := "tok_" + strings.Repeat("ab", 16)
	env := func(mut func(e *proxyEnvelope)) string {
		e := newEnvelope("stripe_t", "POST", "/v1/tokens", nil, stripeTokensBody)
		e.Token = tok
		if mut != nil {
			mut(e)
		}
		return envelopeJSON(e)
	}
	raw := func(s string) string { return strings.ReplaceAll(s, "TOK", tok) }
	good := env(nil)
	big := padBody(good, maxInternalBody+1)
	hdr := func(k, val string) func(e *proxyEnvelope) {
		return func(e *proxyEnvelope) { e.Request.Headers = map[string]string{k: val} }
	}

	cases := []struct {
		name       string
		method     string // default POST
		target     string // default /proxy
		ctype      string // default application/json; omit = absent
		body       string
		noCert     bool
		wantStatus int
		wantError  string
	}{
		// Envelope shape: strict JSON, exact keys, single value.
		{name: "unknown field", body: raw(`{"account":"stripe_t","token":"TOK","request":{"method":"POST","path":"/v1/tokens"},"x":1}`), wantStatus: 400, wantError: msgBadBody},
		{name: "unknown request field", body: raw(`{"account":"stripe_t","token":"TOK","request":{"method":"POST","path":"/v1/tokens","query":"a"}}`), wantStatus: 400, wantError: msgBadBody},
		{name: "case-variant field", body: raw(`{"Account":"stripe_t","token":"TOK","request":{"method":"POST","path":"/v1/tokens"}}`), wantStatus: 400, wantError: msgBadBody},
		{name: "case-variant request field", body: raw(`{"account":"stripe_t","token":"TOK","request":{"Method":"POST","path":"/v1/tokens"}}`), wantStatus: 400, wantError: msgBadBody},
		{name: "duplicate field", body: raw(`{"account":"adyen_br","account":"stripe_t","token":"TOK","request":{"method":"POST","path":"/v1/tokens"}}`), wantStatus: 400, wantError: msgBadBody},
		{name: "duplicate header key", body: raw(`{"account":"stripe_t","token":"TOK","request":{"method":"POST","path":"/v1/tokens","headers":{"Accept":"a","Accept":"b"}}}`), wantStatus: 400, wantError: msgBadBody},
		{name: "missing request", body: raw(`{"account":"stripe_t","token":"TOK"}`), wantStatus: 400, wantError: msgBadBody},
		{name: "null request", body: raw(`{"account":"stripe_t","token":"TOK","request":null}`), wantStatus: 400, wantError: msgBadBody},
		{name: "request string", body: raw(`{"account":"stripe_t","token":"TOK","request":"x"}`), wantStatus: 400, wantError: msgBadBody},
		{name: "body number", body: raw(`{"account":"stripe_t","token":"TOK","request":{"method":"POST","path":"/v1/tokens","body":1}}`), wantStatus: 400, wantError: msgBadBody},
		{name: "headers array", body: raw(`{"account":"stripe_t","token":"TOK","request":{"method":"POST","path":"/v1/tokens","headers":[]}}`), wantStatus: 400, wantError: msgBadBody},
		{name: "header number", body: raw(`{"account":"stripe_t","token":"TOK","request":{"method":"POST","path":"/v1/tokens","headers":{"Accept":1}}}`), wantStatus: 400, wantError: msgBadBody},
		{name: "lone surrogate", body: raw(`{"account":"stripe_t","token":"TOK","request":{"method":"POST","path":"/v1/tokens","body":"a=\ud800"}}`), wantStatus: 400, wantError: msgBadBody},
		{name: "invalid UTF-8", body: raw(`{"account":"stripe_t","token":"TOK","request":{"method":"POST","path":"/v1/tokens","body":"a=` + "\xff" + `"}}`), wantStatus: 400, wantError: msgBadBody},
		{name: "trailing object", body: good + `{}`, wantStatus: 400, wantError: msgBadBody},
		{name: "not json", body: "account=stripe_t", wantStatus: 400, wantError: msgBadBody},
		{name: "array body", body: `[]`, wantStatus: 400, wantError: msgBadBody},
		{name: "null body", body: `null`, wantStatus: 400, wantError: msgBadBody},
		{name: "empty body", body: "", wantStatus: 400, wantError: msgBadBody},

		// checkProxy rejections.
		{name: "bad token", body: env(func(e *proxyEnvelope) { e.Token = "tok_XYZ" }), wantStatus: 400, wantError: msgInvalidToken},
		{name: "uppercase token", body: env(func(e *proxyEnvelope) { e.Token = strings.ToUpper(tok) }), wantStatus: 400, wantError: msgInvalidToken},
		{name: "missing token", body: `{"account":"stripe_t","request":{"method":"POST","path":"/v1/tokens"}}`, wantStatus: 400, wantError: msgInvalidToken},
		{name: "unknown account", body: env(func(e *proxyEnvelope) { e.Account = "stripe_x" }), wantStatus: 400, wantError: msgUnknownAccount},
		{name: "account case", body: env(func(e *proxyEnvelope) { e.Account = "Stripe_t" }), wantStatus: 400, wantError: msgUnknownAccount},
		{name: "prod account in dev", body: env(func(e *proxyEnvelope) { e.Account = "adyen_br_live" }), wantStatus: 400, wantError: msgUnknownAccount},
		{name: "missing account", body: raw(`{"token":"TOK","request":{"method":"POST","path":"/v1/tokens"}}`), wantStatus: 400, wantError: msgUnknownAccount},
		{name: "unknown endpoint", body: env(func(e *proxyEnvelope) { e.Request.Path = "/v1/payment_methods" }), wantStatus: 400, wantError: msgEndpointNotAllowed},
		{name: "wrong method", body: env(func(e *proxyEnvelope) { e.Request.Method = "PUT" }), wantStatus: 400, wantError: msgEndpointNotAllowed},
		{name: "query not allowed", body: env(func(e *proxyEnvelope) { e.Request.Path = "/v1/tokens?x=1" }), wantStatus: 400, wantError: msgEndpointNotAllowed},
		{name: "forged Authorization", body: env(hdr("Authorization", "Bearer sk_test_attacker")), wantStatus: 400, wantError: msgHeaderNotAllowed},
		{name: "forged authorization lowercase", body: env(hdr("authorization", "Bearer sk_test_attacker")), wantStatus: 400, wantError: msgHeaderNotAllowed},
		{name: "Cookie header", body: env(hdr("Cookie", "a=b")), wantStatus: 400, wantError: msgHeaderNotAllowed},
		{name: "Host header", body: env(hdr("Host", "evil.example")), wantStatus: 400, wantError: msgHeaderNotAllowed},
		{name: "idempotency 1025", body: env(hdr("Idempotency-Key", strings.Repeat("k", 1025))), wantStatus: 400, wantError: msgHeaderNotAllowed},
		{name: "idempotency empty", body: env(hdr("Idempotency-Key", "")), wantStatus: 400, wantError: msgHeaderNotAllowed},
		{name: "idempotency DEL", body: env(hdr("Idempotency-Key", "a\x7fb")), wantStatus: 400, wantError: msgHeaderNotAllowed},
		{name: "idempotency tab", body: env(hdr("Idempotency-Key", "a\tb")), wantStatus: 400, wantError: msgHeaderNotAllowed},
		{name: "idempotency CRLF", body: env(hdr("Idempotency-Key", "a\r\nX-Evil: 1")), wantStatus: 400, wantError: msgHeaderNotAllowed},
		{name: "idempotency non-ASCII", body: env(hdr("Idempotency-Key", "clé")), wantStatus: 400, wantError: msgHeaderNotAllowed},
		{name: "idempotency placeholder", body: env(hdr("Idempotency-Key", "{{pan}}")), wantStatus: 400, wantError: msgHeaderNotAllowed},
		{name: "idempotency twice", body: env(func(e *proxyEnvelope) {
			e.Request.Headers = map[string]string{"Idempotency-Key": "a", "idempotency-key": "b"}
		}), wantStatus: 400, wantError: msgHeaderNotAllowed},
		{name: "pan off position", body: env(func(e *proxyEnvelope) {
			e.Request.Body = strings.Replace(stripeTokensBody, "card[number]", "description", 1)
		}), wantStatus: 400, wantError: msgPlaceholder},
		{name: "literal at position", body: env(func(e *proxyEnvelope) {
			e.Request.Body = strings.Replace(stripeTokensBody, "{{pan}}", "4000056655665556", 1)
		}), wantStatus: 400, wantError: msgPlaceholder},
		{name: "forbidden field", body: env(func(e *proxyEnvelope) {
			e.Request.Path, e.Request.Body = "/v1/payment_intents", stripePIBody+"&customer=cus_1"
		}), wantStatus: 400, wantError: msgForbiddenField},
		{name: "pin mismatch", body: env(func(e *proxyEnvelope) {
			e.Account, e.Request.Path = "adyen_br", "/v72/payments"
			e.Request.Body = strings.Replace(adyenBody, "AcmeBR_ECOM", "Other_ECOM", 1)
		}), wantStatus: 400, wantError: msgPinMismatch},
		{name: "malformed form body", body: env(func(e *proxyEnvelope) { e.Request.Body = "a=%zz" }), wantStatus: 400, wantError: msgBadBody},
		{name: "unseeded token", body: env(func(e *proxyEnvelope) { e.Token = unseeded }), wantStatus: 400, wantError: msgUnknownToken},

		// The vault's own HTTP surface.
		{name: "body 65537", body: big, wantStatus: 413, wantError: msgTooLarge},
		{name: "text/plain", ctype: "text/plain", body: good, wantStatus: 400, wantError: msgContentType},
		{name: "missing ctype", ctype: omit, body: good, wantStatus: 400, wantError: msgContentType},
		{name: "query", target: "/proxy?x=1", body: good, wantStatus: 400, wantError: msgQuery},
		{name: "bare question mark", target: "/proxy?", body: good, wantStatus: 400, wantError: msgQuery},
		{name: "healthz query", method: "GET", target: "/healthz?x=1", wantStatus: 400, wantError: msgQuery},
		{name: "GET /proxy", method: "GET", body: good, wantStatus: 405, wantError: msgMethod},
		{name: "PUT /proxy", method: "PUT", body: good, wantStatus: 405, wantError: msgMethod},
		{name: "POST /other", target: "/other", body: good, wantStatus: 404, wantError: msgNotFound},
		{name: "POST /tokenize", target: "/tokenize", body: good, wantStatus: 404, wantError: msgNotFound},
		{name: "POST /proxy/", target: "/proxy/", body: good, wantStatus: 404, wantError: msgNotFound},
		{name: "encoded path", target: "/%70roxy", body: good, wantStatus: 404, wantError: msgNotFound},
		{name: "POST /healthz", target: "/healthz", body: good, wantStatus: 405, wantError: msgMethod},
		{name: "no client cert", body: good, noCert: true, wantStatus: 401, wantError: msgUnauthorized},
		{name: "no client cert healthz", method: "GET", target: "/healthz", noCert: true, wantStatus: 401, wantError: msgUnauthorized},

		// Check order: each case fails two checks; the earlier one wins.
		{name: "order cert>404", target: "/other", noCert: true, wantStatus: 401, wantError: msgUnauthorized},
		{name: "order 404>405", method: "PUT", target: "/x", wantStatus: 404, wantError: msgNotFound},
		{name: "order 405>query", method: "GET", target: "/proxy?x=1", wantStatus: 405, wantError: msgMethod},
		{name: "order query>ctype", target: "/proxy?x=1", ctype: "text/plain", body: good, wantStatus: 400, wantError: msgQuery},
		{name: "order ctype>size", ctype: "text/plain", body: big, wantStatus: 400, wantError: msgContentType},
		{name: "order size>shape", body: big + "x", wantStatus: 413, wantError: msgTooLarge},
		{name: "order shape>policy", body: `{"account":"x","token":"x","extra":1}`, wantStatus: 400, wantError: msgBadBody},
		{name: "order token>account", body: env(func(e *proxyEnvelope) { e.Token, e.Account = "x", "x" }), wantStatus: 400, wantError: msgInvalidToken},
		{name: "order account>endpoint", body: env(func(e *proxyEnvelope) { e.Account, e.Request.Path = "x", "/x" }), wantStatus: 400, wantError: msgUnknownAccount},
		{name: "order endpoint>header", body: env(func(e *proxyEnvelope) {
			e.Request.Path, e.Request.Headers = "/x", map[string]string{"Cookie": "a"}
		}), wantStatus: 400, wantError: msgEndpointNotAllowed},
		{name: "order header>body", body: env(func(e *proxyEnvelope) {
			e.Request.Headers, e.Request.Body = map[string]string{"Cookie": "a"}, "a=%zz"
		}), wantStatus: 400, wantError: msgHeaderNotAllowed},
		{name: "order policy>store", body: env(func(e *proxyEnvelope) {
			e.Token, e.Request.Headers = unseeded, map[string]string{"Cookie": "a"}
		}), wantStatus: 400, wantError: msgHeaderNotAllowed},
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
	if strings.Contains(testLog.String(), "sk_test_attacker") {
		t.Fatal("a forged header value was logged")
	}

	// 405 names the allowed method.
	if rec := serveInternal(v, withClientCert(httptest.NewRequest("GET", "/proxy", nil))); rec.Header().Get("Allow") != "POST" {
		t.Errorf("GET /proxy Allow %q", rec.Header().Get("Allow"))
	}
	if rec := serveInternal(v, withClientCert(httptest.NewRequest("POST", "/healthz", nil))); rec.Header().Get("Allow") != "GET" {
		t.Errorf("POST /healthz Allow %q", rec.Header().Get("Allow"))
	}

	// Boundaries that pass validation and reach the provider with the platform header unchanged: a
	// 1024-byte key of every printable byte, a lowercase allowlisted name, the other allowlisted
	// headers, an envelope of exactly 64 KiB, headers null.
	printable := make([]byte, 0, 95)
	for b := byte(0x20); b <= 0x7e; b++ {
		printable = append(printable, b)
	}
	// HTTP trims leading/trailing spaces from header values, so the run sits inside the key.
	key := "k" + string(printable) + strings.Repeat("k", 1023-len(printable))
	noCVV := func(h map[string]string) string {
		return env(func(e *proxyEnvelope) { e.Request.Headers, e.Request.Body = h, stripeTokensNoCVV })
	}
	for i, c := range []struct {
		body       string
		name, want string
	}{
		{noCVV(map[string]string{"Idempotency-Key": key}), "Idempotency-Key", key},
		{noCVV(map[string]string{"idempotency-key": "k-1"}), "Idempotency-Key", "k-1"},
		{noCVV(map[string]string{"X-Idempotency-Key": "x-1"}), "X-Idempotency-Key", "x-1"},
		{noCVV(map[string]string{"Accept": "application/json"}), "Accept", "application/json"},
		{noCVV(map[string]string{"Authorization": "Bearer {{secret:secretKey}}"}), "Authorization", "Bearer " + testSecret},
		{padBody(noCVV(nil), maxInternalBody), "", ""},
		{raw(`{"account":"stripe_t","token":"TOK","request":{"method":"POST","path":"/v1/tokens","headers":null,"body":"card[number]={{pan}}"}}`), "", ""},
	} {
		before, _, _, _, _ := fp.last()
		rec := serveInternal(v, newProxyRequest(c.body))
		after, _, _, h, _ := fp.last()
		if rec.Code != http.StatusOK || after != before+1 {
			t.Errorf("boundary case %d: status %d, provider hits +%d", i, rec.Code, after-before)
			continue
		}
		if c.name != "" && (len(h.Values(c.name)) != 1 || h.Get(c.name) != c.want) {
			t.Errorf("boundary case %d: %s not sent exactly once and unchanged", i, c.name)
		}
	}

	// Two Content-Type headers are ambiguous and rejected.
	r := newProxyRequest(good)
	r.Header.Add("Content-Type", "application/json")
	if rec := serveInternal(v, r); rec.Code != http.StatusBadRequest || rec.Body.String() != wantErrBody(msgContentType) {
		t.Errorf("two Content-Type headers: status %d", rec.Code)
	}
}

// The success path: the provider receives exactly the platform's body with the card values
// substituted, the vault's own credential and the allowlisted platform headers, and nothing else of
// the inbound request; the platform gets the status, Content-Type and body back.
func TestProxySuccess(t *testing.T) {
	fp := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Provider-Header", "x")
		w.Header().Set("Set-Cookie", "provider=1")
		w.Write([]byte(`{"id":"pi_123"}`))
	})
	v, s := proxyVault(t, fp)
	tok := seedCardNamed(t, v, s, testCVV, testName)
	body := stripePIBody + "&payment_method_data[billing_details][name]={{name}}&description=order+1%2F2&metadata[k]=a%26b"
	e := newEnvelope("stripe_t", "POST", "/v1/payment_intents",
		map[string]string{"Idempotency-Key": "idem-1", "Accept": "application/json"}, body)
	e.Token = tok
	r := newProxyRequest(envelopeJSON(e))
	r.Header.Set("Authorization", "Bearer sk_test_attacker")
	r.Header.Set("Idempotency-Key", "http-idem")
	r.Header.Set("Cookie", "a=b")
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("User-Agent", "platform/9")

	start := testLog.Len()
	rec := serveInternal(v, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (body len %d)", rec.Code, rec.Body.Len())
	}
	hits, method, path, hdr, sent := fp.last()
	if hits != 1 || method != "POST" || path != "/v1/payment_intents" {
		t.Fatalf("outbound: hits %d, %s %s", hits, method, path)
	}
	if want := seededValues("form", body); string(sent) != want {
		t.Errorf("outbound body is not the platform body plus substitutions (len %d, want %d)", len(sent), len(want))
	}
	if got := hdr.Values("Authorization"); len(got) != 1 || got[0] != "Bearer "+testSecret {
		t.Errorf("outbound Authorization is not exactly the vault credential (%d values)", len(got)) // never print it
	}
	if hdr.Get("Idempotency-Key") != "idem-1" || hdr.Get("Accept") != "application/json" || hdr.Get("User-Agent") != "pan-vault/1" ||
		hdr.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Error("outbound Idempotency-Key, Accept, User-Agent or Content-Type wrong")
	}
	allowed := map[string]bool{"Authorization": true, "Content-Type": true, "Idempotency-Key": true, "Accept": true,
		"User-Agent": true, "Content-Length": true, "Accept-Encoding": true}
	for k := range hdr {
		if !allowed[k] {
			t.Errorf("unexpected outbound header %q", k) // name only, never the value
		}
	}
	if s.lastCaller != "0A1B2C" {
		t.Errorf("getCard caller %q, want 0A1B2C", s.lastCaller)
	}
	if rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("Cache-Control") != "no-store" ||
		rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("response Content-Type, Cache-Control or X-Content-Type-Options wrong")
	}
	if rec.Header().Get("X-Provider-Header") != "" || rec.Header().Get("Set-Cookie") != "" {
		t.Error("provider response headers forwarded")
	}
	if rec.Body.String() != `{"id":"pi_123"}` {
		t.Errorf("response body len %d is not the provider body", rec.Body.Len())
	}
	out := testLog.since(start)
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, " path=/proxy status=200 ") || !strings.HasSuffix(out, " caller=0A1B2C\n") {
		t.Errorf("success log unexpected (len %d, %d lines)", len(out), strings.Count(out, "\n"))
	}

	// A json provider, through the account's base path, with a header-template credential.
	pointAccount(t, v, "adyen_br", fp.ts)
	tok2 := seedCardNamed(t, v, s, testCVV, testName)
	e = validEnvelope("adyen")
	e.Token = tok2
	if rec := serveInternal(v, newProxyRequest(envelopeJSON(e))); rec.Code != http.StatusOK {
		t.Fatalf("adyen: status %d", rec.Code)
	}
	_, method, path, hdr, sent = fp.last()
	if method != "POST" || path != "/checkout/v72/payments" {
		t.Fatalf("adyen outbound %s %s", method, path)
	}
	if want := seededValues("json", adyenBody); string(sent) != want {
		t.Errorf("adyen: outbound body is not the platform body plus substitutions (len %d, want %d)", len(sent), len(want))
	}
	if got := hdr.Values("X-Api-Key"); len(got) != 1 || got[0] != testSecret || hdr.Get("Authorization") != "" ||
		hdr.Get("Idempotency-Key") != "ord-1" || hdr.Get("Content-Type") != "application/json" {
		t.Error("adyen: outbound credential, Idempotency-Key or Content-Type wrong")
	}

	// A wildcard path with an allowed query and no {{cvv}}; the CVV is not sent.
	tok3 := seedCard(t, v, s, testCVV)
	e = validEnvelope("stripe_confirm")
	e.Token = tok3
	if rec := serveInternal(v, newProxyRequest(envelopeJSON(e))); rec.Code != http.StatusOK {
		t.Fatalf("confirm: status %d", rec.Code)
	}
	_, method, path, hdr, sent = fp.last()
	if method != "POST" || path != "/v1/payment_intents/pi_123/confirm" || fp.lastQuery() != "expand[]=latest_charge&expand%5B%5D=customer" {
		t.Errorf("confirm outbound %s %s", method, path)
	}
	if want := seededValues("form", stripeConfirmBody); string(sent) != want {
		t.Errorf("confirm: outbound body is not the platform body plus substitutions (len %d, want %d)", len(sent), len(want))
	}
	// The platform supplied no idempotency header, so none is sent.
	if _, ok := hdr["Idempotency-Key"]; ok || hdr.Get("X-Idempotency-Key") != "" {
		t.Error("confirm: an idempotency header was sent although the platform supplied none")
	}
	// The provider answered 2xx, so the CVV the request did not use is dropped on hand-off.
	// TestProxyDropsCVVOnHandoff shows a request without {{cvv}} leaves it cached on any other status.
	if v.cvv.take(tok3) != "" {
		t.Error("CVV still cached after a 2xx hand-off")
	}
}

// The outbound credential is only ever the vault's: a credential header from the platform is
// rejected unless it is exactly the unrendered template, and the provider is never hit.
func TestProxyForgedAuthorization(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := proxyVault(t, fp)
	pointAccount(t, v, "adyen_br", fp.ts)
	clk := &fakeClock{t: testNow}
	v.now = clk.now
	tok := seedCard(t, v, s, testCVV)
	for i, c := range []struct {
		account, path, body, endpoint string
		headers                       map[string]string
	}{
		{"stripe_t", "/v1/tokens", stripeTokensBody, "tokens", map[string]string{"Authorization": "Bearer sk_test_attacker"}},
		{"stripe_t", "/v1/tokens", stripeTokensBody, "tokens", map[string]string{"authorization": "Bearer sk_test_attacker"}},
		{"stripe_t", "/v1/tokens", stripeTokensBody, "tokens", map[string]string{"AUTHORIZATION": "Bearer {{secret:secretKey}} sk_test_attacker"}},
		{"stripe_t", "/v1/tokens", stripeTokensBody, "tokens", map[string]string{"Authorization": "Bearer {{secret:secretKey}}", "authorization": "Bearer sk_test_attacker"}},
		{"adyen_br", "/v72/payments", adyenBody, "payments", map[string]string{"x-api-key": "sk_test_attacker"}},
		{"adyen_br", "/v72/payments", adyenBody, "payments", map[string]string{"Authorization": "Bearer sk_test_attacker"}},
	} {
		clk.advance(time.Second)
		e := newEnvelope(c.account, "POST", c.path, c.headers, c.body)
		e.Token = tok
		start := testLog.Len()
		rec := serveInternal(v, newProxyRequest(envelopeJSON(e)))
		if rec.Code != http.StatusBadRequest || rec.Body.String() != wantErrBody(msgHeaderNotAllowed) {
			t.Errorf("case %d: status %d, body len %d, want 400 header not allowed", i, rec.Code, rec.Body.Len())
		}
		out := testLog.since(start)
		if !strings.Contains(out, " ALERT proxy_policy account="+c.account+" endpoint="+c.endpoint+" reason=header\n") ||
			strings.Contains(out, "sk_test_attacker") {
			t.Errorf("case %d: no proxy_policy header alert, or the forged value was logged", i)
		}
	}
	if hits, _, _, _, _ := fp.last(); hits != 0 {
		t.Fatalf("a forged credential reached the provider %d times", hits)
	}
	if v.cvv.take(tok) != testCVV {
		t.Fatal("a rejected request consumed the CVV")
	}
}

func TestProxyCVVSingleUse(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := proxyVault(t, fp)
	tok := seedCard(t, v, s, testCVV)

	if rec := serveInternal(v, tokensRequest(tok, stripeTokensBody)); rec.Code != http.StatusOK {
		t.Fatalf("first call: status %d", rec.Code)
	}
	_, _, path, _, sent := fp.last()
	if want := seededValues("form", stripeTokensBody); path != "/v1/tokens" || string(sent) != want {
		t.Fatalf("first call: outbound body is not the platform body plus substitutions (len %d, want %d)", len(sent), len(want))
	}

	// The CVV was single use: asking for it again is 409 and the provider is not called.
	rec := serveInternal(v, tokensRequest(tok, stripeTokensBody))
	if rec.Code != http.StatusConflict || rec.Body.String() != wantErrBody(msgCVVUnavailable) {
		t.Fatalf("second call: status %d, body len %d, want 409 cvv unavailable", rec.Code, rec.Body.Len())
	}
	if hits, _, _, _, _ := fp.last(); hits != 1 {
		t.Fatalf("provider hits %d, want 1", hits)
	}

	// The platform resends without the CVV field.
	if rec := serveInternal(v, tokensRequest(tok, stripeTokensNoCVV)); rec.Code != http.StatusOK {
		t.Fatalf("resend without cvv: status %d", rec.Code)
	}
	hits, _, _, _, sent := fp.last()
	if want := seededValues("form", stripeTokensNoCVV); hits != 2 || string(sent) != want || bytes.Contains(sent, []byte(testCVV)) {
		t.Fatalf("resend: hits %d, body len %d, want %d without a CVV", hits, len(sent), len(want))
	}
}

// {{cvv}} with no cached CVV is 409. get_card has already run (its audit and velocity row is
// written), the provider is not called, and no other cached CVV is touched.
func TestProxyCVVUnavailable(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := proxyVault(t, fp)
	clk := &fakeClock{t: testNow}
	v.now = clk.now
	tok := seedCard(t, v, s, "")
	other := seedCard(t, v, s, testCVV)

	start := testLog.Len()
	rec := serveInternal(v, tokensRequest(tok, stripeTokensBody))
	if rec.Code != http.StatusConflict || rec.Body.String() != wantErrBody(msgCVVUnavailable) {
		t.Fatalf("status %d, body len %d, want 409 cvv unavailable", rec.Code, rec.Body.Len())
	}
	if s.gets != 1 || s.lastCaller != "0A1B2C" {
		t.Fatalf("get_card calls %d (caller %q), want 1: the lookup is audited and counted", s.gets, s.lastCaller)
	}
	if hits, _, _, _, _ := fp.last(); hits != 0 {
		t.Fatal("cvv unavailable reached the provider")
	}
	if out := testLog.since(start); strings.Contains(out, "ALERT") || !strings.Contains(out, " status=409 ") {
		t.Fatalf("cvv unavailable log unexpected (len %d)", len(out))
	}

	if v.cvv.take(other) != testCVV {
		t.Fatal("a 409 touched another token's CVV")
	}

	// An expired CVV is unavailable too.
	expired := seedCard(t, v, s, testCVV)
	clk.advance(16 * time.Minute)
	if rec := serveInternal(v, tokensRequest(expired, stripeTokensBody)); rec.Code != http.StatusConflict {
		t.Fatalf("expired cvv: status %d, want 409", rec.Code)
	}
	if hits, _, _, _, _ := fp.last(); hits != 0 {
		t.Fatal("cvv unavailable reached the provider")
	}
}

// {{name}} with a card stored without a name is 409; the name is checked before the CVV is taken.
func TestProxyNameUnavailable(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := proxyVault(t, fp)
	tok := seedCard(t, v, s, testCVV) // stored without a name
	body := stripeTokensBody + "&card[name]={{name}}"

	rec := serveInternal(v, tokensRequest(tok, body))
	if rec.Code != http.StatusConflict || rec.Body.String() != wantErrBody(msgNameUnavailable) {
		t.Fatalf("status %d, body len %d, want 409 name unavailable", rec.Code, rec.Body.Len())
	}
	if hits, _, _, _, _ := fp.last(); hits != 0 || s.gets != 1 {
		t.Fatalf("hits %d, get_card calls %d", hits, s.gets)
	}
	if v.cvv.take(tok) != testCVV {
		t.Fatal("a name-unavailable request consumed the CVV")
	}

	// The same body with a named card goes through, the name encoded for the format.
	tok2 := seedCardNamed(t, v, s, testCVV, testName)
	if rec := serveInternal(v, tokensRequest(tok2, body)); rec.Code != http.StatusOK {
		t.Fatalf("named card: status %d", rec.Code)
	}
	if _, _, _, _, sent := fp.last(); string(sent) != seededValues("form", body) {
		t.Fatalf("named card: outbound body is not the platform body plus substitutions (len %d)", len(sent))
	}
}

// A policy violation raises ALERT proxy_policy with the account, endpoint and fixed reason, at most
// once per second on its own limiter, and never logs the offending value. Envelope errors (bad
// token, unknown account, bad JSON) raise none.
func TestProxyPolicyAlert(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := proxyVault(t, fp)
	clk := &fakeClock{t: testNow}
	v.now = clk.now
	tok := seedCard(t, v, s, testCVV)
	const marker = "offending-value-5e1f"
	violation := tokensRequest(tok, strings.Replace(stripeTokensBody, "{{pan}}", marker, 1))
	const line = " ALERT proxy_policy account=stripe_t endpoint=tokens reason=placeholder\n"

	start := testLog.Len()
	for i := 0; i < 3; i++ {
		r := tokensRequest(tok, strings.Replace(stripeTokensBody, "{{pan}}", marker, 1))
		if rec := serveInternal(v, r); rec.Code != http.StatusBadRequest || rec.Body.String() != wantErrBody(msgPlaceholder) {
			t.Fatalf("call %d: status %d, want 400 invalid placeholder use", i, rec.Code)
		}
	}
	out := testLog.since(start)
	if strings.Count(out, "ALERT") != 1 || !strings.Contains(out, line) {
		t.Fatalf("%d ALERT lines in one second, want exactly one proxy_policy placeholder line", strings.Count(out, "ALERT"))
	}
	if strings.Contains(testLog.String(), marker) {
		t.Fatal("the offending value was logged")
	}

	// The session alert has its own limiter: it still fires in the same second.
	start = testLog.Len()
	v.alertSession("bad_mac")
	if !strings.Contains(testLog.since(start), "ALERT session_token_invalid reason=bad_mac") {
		t.Fatal("a proxy_policy alert suppressed a session alert in the same second")
	}

	// The next second alerts again.
	clk.advance(time.Second)
	start = testLog.Len()
	serveInternal(v, violation)
	if !strings.Contains(testLog.since(start), line) {
		t.Fatal("no alert in the next second")
	}

	// An endpoint outside the catalog: endpoint=-.
	clk.advance(time.Second)
	e := newEnvelope("stripe_t", "POST", "/v1/charges", nil, stripeTokensBody)
	e.Token = tok
	start = testLog.Len()
	serveInternal(v, newProxyRequest(envelopeJSON(e)))
	if !strings.Contains(testLog.since(start), " ALERT proxy_policy account=stripe_t endpoint=- reason=endpoint\n") {
		t.Fatal("no endpoint alert with endpoint=-")
	}

	// Each fixed reason.
	for _, c := range []struct {
		e    *proxyEnvelope
		line string
	}{
		{newEnvelope("adyen_br", "POST", "/v72/payments", nil, strings.Replace(adyenBody, "AcmeBR_ECOM", "Other", 1)),
			"account=adyen_br endpoint=payments reason=pin"},
		{newEnvelope("stripe_t", "POST", "/v1/payment_intents", nil, stripePIBody+"&customer=cus_1"),
			"account=stripe_t endpoint=payment_intents reason=forbidden_field"},
		{newEnvelope("stripe_t", "POST", "/v1/tokens", nil, "a=%zz"), "account=stripe_t endpoint=tokens reason=body"},
		{newEnvelope("stripe_t", "POST", "/v1/tokens", map[string]string{"Cookie": "a"}, stripeTokensBody),
			"account=stripe_t endpoint=tokens reason=header"},
	} {
		clk.advance(time.Second)
		c.e.Token = tok
		start = testLog.Len()
		serveInternal(v, newProxyRequest(envelopeJSON(c.e)))
		if !strings.Contains(testLog.since(start), " ALERT proxy_policy "+c.line+"\n") {
			t.Errorf("no proxy_policy alert %q", c.line)
		}
	}

	// Envelope errors raise no alert.
	for i, body := range []string{
		envelopeJSON(newEnvelope("stripe_t", "POST", "/v1/tokens", nil, stripeTokensBody)), // checkToken is not seeded but valid
		func() string {
			e := newEnvelope("stripe_t", "POST", "/v1/tokens", nil, stripeTokensBody)
			e.Token = "tok_bad"
			return envelopeJSON(e)
		}(),
		func() string {
			e := newEnvelope("nope", "POST", "/v1/tokens", nil, stripeTokensBody)
			e.Token = tok
			return envelopeJSON(e)
		}(),
		`{"account":"stripe_t"`,
	} {
		clk.advance(time.Second)
		start = testLog.Len()
		serveInternal(v, newProxyRequest(body))
		if strings.Contains(testLog.since(start), "ALERT") {
			t.Errorf("envelope error %d raised an alert", i)
		}
	}
	if hits, _, _, _, _ := fp.last(); hits != 0 {
		t.Fatal("a policy violation reached the provider")
	}
}

// A policy error is decided before the database: get_card is never called.
func TestProxyNoDBOnPolicyError(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, _ := proxyVault(t, fp)
	var calls atomic.Int32
	v.getCard = func(context.Context, string, string) ([]byte, int, error) {
		calls.Add(1)
		return nil, 0, errUnknownToken
	}
	for i, e := range []*proxyEnvelope{
		newEnvelope("stripe_t", "POST", "/v1/tokens", map[string]string{"Authorization": "Bearer sk_test_attacker"}, stripeTokensBody),
		newEnvelope("stripe_t", "POST", "/v1/tokens", nil, strings.Replace(stripeTokensBody, "card[number]", "description", 1)),
		newEnvelope("stripe_t", "POST", "/v1/tokens", nil, "pii[id_number]=x"), // no {{pan}}
		newEnvelope("stripe_t", "POST", "/v1/payment_intents", nil, stripePIBody+"&customer=cus_1"),
		newEnvelope("adyen_br", "POST", "/v72/payments", nil, strings.Replace(adyenBody, "AcmeBR_ECOM", "Other", 1)),
		newEnvelope("payu_co", "POST", "/payments-api/4.0/service.cgi", nil, strings.Replace(payuBody, `"referenceCode":"TestPayU",`, "", 1)),
		newEnvelope("stripe_t", "POST", "/v1/charges", nil, stripeTokensBody),
		newEnvelope("nope", "POST", "/v1/tokens", nil, stripeTokensBody),
		newEnvelope("stripe_t", "POST", "/v1/tokens", nil, "a=%zz"),
		func() *proxyEnvelope {
			e := newEnvelope("stripe_t", "POST", "/v1/tokens", nil, stripeTokensBody)
			e.Token = "tok_bad"
			return e
		}(),
	} {
		if rec := serveInternal(v, newProxyRequest(envelopeJSON(e))); rec.Code != http.StatusBadRequest {
			t.Errorf("case %d: status %d, want 400", i, rec.Code)
		}
	}
	if rec := serveInternal(v, newProxyRequest(`{"account":"stripe_t","x":1}`)); rec.Code != http.StatusBadRequest {
		t.Errorf("bad envelope: status %d", rec.Code)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("get_card called %d times on policy errors", n)
	}
	if hits, _, _, _, _ := fp.last(); hits != 0 {
		t.Fatal("a policy error reached the provider")
	}
}

// TestProxyEmbeddedCardOnly sends card-free and off-catalog probes through the handler with the embedded
// catalog (catalog.json): a /v1/tokens request that carries no {{pan}} (a pii token, a card-free
// body, a card body without the number) would only borrow the vault's Stripe credential, so it is
// refused as a placeholder violation; so are endpoints outside the catalog (payment_methods is
// storage) and a token cloned through customer. Each is 400 with its alert, before get_card and
// with nothing sent to the provider.
func TestProxyEmbeddedCardOnly(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := embeddedStripeVault(t, testSecret)
	pointAccount(t, v, "stripe_test", fp.ts)
	clk := &fakeClock{t: testNow}
	v.now = clk.now
	tok := seedCardNamed(t, v, s, testCVV, testName)
	var calls atomic.Int32
	v.getCard = func(context.Context, string, string) ([]byte, int, error) {
		calls.Add(1)
		return nil, 0, errUnknownToken
	}
	for _, c := range []struct {
		name, path, body, msg, reason string
	}{
		{"tokens pii probe", "/v1/tokens", "pii[id_number]=x", msgPlaceholder, "placeholder"},
		{"tokens without {{pan}}", "/v1/tokens", strings.Replace(embeddedTokensBody, "card[number]={{pan}}&", "", 1), msgPlaceholder, "placeholder"},
		{"tokens card-free body", "/v1/tokens", "metadata[k]=v", msgPlaceholder, "placeholder"},
		{"tokens empty body", "/v1/tokens", "", msgPlaceholder, "placeholder"},
		{"tokens with customer", "/v1/tokens", embeddedTokensBody + "&customer=cus_1", msgForbiddenField, "forbidden_field"},
		{"payment_methods", "/v1/payment_methods", "type=card&card[number]={{pan}}", msgEndpointNotAllowed, "endpoint"},
		{"payment_intents", "/v1/payment_intents", "payment_method_data[card][number]={{pan}}", msgEndpointNotAllowed, "endpoint"},
	} {
		clk.advance(time.Second) // one proxy_policy alert per second
		start := testLog.Len()
		rec := serveInternal(v, stripeProxyRequest(tok, c.path, nil, c.body))
		if rec.Code != http.StatusBadRequest || rec.Body.String() != wantErrBody(c.msg) {
			t.Errorf("%s: status %d, want 400 %q", c.name, rec.Code, c.msg)
		}
		endpoint := "tokens"
		if c.reason == "endpoint" {
			endpoint = "-"
		}
		if line := " ALERT proxy_policy account=stripe_test endpoint=" + endpoint + " reason=" + c.reason + "\n"; !strings.Contains(testLog.since(start), line) {
			t.Errorf("%s: no alert%s", c.name, strings.TrimSuffix(line, "\n"))
		}
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("get_card called %d times", n)
	}
	if hits, _, _, _, _ := fp.last(); hits != 0 {
		t.Errorf("%d requests reached the provider", hits)
	}
	if v.cvv.take(tok) != testCVV {
		t.Error("a refused request consumed the CVV")
	}
}

// PayU end to end: the provider receives the body credential and the signature over the signer
// inputs (sha256 for payu_co), and the rest of the body unchanged.
func TestProxyPayUSignature(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := newTestVault(t)
	pointAccount(t, v, "payu_co", fp.ts)
	tok := seedCardNamed(t, v, s, testCVV, testName)
	e := validEnvelope("payu")
	e.Token = tok
	rec := serveInternal(v, newProxyRequest(envelopeJSON(e)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	_, method, path, hdr, sent := fp.last()
	if method != "POST" || path != "/payments-api/4.0/service.cgi" || hdr.Get("Content-Type") != "application/json" || hdr.Get("Authorization") != "" {
		t.Fatalf("outbound %s %s, or headers wrong", method, path)
	}
	var got struct {
		Merchant struct {
			APIKey string `json:"apiKey"`
		} `json:"merchant"`
		Transaction struct {
			Order struct {
				Signature string `json:"signature"`
			} `json:"order"`
		} `json:"transaction"`
	}
	if err := json.Unmarshal(sent, &got); err != nil {
		t.Fatal("outbound body is not JSON")
	}
	sum := sha256.Sum256([]byte(payuTestAPIKey + "~508029~TestPayU~3~USD"))
	sig := hex.EncodeToString(sum[:])
	if got.Transaction.Order.Signature != sig {
		t.Error("transaction.order.signature is not the test vector")
	}
	if got.Merchant.APIKey != payuTestAPIKey {
		t.Error("merchant.apiKey is not the account secret") // never print it
	}
	want := strings.NewReplacer(`"{{secret:apiKey}}"`, `"`+payuTestAPIKey+`"`, `"{{signature}}"`, `"`+sig+`"`).Replace(seededValues("json", payuBody))
	if string(sent) != want {
		t.Errorf("outbound body is not the platform body plus substitutions (len %d, want %d)", len(sent), len(want))
	}
}

func TestProxyVelocity(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := proxyVault(t, fp)
	tok := seedCard(t, v, s, testCVV)
	s.velocity = true
	start := testLog.Len()
	rec := serveInternal(v, tokensRequest(tok, stripeTokensBody))
	if rec.Code != http.StatusTooManyRequests || rec.Body.String() != wantErrBody(msgVelocity) {
		t.Fatalf("status %d, body len %d, want 429 velocity", rec.Code, rec.Body.Len())
	}
	if !strings.Contains(testLog.since(start), " ALERT velocity token="+tok+" caller=0A1B2C account=stripe_t\n") {
		t.Fatal("no ALERT velocity line with token, caller and account")
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
	tok := seedCard(t, v, s, testCVV)
	const marker = "store-error-marker-91ab"
	s.getErr = errors.New(marker)
	start := testLog.Len()
	rec := serveInternal(v, tokensRequest(tok, stripeTokensBody))
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != wantErrBody(msgInternal) {
		t.Fatalf("status %d, body len %d, want 500 internal", rec.Code, rec.Body.Len())
	}
	if out := testLog.since(start); strings.Contains(out, marker) || strings.Contains(out, "ALERT") || strings.Count(out, "\n") != 1 {
		t.Fatalf("store error log unexpected (len %d, %d lines)", len(out), strings.Count(out, "\n"))
	}
	if hits, _, _, _, _ := fp.last(); hits != 0 {
		t.Fatal("store error reached the provider")
	}
	if v.cvv.take(tok) != testCVV {
		t.Fatal("a store error consumed the CVV")
	}

	// A wrapped velocity/unknown error is still recognized.
	s.getErr = nil
	v.getCard = func(context.Context, string, string) ([]byte, int, error) {
		return nil, 0, fmt.Errorf("wrapped: %w", errUnknownToken)
	}
	if rec := serveInternal(v, tokensRequest(tok, stripeTokensNoCVV)); rec.Body.String() != wantErrBody(msgUnknownToken) {
		t.Fatalf("wrapped errUnknownToken: status %d", rec.Code)
	}
	v.getCard = func(context.Context, string, string) ([]byte, int, error) {
		return nil, 0, fmt.Errorf("wrapped: %w", errVelocity)
	}
	if rec := serveInternal(v, tokensRequest(tok, stripeTokensNoCVV)); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("wrapped errVelocity: status %d", rec.Code)
	}
}

func TestProxyDecryptFailed(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := proxyVault(t, fp)
	tok := seedCard(t, v, s, testCVV)
	row := s.rows[tok]
	row.ciphertext[len(row.ciphertext)-1] ^= 0x01
	start := testLog.Len()
	rec := serveInternal(v, tokensRequest(tok, stripeTokensBody))
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != wantErrBody(msgInternal) {
		t.Fatalf("status %d, body len %d, want 500 internal", rec.Code, rec.Body.Len())
	}
	if !strings.Contains(testLog.since(start), " ALERT decrypt_failed token="+tok+" key_version=1 account=stripe_t\n") {
		t.Fatal("no ALERT decrypt_failed line")
	}
	if v.cvv.take(tok) != testCVV {
		t.Fatal("a decrypt failure consumed the CVV")
	}

	// A row whose key version has no loaded DEK is a decrypt failure too.
	tok2 := seedCard(t, v, s, "")
	row = s.rows[tok2]
	row.keyVersion = 9
	s.rows[tok2] = row
	start = testLog.Len()
	rec = serveInternal(v, tokensRequest(tok2, stripeTokensNoCVV))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(testLog.since(start), " ALERT decrypt_failed token="+tok2+" key_version=9 account=stripe_t\n") {
		t.Fatalf("missing DEK: status %d, or no alert", rec.Code)
	}

	// Authentic ciphertext whose plaintext is not a card record is a decrypt failure too.
	tok3 := newToken()
	s.rows[tok3] = fakeRow{ciphertext: seal(dekOf(v, 1), []byte("not json"), cardAAD(tok3)), last4: "0000", keyVersion: 1}
	start = testLog.Len()
	rec = serveInternal(v, tokensRequest(tok3, stripeTokensNoCVV))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(testLog.since(start), " ALERT decrypt_failed token="+tok3+" key_version=1 account=stripe_t\n") {
		t.Fatalf("bad plaintext: status %d, or no alert", rec.Code)
	}

	if hits, _, _, _, _ := fp.last(); hits != 0 {
		t.Fatal("decrypt failure reached the provider")
	}
}

// A stored ciphertext is bound to its token: the same row copied under another token (same
// ciphertext, same key version) fails as decrypt_failed before anything is sent or consumed.
func TestProxyCiphertextNotPortable(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := proxyVault(t, fp)
	tokA := seedCard(t, v, s, "")
	tokB := newToken()
	s.mu.Lock()
	rowA := s.rows[tokA]
	s.rows[tokB] = fakeRow{ciphertext: bytes.Clone(rowA.ciphertext), last4: rowA.last4, keyVersion: rowA.keyVersion}
	s.mu.Unlock()
	v.cvv.put(tokB, testCVV)

	start := testLog.Len()
	rec := serveInternal(v, tokensRequest(tokB, stripeTokensBody))
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != wantErrBody(msgInternal) {
		t.Fatalf("status %d, body len %d, want 500 internal", rec.Code, rec.Body.Len())
	}
	if !strings.Contains(testLog.since(start), " ALERT decrypt_failed token="+tokB+" key_version=1 account=stripe_t\n") {
		t.Fatal("no ALERT decrypt_failed line for the copied row")
	}
	if hits, _, _, _, _ := fp.last(); hits != 0 {
		t.Fatal("a copied ciphertext reached the provider")
	}
	if v.cvv.take(tokB) != testCVV {
		t.Fatal("a copied ciphertext consumed the CVV")
	}

	// The original row still works under its own token.
	if rec := serveInternal(v, tokensRequest(tokA, stripeTokensNoCVV)); rec.Code != http.StatusOK {
		t.Fatalf("original token: status %d, want 200", rec.Code)
	}
}

func TestProxyEgressInvariant(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := proxyVault(t, fp)
	tok := seedCard(t, v, s, "")
	good := v.catalog.accounts["stripe_t"].host
	for i, host := range []string{"", good + "/x", "evil.example@" + good} {
		v.catalog.accounts["stripe_t"].host = host
		start := testLog.Len()
		rec := serveInternal(v, tokensRequest(tok, stripeTokensNoCVV))
		if rec.Code != http.StatusInternalServerError || rec.Body.String() != wantErrBody(msgInternal) {
			t.Fatalf("case %d: status %d, body len %d, want 500 internal", i, rec.Code, rec.Body.Len())
		}
		if !strings.Contains(testLog.since(start), " ALERT egress_invariant account=stripe_t\n") {
			t.Fatalf("case %d: no ALERT egress_invariant line", i)
		}
	}

	// Any other render failure (here a missing secret) is 500 without the egress alert.
	v.catalog.accounts["stripe_t"].host = good
	delete(v.catalog.accounts["stripe_t"].secrets, "secretKey")
	start := testLog.Len()
	rec := serveInternal(v, tokensRequest(tok, stripeTokensNoCVV))
	if rec.Code != http.StatusInternalServerError || strings.Contains(testLog.since(start), "ALERT") {
		t.Fatalf("missing secret: status %d, or an alert", rec.Code)
	}
	if hits, _, _, _, _ := fp.last(); hits != 0 {
		t.Fatal("a render failure reached the provider")
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
	rec := serveInternal(v, tokensRequest(tok, stripeTokensNoCVV))
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
	rec := serveInternal(v, tokensRequest(tok, stripeTokensNoCVV))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Body.String(); got != `{"number":"****4242","f":"****4242","h":"****4242"}` {
		t.Fatalf("body not masked as expected (len %d, has PAN %v)", len(got), len(luhnWindowOffsets(joinDigitSeparators(got))) > 0)
	}
	out := testLog.since(start)
	if !strings.Contains(out, " ALERT pan_echo account=stripe_t endpoint=tokens token="+tok+"\n") {
		t.Fatal("no ALERT pan_echo line")
	}
	if strings.Count(out, "ALERT") != 1 {
		t.Fatalf("%d ALERT lines, want 1", strings.Count(out, "ALERT"))
	}

	// A clean response raises no alert.
	fp.respond = nil
	start = testLog.Len()
	serveInternal(v, tokensRequest(tok, stripeTokensNoCVV))
	if strings.Contains(testLog.since(start), "ALERT") {
		t.Fatal("clean response raised an alert")
	}

	// A provider response with no Content-Type gets none from the vault either, and the
	// provider's status is passed through.
	fp.respond = func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Content-Type"] = nil // suppress sniffing
		w.WriteHeader(http.StatusPaymentRequired)
		w.Write([]byte(`card_declined`))
	}
	rec = serveInternal(v, tokensRequest(tok, stripeTokensNoCVV))
	if rec.Code != http.StatusPaymentRequired || rec.Body.String() != "card_declined" || rec.Header().Get("Content-Type") != "" {
		t.Errorf("no Content-Type case: status %d, Content-Type %q", rec.Code, rec.Header().Get("Content-Type"))
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
	rec := serveInternal(v, tokensRequest(tok, stripeTokensNoCVV))
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
		rec := serveInternal(v, tokensRequest(tok, stripeTokensNoCVV))
		if rec.Code != http.StatusBadGateway || rec.Body.String() != wantErrBody(msgProvider) {
			t.Errorf("encoding case %d: status %d, body len %d, want 502", i, rec.Code, rec.Body.Len())
		}
	}
}

func TestProxyProviderUnreachable(t *testing.T) {
	closed := httptest.NewTLSServer(http.NotFoundHandler())
	v, s := newTestVault(t)
	pointAccount(t, v, "stripe_t", closed)
	closed.Close()
	tok := seedCard(t, v, s, "")
	start := testLog.Len()
	rec := serveInternal(v, tokensRequest(tok, stripeTokensNoCVV))
	if rec.Code != http.StatusBadGateway || rec.Body.String() != `{"error":"provider unreachable"}`+"\n" {
		t.Fatalf("status %d, body len %d, want 502 provider unreachable", rec.Code, rec.Body.Len())
	}
	if out := testLog.since(start); strings.Count(out, "\n") != 1 || strings.Contains(out, "127.0.0.1") {
		t.Fatalf("unreachable log unexpected (len %d, %d lines)", len(out), strings.Count(out, "\n"))
	}

	// A provider whose certificate is not trusted is unreachable too (TLS is verified). (All
	// httptest servers share one certificate, so trust nothing at all here.)
	fp := newFakeProvider(t, nil)
	pointAccount(t, v, "stripe_t", fp.ts)
	v.client = newOutboundClient(x509.NewCertPool())
	if rec := serveInternal(v, tokensRequest(tok, stripeTokensNoCVV)); rec.Code != http.StatusBadGateway {
		t.Fatalf("untrusted cert: status %d, want 502", rec.Code)
	}
	if hits, _, _, _, _ := fp.last(); hits != 0 {
		t.Fatal("untrusted provider received the request")
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
	rec := serveInternal(v, tokensRequest(tok, stripeTokensNoCVV))
	if rec.Code != http.StatusBadGateway || rec.Body.String() != wantErrBody(msgProvider) {
		t.Fatalf("status %d, body len %d, want 502", rec.Code, rec.Body.Len())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(testPAN)) {
		t.Fatal("oversize response leaked the PAN")
	}

	// Exactly 4 MiB is accepted and masked, PAN near the end included.
	size.Store(maxProviderResponse)
	rec = serveInternal(v, tokensRequest(tok, stripeTokensNoCVV))
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

// A 2xx from the provider means the card has left the vault, so the CVV still cached for the token
// is dropped even when the request did not use {{cvv}}. Any other status keeps it for a retry.
func TestProxyDropsCVVOnHandoff(t *testing.T) {
	for _, c := range []struct {
		status  int
		dropped bool
	}{
		{http.StatusOK, true},
		{http.StatusCreated, true},
		{http.StatusFound, false},
		{http.StatusInternalServerError, false},
	} {
		t.Run(fmt.Sprint(c.status), func(t *testing.T) {
			fp := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(c.status)
				w.Write([]byte(`{}`))
			})
			v, s := proxyVault(t, fp)
			tok := seedCard(t, v, s, testCVV)
			rec := serveInternal(v, tokensRequest(tok, stripeTokensNoCVV))
			if rec.Code != c.status {
				t.Fatalf("status %d, want %d", rec.Code, c.status)
			}
			if hits, _, _, _, _ := fp.last(); hits != 1 {
				t.Fatalf("provider hits %d, want 1", hits)
			}
			got := v.cvv.take(tok)
			if c.dropped && got != "" {
				t.Fatal("CVV still cached after a 2xx hand-off")
			}
			if !c.dropped && got != testCVV {
				t.Fatal("CVV not cached after a non-2xx provider response")
			}
		})
	}
}

// A card sealed under a key version this instance has not loaded yet (written by an instance
// that saw a rotation first) is decrypted after one on-demand refresh.
func TestProxyRefreshOnUnknownVersion(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := proxyVault(t, fp)
	dek1 := dekOf(v, 1)
	dek2 := bytes.Repeat([]byte{0x02}, 32)
	pt, err := json.Marshal(card{PAN: testPAN, ExpMonth: "12", ExpYear: "2030"})
	if err != nil {
		t.Fatal("marshal card failed")
	}
	tok := newToken()
	s.rows[tok] = fakeRow{ciphertext: seal(dek2, pt, cardAAD(tok)), last4: "4242", keyVersion: 2}
	var calls atomic.Int32
	v.refreshDEKs = func(context.Context) error {
		calls.Add(1)
		v.keys.Store(&dekSet{deks: map[int][]byte{1: dek1, 2: dek2}, current: 2})
		return nil
	}
	start := testLog.Len()
	rec := serveInternal(v, tokensRequest(tok, stripeTokensNoCVV))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (body len %d)", rec.Code, rec.Body.Len())
	}
	if hits, _, _, _, _ := fp.last(); hits != 1 {
		t.Fatalf("provider hits %d, want 1", hits)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("refresh ran %d times, want 1", n)
	}
	if strings.Contains(testLog.since(start), "decrypt_failed") {
		t.Fatal("decrypt_failed logged for a version a refresh supplied")
	}
	// A known version never triggers a refresh.
	tok1 := seedCard(t, v, s, "")
	v.lastRefresh.Store(0)
	if rec := serveInternal(v, tokensRequest(tok1, stripeTokensNoCVV)); rec.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("known version: status %d, refreshes %d; want 200 and no new refresh", rec.Code, calls.Load())
	}
}

// A forged key version that never appears costs one refresh per window, however many requests
// carry it, and every such request still fails as decrypt_failed.
func TestProxyUnknownVersionRateLimited(t *testing.T) {
	fp := newFakeProvider(t, nil)
	v, s := proxyVault(t, fp)
	tok := seedCard(t, v, s, "")
	row := s.rows[tok]
	row.keyVersion = 999
	s.rows[tok] = row
	var calls atomic.Int32
	v.refreshDEKs = func(context.Context) error { calls.Add(1); return nil }
	for i := range 5 {
		start := testLog.Len()
		rec := serveInternal(v, tokensRequest(tok, stripeTokensNoCVV))
		if rec.Code != http.StatusInternalServerError || rec.Body.String() != wantErrBody(msgInternal) {
			t.Fatalf("request %d: status %d, body len %d, want 500 internal", i, rec.Code, rec.Body.Len())
		}
		if !strings.Contains(testLog.since(start), " ALERT decrypt_failed token="+tok+" key_version=999 account=stripe_t\n") {
			t.Fatalf("request %d: no ALERT decrypt_failed line", i)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("refresh ran %d times for 5 requests, want 1", n)
	}
	if hits, _, _, _, _ := fp.last(); hits != 0 {
		t.Fatal("an undecryptable card reached the provider")
	}
}
