package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// POST /tokenize and CORS
// ---------------------------------------------------------------------------

// goodBody is the canonical valid /tokenize request (spaced PAN, CVV present).
const goodBody = `{"pan":"4242 4242 4242 4242","exp_month":"12","exp_year":"2030","cvv":"9071"}`

// validAuthz is a session token the platform would mint for testNow.
func validAuthz() string { return "Bearer " + mintSession(testHMACKey, testNow.Add(10*time.Minute)) }

func TestTokenize(t *testing.T) {
	expired := "Bearer " + mintSession(testHMACKey, testNow.Add(-time.Second))
	future := "Bearer " + mintSession(testHMACKey, testNow.Add(15*time.Minute+time.Second))
	wrongKey := "Bearer " + mintSession(bytes.Repeat([]byte{0x43}, 32), testNow.Add(time.Minute))

	cases := []tokCase{
		// Success, including every passing variant of the card validation rules.
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

// A preflight never needs a session and gets exactly the CORS preflight headers.
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
	pt, err := unseal(dekOf(v, 1), row.ciphertext, cardAAD(resp.Token))
	if err != nil {
		t.Fatal("stored ciphertext does not unseal with DEK v1 and its token's AAD")
	}
	if _, err := unseal(dekOf(v, 1), row.ciphertext, cardAAD(newToken())); err == nil {
		t.Fatal("stored ciphertext unseals with another token's AAD")
	}
	if _, err := unseal(dekOf(v, 1), row.ciphertext, nil); err == nil {
		t.Fatal("stored ciphertext unseals without AAD")
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
	v.keys.Store(&dekSet{deks: map[int][]byte{1: dekOf(v, 1), 2: bytes.Repeat([]byte{0x02}, 32)}, current: 2})
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
	} else if _, err := unseal(dekOf(v, 2), row.ciphertext, cardAAD(resp.Token)); err != nil {
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

// An optional name is sealed with the card: the plaintext gains a "name" key only when
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
	pt, err := unseal(dekOf(v, row.keyVersion), row.ciphertext, cardAAD(resp.Token))
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
	pt, err = unseal(dekOf(v, s.rows[resp.Token].keyVersion), s.rows[resp.Token].ciphertext, cardAAD(resp.Token))
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
	v.keys.Store(&dekSet{deks: v.keys.Load().deks, current: 9})
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

// A full CVV cache does not fail /tokenize: the card is stored, its CVV is not cached, and the
// vault raises ALERT cvv_cache_full at most once per second.
func TestTokenizeCVVCacheFull(t *testing.T) {
	v, s := newTestVault(t)
	fillCVVCache(v.cvv, "tok_fill_", cvvCacheMax, testNow.Add(time.Hour))
	start := testLog.Len()
	for i := 0; i < 5; i++ {
		rec := serveTokenize(v, tokRequest(tokCase{}))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status %d, want 200", i, rec.Code)
		}
		var resp tokenizeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || !tokenRe.MatchString(resp.Token) {
			t.Fatalf("request %d: response is not a token response", i)
		}
		s.mu.Lock()
		_, stored := s.rows[resp.Token]
		s.mu.Unlock()
		if !stored {
			t.Fatalf("request %d: card not stored", i)
		}
		if v.cvv.take(resp.Token) != "" {
			t.Fatalf("request %d: CVV cached beyond the cap", i)
		}
	}
	if n := cvvCacheLen(v.cvv); n != cvvCacheMax {
		t.Fatalf("cache holds %d entries, want %d", n, cvvCacheMax)
	}
	if n := strings.Count(testLog.since(start), "ALERT cvv_cache_full\n"); n != 1 {
		t.Fatalf("%d cvv_cache_full alerts within one second, want 1", n)
	}
}
