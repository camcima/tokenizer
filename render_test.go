package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Rendering, the PayU signer and account URLs
// ---------------------------------------------------------------------------

// renderCard is the decrypted card the render tests substitute.
var renderCard = card{PAN: testPAN, ExpMonth: "03", ExpYear: "2030", Name: "Ana María"}

// renderCatalog is testCatalog with every dev account's secrets set (as loadAccountSecrets does at boot).
func renderCatalog(t *testing.T) *catalog {
	t.Helper()
	c := testCatalog(t, "127.0.0.1:9")
	c.accounts["stripe_t"].secrets["secretKey"] = "sk_x"
	c.accounts["adyen_br"].secrets["apiKey"] = "ak_test_1"
	c.accounts["mp_ar"].secrets["accessToken"] = "APP_USR-1"
	c.accounts["payu_co"].secrets["apiKey"] = payuTestAPIKey
	c.accounts["pagarme_br"].secrets["secretKey"] = "sk_x"
	return c
}

// renderPlan runs e through checkProxy, failing the test on a rejection.
func renderPlan(t *testing.T, c *catalog, e *proxyEnvelope) *proxyPlan {
	t.Helper()
	p, perr := c.checkProxy(e)
	if perr != nil {
		t.Fatalf("checkProxy rejected: %+v", *perr)
	}
	return p
}

// renderBody renders p and returns the request and the body it carries. Content-Length must equal
// the body length.
func renderBody(t *testing.T, p *proxyPlan, c card, cvv string) (*http.Request, []byte) {
	t.Helper()
	req, err := renderRequest(context.Background(), p, c, cvv)
	if err != nil {
		t.Fatalf("renderRequest: %v", err)
	}
	var body []byte
	if req.Body != nil {
		body, err = io.ReadAll(req.Body)
		if err != nil {
			t.Fatal("read rendered body failed")
		}
	}
	if req.ContentLength != int64(len(body)) {
		t.Errorf("Content-Length %d, body length %d", req.ContentLength, len(body))
	}
	return req, body
}

// checkRendered compares a rendered body with want without printing either (they hold card data).
func checkRendered(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if string(got) != want {
		t.Errorf("%s: rendered body differs from the platform body plus substitutions (len %d, want %d)", name, len(got), len(want))
	}
}

func TestRenderJSONTyped(t *testing.T) {
	c := renderCatalog(t)
	req, body := renderBody(t, renderPlan(t, c, validEnvelope("mercadopago")), renderCard, testCVV)
	want := strings.NewReplacer(`"{{pan}}"`, `"`+testPAN+`"`, `"{{exp_month:int}}"`, `3`, `"{{exp_year:int}}"`, `2030`,
		`"{{cvv}}"`, `"`+testCVV+`"`).Replace(mpBody)
	checkRendered(t, "mercadopago", body, want)
	if !bytes.Contains(body, []byte(`"expiration_month":3,`)) || !bytes.Contains(body, []byte(`"expiration_year":2030,`)) {
		t.Errorf("mercadopago: expiry is not a bare JSON number")
	}
	if req.Method != "POST" || req.URL.String() != "https://127.0.0.1:9/v1/card_tokens" {
		t.Errorf("mercadopago: %s %s", req.Method, req.URL.Redacted())
	}

	// Adyen: string expiry, the cardholder name, and the account's base path.
	req, body = renderBody(t, renderPlan(t, c, validEnvelope("adyen")), renderCard, testCVV)
	want = strings.NewReplacer(`"{{pan}}"`, `"`+testPAN+`"`, `"{{exp_month}}"`, `"03"`, `"{{exp_year}}"`, `"2030"`,
		`"{{cvv}}"`, `"`+testCVV+`"`, `"{{name}}"`, `"Ana María"`).Replace(adyenBody)
	checkRendered(t, "adyen", body, want)
	if req.URL.String() != "https://127.0.0.1:9/checkout/v72/payments" {
		t.Errorf("adyen: URL %s", req.URL.Redacted())
	}

	// Pagar.me: array positions and integer expiry; no CVV placeholder, so none is needed.
	_, body = renderBody(t, renderPlan(t, c, validEnvelope("pagarme")), renderCard, "")
	want = strings.NewReplacer(`"{{pan}}"`, `"`+testPAN+`"`, `"{{exp_month:int}}"`, `3`, `"{{exp_year:int}}"`, `2030`,
		`"{{name}}"`, `"Ana María"`).Replace(pagarmeBody)
	checkRendered(t, "pagarme", body, want)

	// A name needing JSON escapes is encoded as a JSON string.
	odd := renderCard
	odd.Name = `Ana "A" \ María`
	_, body = renderBody(t, renderPlan(t, c, validEnvelope("pagarme")), odd, "")
	var parsed struct {
		Payments []struct {
			CreditCard struct {
				Card struct {
					HolderName string `json:"holder_name"`
				} `json:"card"`
			} `json:"credit_card"`
		} `json:"payments"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || len(parsed.Payments) != 1 || parsed.Payments[0].CreditCard.Card.HolderName != odd.Name {
		t.Errorf("pagarme: escaped name does not round-trip (parse ok=%v)", err == nil)
	}
}

func TestRenderExpiryFormats(t *testing.T) {
	cases := []struct {
		ph         placeholder
		json, form string
	}{
		{placeholder{kind: "exp_month"}, `"03"`, `03`},
		{placeholder{kind: "exp_month", mod: "int"}, `3`, `3`},
		{placeholder{kind: "exp_year"}, `"2030"`, `2030`},
		{placeholder{kind: "exp_year", mod: "yy"}, `"30"`, `30`},
		{placeholder{kind: "exp_year", mod: "int"}, `2030`, `2030`},
		{placeholder{kind: "exp", mod: "yyyy/mm"}, `"2030/03"`, `2030%2F03`},
		{placeholder{kind: "exp", mod: "mm/yy"}, `"03/30"`, `03%2F30`},
	}
	for _, tc := range cases {
		t.Run(tc.ph.String(), func(t *testing.T) {
			c := renderCatalog(t)
			// Every request carries {{pan}}, so each body has it next to the expiry under test.
			catEndpointByID(t, c, "adyen", "payments").positions = map[string]placeholder{"/paymentMethod/expiry": tc.ph, "/paymentMethod/number": {kind: "pan"}}
			e := validEnvelope("adyen")
			e.Request.Body = `{"merchantAccount":"AcmeBR_ECOM","paymentMethod":{"number":"{{pan}}","expiry":"` + tc.ph.String() + `"},"x":1}`
			_, body := renderBody(t, renderPlan(t, c, e), renderCard, "")
			checkRendered(t, "json", body, `{"merchantAccount":"AcmeBR_ECOM","paymentMethod":{"number":"`+testPAN+`","expiry":`+tc.json+`},"x":1}`)

			catEndpointByID(t, c, "stripe", "tokens").positions = map[string]placeholder{"card[expiry]": tc.ph, "card[number]": {kind: "pan"}}
			e = newEnvelope("stripe_t", "POST", "/v1/tokens", nil, "a=1&card[number]={{pan}}&card[expiry]="+tc.ph.String()+"&b=2")
			_, body = renderBody(t, renderPlan(t, c, e), renderCard, "")
			checkRendered(t, "form", body, "a=1&card[number]="+testPAN+"&card[expiry]="+tc.form+"&b=2")
		})
	}

	// A December card: no leading zero to drop.
	c := renderCatalog(t)
	dec := renderCard
	dec.ExpMonth = "12"
	_, body := renderBody(t, renderPlan(t, c, validEnvelope("mercadopago")), dec, testCVV)
	if !bytes.Contains(body, []byte(`"expiration_month":12,`)) {
		t.Errorf("December: month not rendered as 12")
	}
}

func TestRenderForm(t *testing.T) {
	c := renderCatalog(t)
	req, body := renderBody(t, renderPlan(t, c, validEnvelope("stripe")), renderCard, testCVV)
	want := strings.NewReplacer("{{pan}}", testPAN, "{{exp_month}}", "03", "{{exp_year}}", "2030", "{{cvv}}", testCVV).Replace(stripePIBody)
	checkRendered(t, "payment_intents", body, want)
	if req.Method != "POST" || req.URL.String() != "https://127.0.0.1:9/v1/payment_intents" {
		t.Errorf("payment_intents: %s %s", req.Method, req.URL.Redacted())
	}

	// Values are percent-encoded in place; the rest of the body is untouched.
	odd := renderCard
	odd.Name = "Ana María & Co=1"
	e := newEnvelope("stripe_t", "POST", "/v1/tokens", nil, "card[number]={{pan}}&card[name]={{name}}&card[cvc]={{cvv}}&x=%41")
	_, body = renderBody(t, renderPlan(t, c, e), odd, testCVV)
	checkRendered(t, "tokens", body, "card[number]="+testPAN+"&card[name]=Ana+Mar%C3%ADa+%26+Co%3D1&card[cvc]="+testCVV+"&x=%41")
	q, err := url.ParseQuery(string(body))
	if err != nil || q.Get("card[name]") != odd.Name || q.Get("card[number]") != testPAN || len(q) != 4 {
		t.Errorf("tokens: rendered form does not decode to the card (parse ok=%v, %d keys)", err == nil, len(q))
	}

	// A wildcard path with a query: the validated query is kept.
	req, body = renderBody(t, renderPlan(t, c, validEnvelope("stripe_confirm")), renderCard, "")
	checkRendered(t, "confirm_payment_intent", body,
		strings.NewReplacer("{{pan}}", testPAN, "{{exp_month}}", "03", "{{exp_year}}", "2030").Replace(stripeConfirmBody))
	if req.Method != "POST" ||
		req.URL.String() != "https://127.0.0.1:9/v1/payment_intents/pi_123/confirm?expand[]=latest_charge&expand%5B%5D=customer" {
		t.Errorf("confirm_payment_intent: %s %s", req.Method, req.URL.Redacted())
	}
}

func TestRenderHeaders(t *testing.T) {
	c := renderCatalog(t)
	// headerNames lists names only: test failure messages never print header values.
	headerNames := func(h http.Header) []string { return slices.Sorted(maps.Keys(h)) }
	check := func(name string, req *http.Request, want http.Header) {
		t.Helper()
		if !slices.Equal(headerNames(req.Header), headerNames(want)) {
			t.Errorf("%s: header names %v, want %v", name, headerNames(req.Header), headerNames(want))
			return
		}
		for k, v := range want {
			if !slices.Equal(req.Header[k], v) {
				t.Errorf("%s: header %s has the wrong value", name, k)
			}
		}
	}

	req, _ := renderBody(t, renderPlan(t, c, validEnvelope("stripe")), renderCard, testCVV)
	check("stripe", req, http.Header{
		"Authorization": {"Bearer sk_x"}, "Content-Type": {formContentType}, "User-Agent": {"pan-vault/1"},
		"Idempotency-Key": {"ord-1"},
	})

	req, _ = renderBody(t, renderPlan(t, c, validEnvelope("pagarme")), renderCard, "")
	check("pagarme", req, http.Header{
		"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("sk_x:"))}, "Content-Type": {"application/json"},
		"User-Agent": {"pan-vault/1"}, "Accept": {"application/json"},
	})
	if req.Header.Get("Authorization") != "Basic c2tfeDo=" {
		t.Errorf("pagarme: Basic credential is not base64(secret + \":\")")
	}

	// The platform omitted X-API-Key; the vault adds it.
	e := validEnvelope("adyen")
	delete(e.Request.Headers, "X-API-Key")
	req, _ = renderBody(t, renderPlan(t, c, e), renderCard, testCVV)
	check("adyen", req, http.Header{
		"X-Api-Key": {"ak_test_1"}, "Content-Type": {"application/json"}, "User-Agent": {"pan-vault/1"},
		"Idempotency-Key": {"ord-1"},
	})

	req, _ = renderBody(t, renderPlan(t, c, validEnvelope("mercadopago")), renderCard, testCVV)
	check("mercadopago", req, http.Header{
		"Authorization": {"Bearer APP_USR-1"}, "Content-Type": {"application/json"}, "User-Agent": {"pan-vault/1"},
		"X-Idempotency-Key": {"k-1"},
	})

	// A {{signature}} header template carries the signer's output.
	pu := catEndpointByID(t, c, "payu", "submit_transaction")
	pu.headers["X-Signature"] = "sig={{signature}}"
	p := renderPlan(t, c, validEnvelope("payu"))
	sig, err := signPayU(p)
	if err != nil {
		t.Fatalf("signPayU: %v", err)
	}
	req, _ = renderBody(t, p, renderCard, testCVV)
	check("payu", req, http.Header{
		"X-Signature": {"sig=" + sig}, "Content-Type": {"application/json"}, "User-Agent": {"pan-vault/1"},
	})

	// Only allowlisted platform headers are copied, and never over a template header.
	p = renderPlan(t, c, validEnvelope("stripe"))
	p.headers.Set("X-Evil", "1")
	p.headers.Set("Authorization", "Bearer sk_attacker")
	p.headers.Set("Accept-Encoding", "identity")
	req, _ = renderBody(t, p, renderCard, testCVV)
	check("stripe tampered plan", req, http.Header{
		"Authorization": {"Bearer sk_x"}, "Content-Type": {formContentType}, "User-Agent": {"pan-vault/1"},
		"Idempotency-Key": {"ord-1"},
	})
}

// TestRenderZeroesPreviousSent: renderRequest zeroes the body left in p.sent by an earlier render of the same plan before it
// renders again (best effort), whether or not the new render succeeds.
func TestRenderZeroesPreviousSent(t *testing.T) {
	c := renderCatalog(t)
	p := renderPlan(t, c, validEnvelope("stripe"))
	if _, err := renderRequest(context.Background(), p, renderCard, testCVV); err != nil || len(p.sent) == 0 {
		t.Fatalf("first render failed (err nil=%v)", err == nil)
	}
	first := p.sent
	if _, err := renderRequest(context.Background(), p, renderCard, testCVV); err != nil {
		t.Fatal("second render failed")
	}
	if bytes.ContainsFunc(first, func(r rune) bool { return r != 0 }) {
		t.Error("the first rendered body was not zeroed")
	}
	if len(p.sent) == 0 || &p.sent[0] == &first[0] {
		t.Error("the second render did not leave a fresh body in p.sent")
	}
	second := p.sent
	p.acct.host = "" // fails the egress invariant
	if req, err := renderRequest(context.Background(), p, renderCard, testCVV); err == nil || req != nil || p.sent != nil {
		t.Errorf("failed render: err nil=%v, p.sent set=%v", err == nil, p.sent != nil)
	}
	if bytes.ContainsFunc(second, func(r rune) bool { return r != 0 }) {
		t.Error("a failed render left the previous body unzeroed")
	}
}

// TestRenderFailsClosed: renderRequest refuses, with no request, anything it cannot fill exactly.
func TestRenderFailsClosed(t *testing.T) {
	cases := map[string]func(c *catalog, p *proxyPlan, cd *card, cvv *string){
		"cvv used but empty":   func(c *catalog, p *proxyPlan, cd *card, cvv *string) { *cvv = "" },
		"name used but empty":  func(c *catalog, p *proxyPlan, cd *card, cvv *string) { cd.Name = "" },
		"bad expiry month":     func(c *catalog, p *proxyPlan, cd *card, cvv *string) { cd.ExpMonth = "3" },
		"bad expiry year":      func(c *catalog, p *proxyPlan, cd *card, cvv *string) { cd.ExpYear = "30" },
		"body secret missing":  func(c *catalog, p *proxyPlan, cd *card, cvv *string) { delete(p.acct.secrets, "apiKey") },
		"body secret has CRLF": func(c *catalog, p *proxyPlan, cd *card, cvv *string) { p.acct.secrets["apiKey"] = "k\r\nX: 1" },
		"unknown signer":       func(c *catalog, p *proxyPlan, cd *card, cvv *string) { p.ep.signer = "payu2" },
		"no signer":            func(c *catalog, p *proxyPlan, cd *card, cvv *string) { p.ep.signer = "" },
		"span moved": func(c *catalog, p *proxyPlan, cd *card, cvv *string) {
			p.occs[0].start++
		},
		"occurrence not a rule position": func(c *catalog, p *proxyPlan, cd *card, cvv *string) {
			p.occs[0].addr = "/description"
		},
		"occurrence placeholder changed": func(c *catalog, p *proxyPlan, cd *card, cvv *string) {
			p.occs[0].ph = placeholder{kind: "pan"}
		},
		"egress host": func(c *catalog, p *proxyPlan, cd *card, cvv *string) { p.acct.host = "" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := renderCatalog(t)
			p := renderPlan(t, c, validEnvelope("payu"))
			cd, cvv := renderCard, testCVV
			mut(c, p, &cd, &cvv)
			if req, err := renderRequest(context.Background(), p, cd, cvv); err == nil || req != nil {
				t.Errorf("rendered (err nil=%v)", err == nil)
			}
		})
	}

	// Header template secrets: missing, or not printable non-space ASCII.
	for name, v := range map[string]string{"missing": "", "CRLF": "sk\r\nX-Evil: 1", "space": "sk x", "non-ascii": "sk_é"} {
		c := renderCatalog(t)
		p := renderPlan(t, c, validEnvelope("stripe"))
		if v == "" {
			delete(p.acct.secrets, "secretKey")
		} else {
			p.acct.secrets["secretKey"] = v
		}
		if req, err := renderRequest(context.Background(), p, renderCard, testCVV); err == nil || req != nil {
			t.Errorf("header secret %s: rendered (err nil=%v)", name, err == nil)
		}
	}
}

func TestSignPayU(t *testing.T) {
	c := renderCatalog(t)
	acct := c.accounts["payu_co"]
	const input = payuTestAPIKey + "~508029~TestPayU~3~USD"
	md5Sum, sha1Sum, sha256Sum := md5.Sum([]byte(input)), sha1.Sum([]byte(input)), sha256.Sum256([]byte(input))
	if hex.EncodeToString(md5Sum[:]) != "ba9ffa71559580175585e45ce70b6c37" {
		t.Fatalf("md5 of the input string is not PayU's documented example")
	}
	for hash, want := range map[string]string{
		"md5": hex.EncodeToString(md5Sum[:]), "sha1": hex.EncodeToString(sha1Sum[:]), "sha256": hex.EncodeToString(sha256Sum[:]),
	} {
		acct.values["hash"] = hash
		got, err := signPayU(renderPlan(t, c, validEnvelope("payu")))
		if err != nil || got != want {
			t.Errorf("%s: signature mismatch (err nil=%v)", hash, err == nil)
		}
	}
	acct.values["hash"] = "md5"
	if got, _ := signPayU(renderPlan(t, c, validEnvelope("payu"))); got != "ba9ffa71559580175585e45ce70b6c37" {
		t.Errorf("md5: not PayU's documented example signature")
	}

	// Body fields are used exactly as written: 3.50 stays 3.50, as a number or a string.
	for _, v := range []string{`3.50`, `"3.50"`} {
		e := validEnvelope("payu")
		e.Request.Body = strings.Replace(payuBody, `"value":3`, `"value":`+v, 1)
		sum := md5.Sum([]byte(payuTestAPIKey + "~508029~TestPayU~3.50~USD"))
		if got, err := signPayU(renderPlan(t, c, e)); err != nil || got != hex.EncodeToString(sum[:]) {
			t.Errorf("value %s: signature not over the verbatim amount (err nil=%v)", v, err == nil)
		}
	}
	// A string field is used decoded: "\u0054estPayU" is TestPayU.
	e := validEnvelope("payu")
	e.Request.Body = strings.Replace(payuBody, `"TestPayU"`, `"\u0054estPayU"`, 1)
	if e.Request.Body == payuBody {
		t.Fatal("escaped referenceCode: fixture unchanged")
	}
	if got, err := signPayU(renderPlan(t, c, e)); err != nil || got != "ba9ffa71559580175585e45ce70b6c37" {
		t.Errorf("escaped referenceCode: signature mismatch (err nil=%v)", err == nil)
	}

	// Rendering puts the signature and the body credential at their positions.
	acct.values["hash"] = "sha256"
	p := renderPlan(t, c, validEnvelope("payu"))
	_, body := renderBody(t, p, renderCard, testCVV)
	want := strings.NewReplacer(`"{{secret:apiKey}}"`, `"`+payuTestAPIKey+`"`, `"{{signature}}"`, `"`+hex.EncodeToString(sha256Sum[:])+`"`,
		`"{{pan}}"`, `"`+testPAN+`"`, `"{{cvv}}"`, `"`+testCVV+`"`, `"{{exp:yyyy/mm}}"`, `"2030/03"`, `"{{name}}"`, `"Ana María"`).Replace(payuBody)
	checkRendered(t, "payu", body, want)

	// Fail closed on anything missing or unknown.
	fails := map[string]func(p *proxyPlan){
		"unknown hash":       func(p *proxyPlan) { p.acct.values["hash"] = "sha512" },
		"no hash":            func(p *proxyPlan) { delete(p.acct.values, "hash") },
		"no apiKey":          func(p *proxyPlan) { delete(p.acct.secrets, "apiKey") },
		"no merchantId":      func(p *proxyPlan) { delete(p.acct.values, "merchantId") },
		"referenceCode gone": func(p *proxyPlan) { p.body = []byte(strings.Replace(payuBody, `"referenceCode":"TestPayU",`, "", 1)) },
		"value is an object": func(p *proxyPlan) { p.body = []byte(strings.Replace(payuBody, `"value":3`, `"value":{}`, 1)) },
		"currency placeholder": func(p *proxyPlan) {
			p.body = []byte(strings.Replace(payuBody, `"currency":"USD"`, `"currency":"{{name}}"`, 1))
		},
		"not json": func(p *proxyPlan) { p.body = []byte("referenceCode=TestPayU") },
	}
	for name, mut := range fails {
		c := renderCatalog(t)
		p := renderPlan(t, c, validEnvelope("payu"))
		mut(p)
		if got, err := signPayU(p); err == nil || got != "" {
			t.Errorf("%s: signed (err nil=%v)", name, err == nil)
		}
	}
}

func TestAccountURLInvariant(t *testing.T) {
	crafted := []string{
		"/v1/tokens", "//evil.com/x", "https://evil.com/x", "@evil.com", "/%2F%2Fevil.com",
		"/\\evil.com/x", "/v1/tokens?x=https://evil.com#frag", "/v1/tokens\r\nHost: evil.com", "/@evil.com",
		"/:443@evil.com", "///evil.com", "/v1/tokens%00", "http://evil.com", "//api.example.test@evil.com/",
		"/v1/x?a=1&b=//evil.com", "/?@evil.com", "/v1/x?#", "/v1/x#@evil.com",
	}
	for _, base := range []string{"/checkout", ""} {
		a := &catAccount{name: "t", host: "api.example.test", basePath: base}
		for i, p := range crafted {
			u, err := accountURL(a, p)
			if err != nil {
				continue
			}
			if u.Scheme != "https" || u.Host != a.host || u.User != nil || u.Fragment != "" || !strings.HasPrefix(u.Path, base+"/") {
				t.Errorf("base %q case %d: constructed URL escapes scheme/host/base path", base, i)
				continue
			}
			re, err := url.Parse(u.String())
			if err != nil || re.Scheme != "https" || re.Host != a.host || re.User != nil || re.Fragment != "" || !strings.HasPrefix(re.Path, base+"/") {
				t.Errorf("base %q case %d: reparsed URL escapes scheme/host/base path", base, i)
			}
		}
	}

	a := &catAccount{name: "t", host: "api.example.test", basePath: "/checkout"}
	for p, want := range map[string]string{
		"/v72/payments":                   "https://api.example.test/checkout/v72/payments",
		"/v1/x?expand[]=a&expand%5B%5D=b": "https://api.example.test/checkout/v1/x?expand[]=a&expand%5B%5D=b",
	} {
		if u, err := accountURL(a, p); err != nil || u.String() != want {
			t.Errorf("%s: rejected or altered (err nil=%v)", p, err == nil)
		}
	}
	if u, err := accountURL(&catAccount{host: "127.0.0.1:8443"}, "/v1/tokens"); err != nil || u.String() != "https://127.0.0.1:8443/v1/tokens" {
		t.Errorf("host with port, no base path: rejected or altered (err nil=%v)", err == nil)
	}
	for i, p := range []string{"", "v1/tokens", "@evil.com", "https://evil.com/x", "evil.com/x", " /v1/tokens",
		"/v1/tokens?", "/v1/x#frag", "/v1/x?a=1#frag", "/v1/tokens\r\n", "/v1/to kens", "/v1/x?a=\x7f",
		"/v1/../../x", "/v1/..", "/..", "/v1/./x", "/./v1", "/v1/.", "/v1/%2e%2e/x", "/v1/x%2Fy", "/%2F%2Fevil.com", "/v1/tokens%00",
		"/v1/..?a=1", "/v1/x%41?a=1"} {
		if _, err := accountURL(a, p); err == nil {
			t.Errorf("bad path %d accepted", i)
		}
	}
	for i, b := range []*catAccount{nil, {host: ""}, {host: "api.example.test", basePath: "checkout"}, {host: "api.example.test", basePath: "/checkout/"}} {
		if _, err := accountURL(b, "/v1/tokens"); err == nil {
			t.Errorf("bad account %d accepted", i)
		}
	}
}
