package main

import (
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// /proxy request policy: checkProxy
// ---------------------------------------------------------------------------

const checkToken = "tok_0123456789abcdef0123456789abcdef"

// occSummary renders occs as "addr=placeholder" strings and checks each span holds the placeholder
// text (quoted for json).
func occSummary(t *testing.T, format string, body []byte, occs []occurrence) []string {
	t.Helper()
	var out []string
	for _, o := range occs {
		want := o.ph.String()
		if format == "json" {
			want = `"` + want + `"`
		}
		if string(body[o.start:o.end]) != want {
			t.Errorf("occurrence %s: span does not hold %s", o.addr, o.ph)
		}
		out = append(out, o.addr+"="+o.ph.String())
	}
	return out
}

func TestCheckProxyAccepts(t *testing.T) {
	c := testCatalog(t, "127.0.0.1:9")
	cases := []struct {
		name, provider, endpoint, path string
		occs                           []string
		headers                        http.Header
		cvv, holder                    bool
	}{
		{"stripe", "stripe", "payment_intents", "/v1/payment_intents", []string{
			"payment_method_data[card][number]={{pan}}", "payment_method_data[card][exp_month]={{exp_month}}",
			"payment_method_data[card][exp_year]={{exp_year}}", "payment_method_data[card][cvc]={{cvv}}",
		}, http.Header{"Idempotency-Key": {"ord-1"}}, true, false},
		{"stripe_confirm", "stripe", "confirm_payment_intent", "/v1/payment_intents/pi_123/confirm?expand[]=latest_charge&expand%5B%5D=customer",
			[]string{"payment_method_data[card][number]={{pan}}", "payment_method_data[card][exp_month]={{exp_month}}",
				"payment_method_data[card][exp_year]={{exp_year}}"}, http.Header{"Accept": {"application/json"}}, false, false},
		{"adyen", "adyen", "payments", "/v72/payments", []string{
			"/paymentMethod/number={{pan}}", "/paymentMethod/expiryMonth={{exp_month}}", "/paymentMethod/expiryYear={{exp_year}}",
			"/paymentMethod/cvc={{cvv}}", "/paymentMethod/holderName={{name}}",
		}, http.Header{"Idempotency-Key": {"ord-1"}}, true, true},
		{"mercadopago", "mercadopago", "card_tokens", "/v1/card_tokens", []string{
			"/card_number={{pan}}", "/expiration_month={{exp_month:int}}", "/expiration_year={{exp_year:int}}", "/security_code={{cvv}}",
		}, http.Header{"X-Idempotency-Key": {"k-1"}}, true, false},
		{"payu", "payu", "submit_transaction", "/payments-api/4.0/service.cgi", []string{
			"/merchant/apiKey={{secret:apiKey}}", "/transaction/order/signature={{signature}}",
			"/transaction/creditCard/number={{pan}}", "/transaction/creditCard/securityCode={{cvv}}",
			"/transaction/creditCard/expirationDate={{exp:yyyy/mm}}", "/transaction/creditCard/name={{name}}",
		}, http.Header{}, true, true},
		{"pagarme", "pagarme", "orders", "/core/v5/orders", []string{
			"/payments/0/credit_card/card/number={{pan}}", "/payments/0/credit_card/card/exp_month={{exp_month:int}}",
			"/payments/0/credit_card/card/exp_year={{exp_year:int}}", "/payments/0/credit_card/card/holder_name={{name}}",
		}, http.Header{"Accept": {"application/json"}}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validEnvelope(tc.name)
			p, perr := c.checkProxy(e)
			if perr != nil {
				t.Fatalf("rejected: %+v", *perr)
			}
			if p.acct != c.accounts[e.Account] || p.prov != c.providers[tc.provider] || p.ep != catEndpointByID(t, c, tc.provider, tc.endpoint) {
				t.Errorf("plan account/provider/endpoint = %v/%v/%v", p.acct.name, p.prov.name, p.ep.id)
			}
			if p.path != tc.path || string(p.body) != e.Request.Body {
				t.Errorf("plan path %q or body differs from the envelope", p.path)
			}
			if got := occSummary(t, p.prov.format, p.body, p.occs); !slices.Equal(got, tc.occs) {
				t.Errorf("occs = %v, want %v", got, tc.occs)
			}
			if p.usesCVV != tc.cvv || p.usesName != tc.holder {
				t.Errorf("usesCVV, usesName = %v, %v, want %v, %v", p.usesCVV, p.usesName, tc.cvv, tc.holder)
			}
			// Only allowlisted headers are carried; template headers are rendered by the vault.
			if !reflect.DeepEqual(p.headers, tc.headers) {
				// Names only: test failure messages never print header values.
				t.Errorf("plan header names = %v, want %v (or values differ)", slices.Sorted(maps.Keys(p.headers)), slices.Sorted(maps.Keys(tc.headers)))
			}
		})
	}

	// Forbid with an allowed literal: storePaymentMethod false and absent both pass.
	e := validEnvelope("adyen")
	e.Request.Body = strings.Replace(adyenBody, `,"storePaymentMethod":false`, "", 1)
	if _, perr := c.checkProxy(e); perr != nil {
		t.Errorf("adyen without storePaymentMethod rejected: %+v", *perr)
	}
	// Omitting a template header is fine: the vault adds it.
	e = validEnvelope("adyen")
	e.Request.Headers = nil
	if _, perr := c.checkProxy(e); perr != nil {
		t.Errorf("adyen without X-API-Key rejected: %+v", *perr)
	}
	// Positions other than {{pan}} are optional: a body with only {{pan}} passes.
	e = validEnvelope("stripe")
	e.Request.Body = "amount=1000&currency=usd&payment_method_data[type]=card&payment_method_data[card][number]={{pan}}"
	if p, perr := c.checkProxy(e); perr != nil {
		t.Errorf("stripe body with only {{pan}} rejected: %+v", *perr)
	} else if len(p.occs) != 1 || p.usesCVV || p.usesName {
		t.Errorf("stripe body with only {{pan}}: %d occs, usesCVV %v, usesName %v", len(p.occs), p.usesCVV, p.usesName)
	}
}

func TestCheckProxyRejects(t *testing.T) {
	c := testCatalog(t, "127.0.0.1:9")
	const (
		ep  = "endpoint"
		hdr = "header"
		ph  = "placeholder"
	)
	type tc struct {
		name, base  string
		mut         func(e *proxyEnvelope)
		msg, reason string
	}
	path := func(p string) func(e *proxyEnvelope) { return func(e *proxyEnvelope) { e.Request.Path = p } }
	header := func(k, v string) func(e *proxyEnvelope) {
		return func(e *proxyEnvelope) {
			h := map[string]string{}
			maps.Copy(h, e.Request.Headers)
			h[k] = v
			e.Request.Headers = h
		}
	}
	body := func(b string) func(e *proxyEnvelope) { return func(e *proxyEnvelope) { e.Request.Body = b } }
	replace := func(base, old, new string) func(e *proxyEnvelope) {
		if !strings.Contains(base, old) {
			panic("replace: fixture lacks " + old)
		}
		return body(strings.Replace(base, old, new, 1))
	}
	cases := []tc{
		// Envelope errors: no alert reason.
		{"invalid token", "adyen", func(e *proxyEnvelope) { e.Token = "tok_ABC" }, msgInvalidToken, ""},
		{"unknown account", "adyen", func(e *proxyEnvelope) { e.Account = "nope" }, msgUnknownAccount, ""},
		{"other env account", "adyen", func(e *proxyEnvelope) { e.Account = "adyen_br_live" }, msgUnknownAccount, ""},
		{"empty account", "adyen", func(e *proxyEnvelope) { e.Account = "" }, msgUnknownAccount, ""},

		// Endpoint matching.
		{"wrong method", "adyen", func(e *proxyEnvelope) { e.Request.Method = "PUT" }, msgEndpointNotAllowed, ep},
		{"lowercase method", "adyen", func(e *proxyEnvelope) { e.Request.Method = "post" }, msgEndpointNotAllowed, ep},
		{"unknown path", "adyen", path("/v72/refunds"), msgEndpointNotAllowed, ep},
		{"other provider path", "adyen", path("/v1/card_tokens"), msgEndpointNotAllowed, ep},
		{"trailing slash", "adyen", path("/v72/payments/"), msgEndpointNotAllowed, ep},
		{"no leading slash", "adyen", path("v72/payments"), msgEndpointNotAllowed, ep},
		{"empty path", "adyen", path(""), msgEndpointNotAllowed, ep},
		{"percent-encoded slash", "stripe_confirm", path("/v1/payment_intents/pi%2F1/confirm"), msgEndpointNotAllowed, ep},
		{"percent-encoded literal", "adyen", path("/v72/p%61yments"), msgEndpointNotAllowed, ep},
		{"dot-dot", "stripe_confirm", path("/v1/payment_intents/../tokens"), msgEndpointNotAllowed, ep},
		{"dot-dot wildcard", "stripe_confirm", path("/v1/payment_intents/../confirm"), msgEndpointNotAllowed, ep},
		{"double slash", "adyen", path("//v72/payments"), msgEndpointNotAllowed, ep},
		{"inner double slash", "adyen", path("/v72//payments"), msgEndpointNotAllowed, ep},
		{"wildcard bad char", "stripe_confirm", path("/v1/payment_intents/pi.1/confirm"), msgEndpointNotAllowed, ep},
		{"wildcard too long", "stripe_confirm", path("/v1/payment_intents/" + strings.Repeat("a", 129) + "/confirm"), msgEndpointNotAllowed, ep},
		{"placeholder in path", "stripe_confirm", path("/v1/payment_intents/{{pan}}/confirm"), msgEndpointNotAllowed, ep},
		{"fragment", "adyen", path("/v72/payments#x"), msgEndpointNotAllowed, ep},
		{"unlisted query key", "stripe_confirm", path("/v1/payment_intents/pi_1/confirm?limit=3"), msgEndpointNotAllowed, ep},
		{"query on endpoint without keys", "adyen", path("/v72/payments?expand[]=a"), msgEndpointNotAllowed, ep},
		{"placeholder in query value", "stripe_confirm", path("/v1/payment_intents/pi_1/confirm?expand[]={{pan}}"), msgEndpointNotAllowed, ep},
		{"encoded placeholder in query value", "stripe_confirm", path("/v1/payment_intents/pi_1/confirm?expand[]=%7B%7Bpan%7D%7D"), msgEndpointNotAllowed, ep},
		{"bare question mark", "stripe_confirm", path("/v1/payment_intents/pi_1/confirm?"), msgEndpointNotAllowed, ep},
		{"query without value", "stripe_confirm", path("/v1/payment_intents/pi_1/confirm?expand[]"), msgEndpointNotAllowed, ep},
		{"query semicolon", "stripe_confirm", path("/v1/payment_intents/pi_1/confirm?expand[]=a;b"), msgEndpointNotAllowed, ep},
		{"query second question mark", "stripe_confirm", path("/v1/payment_intents/pi_1/confirm?expand[]=a?b"), msgEndpointNotAllowed, ep},

		// Headers.
		{"content-type header", "adyen", header("Content-Type", "text/plain"), msgHeaderNotAllowed, hdr},
		{"host header", "adyen", header("Host", "evil.example"), msgHeaderNotAllowed, hdr},
		{"x-use-mocks header", "adyen", header("X-Use-Mocks", "true"), msgHeaderNotAllowed, hdr},
		{"stripe-account header", "stripe", header("Stripe-Account", "acct_attacker"), msgHeaderNotAllowed, hdr},
		{"other endpoint's template header", "adyen", header("Authorization", "Bearer {{secret:apiKey}}"), msgHeaderNotAllowed, hdr},
		{"template header other value", "adyen", header("X-API-Key", "attacker"), msgHeaderNotAllowed, hdr},
		{"template header other secret", "stripe", header("Authorization", "Bearer {{secret:other}}"), msgHeaderNotAllowed, hdr},
		{"template header padded", "stripe", header("Authorization", "Bearer {{secret:secretKey}} "), msgHeaderNotAllowed, hdr},
		{"duplicate after canonicalization", "adyen", header("idempotency-key", "ord-2"), msgHeaderNotAllowed, hdr},
		{"duplicate template after canonicalization", "adyen", header("x-api-key", "{{secret:apiKey}}"), msgHeaderNotAllowed, hdr},
		{"pan in header value", "adyen", header("Idempotency-Key", "{{pan}}"), msgHeaderNotAllowed, hdr},
		{"pan in template header", "mercadopago", header("Authorization", "Bearer {{pan}}"), msgHeaderNotAllowed, hdr},
		{"empty header value", "adyen", header("Accept", ""), msgHeaderNotAllowed, hdr},
		{"long header value", "adyen", header("Accept", strings.Repeat("a", 1025)), msgHeaderNotAllowed, hdr},
		{"non-ascii header value", "adyen", header("Accept", "café"), msgHeaderNotAllowed, hdr},
		{"control char header value", "adyen", header("Accept", "a\r\nX-Evil: 1"), msgHeaderNotAllowed, hdr},
		{"invalid header name", "adyen", header("Accept ", "a"), msgHeaderNotAllowed, hdr},
		{"empty header name", "adyen", header("", "a"), msgHeaderNotAllowed, hdr},

		// Body parsing.
		{"invalid json", "adyen", body(`{"merchantAccount":`), msgBadBody, "body"},
		{"duplicate key", "adyen", replace(adyenBody, `"reference":"ord-1",`, `"reference":"ord-1","reference":"ord-2",`), msgBadBody, "body"},
		{"empty json body", "adyen", body(""), msgBadBody, "body"},
		{"duplicate form key", "stripe", body(stripePIBody + "&amount=1"), msgBadBody, "body"},
		{"malformed form", "stripe", body(stripePIBody + "&&x=1"), msgBadBody, "body"},

		// Placeholders.
		{"placeholder at unlisted address", "adyen", replace(adyenBody, `"reference":"ord-1"`, `"reference":"{{pan}}"`), msgPlaceholder, ph},
		{"pan twice", "adyen", replace(adyenBody, `"holderName":"{{name}}"`, `"holderName":"{{pan}}"`), msgPlaceholder, ph},
		{"secret at card position", "adyen", replace(adyenBody, `"number":"{{pan}}"`, `"number":"{{secret:apiKey}}"`), msgPlaceholder, ph},
		{"wrong modifier at position", "mercadopago", replace(mpBody, `"{{exp_month:int}}"`, `"{{exp_month}}"`), msgPlaceholder, ph},
		{"signature at unlisted address", "payu", replace(payuBody, `"description":"x"`, `"description":"{{signature}}"`), msgPlaceholder, ph},
		{"unknown placeholder", "adyen", replace(adyenBody, `"reference":"ord-1"`, `"reference":"{{foo}}"`), msgPlaceholder, ph},
		{"concatenated placeholder", "adyen", replace(adyenBody, `"reference":"ord-1"`, `"reference":"x{{pan}}"`), msgPlaceholder, ph},
		{"placeholder in key", "adyen", replace(adyenBody, `"reference"`, `"{{pan}}"`), msgPlaceholder, ph},
		{"literal credential at secret position", "payu", replace(payuBody, `"{{secret:apiKey}}"`, `"attackerKey"`), msgPlaceholder, ph},
		{"literal pan at card position", "adyen", replace(adyenBody, `"number":"{{pan}}"`, `"number":"4111111111111111"`), msgPlaceholder, ph},
		{"object at position", "mercadopago", replace(mpBody, `"security_code":"{{cvv}}"`, `"security_code":{"x":"y"}`), msgPlaceholder, ph},
		{"number at position", "mercadopago", replace(mpBody, `"{{exp_month:int}}"`, `3`), msgPlaceholder, ph},
		{"form literal at position", "stripe", replace(stripePIBody, `[cvc]={{cvv}}`, `[cvc]=123`), msgPlaceholder, ph},
		{"case-variant credential next to position", "payu", replace(payuBody, `"merchant":{`, `"Merchant":{"apiKey":"attackerKey"},"merchant":{`), msgPlaceholder, ph},
		{"case-variant credential instead of position", "payu", replace(payuBody, `"apiKey":"{{secret:apiKey}}",`, `"APIKEY":"attackerKey",`), msgPlaceholder, ph},
		{"form placeholder at unlisted key", "stripe", body(stripePIBody + "&description={{pan}}"), msgPlaceholder, ph},
		{"form encoded placeholder", "stripe", body(stripePIBody + "&description=%7B%7Bpan%7D%7D"), msgPlaceholder, ph},

		// Every request carries {{pan}}; the vault credential is never lent to a non-card call.
		{"no pan: card-free form body", "stripe", body("amount=1000&currency=usd"), msgPlaceholder, ph},
		{"no pan: other card placeholders only", "stripe", replace(stripePIBody, "&payment_method_data[card][number]={{pan}}", ""), msgPlaceholder, ph},
		{"no pan: empty form body", "stripe", body(""), msgPlaceholder, ph},
		{"no pan: json", "mercadopago", replace(mpBody, `"card_number":"{{pan}}",`, ""), msgPlaceholder, ph},
		{"no pan: payu with credential and signature only", "payu", replace(payuBody, `"number":"{{pan}}",`, ""), msgPlaceholder, ph},

		// Pins.
		{"adyen merchantAccount mismatch", "adyen", replace(adyenBody, `"AcmeBR_ECOM"`, `"AcmeBR_LIVE"`), msgPinMismatch, "pin"},
		{"adyen merchantAccount absent", "adyen", replace(adyenBody, `"merchantAccount":"AcmeBR_ECOM",`, ""), msgPinMismatch, "pin"},
		{"adyen merchantAccount not a string", "adyen", replace(adyenBody, `"AcmeBR_ECOM"`, `["AcmeBR_ECOM"]`), msgPinMismatch, "pin"},
		{"adyen merchantAccount case variant", "adyen", replace(adyenBody, `"merchantAccount":"AcmeBR_ECOM",`,
			`"merchantAccount":"AcmeBR_ECOM","MerchantAccount":"AcmeBR_LIVE",`), msgPinMismatch, "pin"},
		{"payu command CREATE_TOKEN", "payu", replace(payuBody, `"SUBMIT_TRANSACTION"`, `"CREATE_TOKEN"`), msgPinMismatch, "pin"},
		{"payu command absent", "payu", replace(payuBody, `"command":"SUBMIT_TRANSACTION",`, ""), msgPinMismatch, "pin"},
		{"payu accountId as number", "payu", replace(payuBody, `"accountId":"512321"`, `"accountId":512321`), msgPinMismatch, "pin"},
		{"payu apiLogin mismatch", "payu", replace(payuBody, `"pRRXKOl8ikMmt9u"`, `"attacker"`), msgPinMismatch, "pin"},

		// Forbid.
		{"adyen storePaymentMethod true", "adyen", replace(adyenBody, `"storePaymentMethod":false`, `"storePaymentMethod":true`), msgForbiddenField, "forbidden_field"},
		{"adyen storePaymentMethod string false", "adyen", replace(adyenBody, `"storePaymentMethod":false`, `"storePaymentMethod":"false"`), msgForbiddenField, "forbidden_field"},
		{"adyen storePaymentMethod null", "adyen", replace(adyenBody, `"storePaymentMethod":false`, `"storePaymentMethod":null`), msgForbiddenField, "forbidden_field"},
		{"adyen shopperReference present", "adyen", replace(adyenBody, `"storePaymentMethod":false`, `"shopperReference":"u1"`), msgForbiddenField, "forbidden_field"},
		{"adyen storePaymentMethod case variant", "adyen", replace(adyenBody, `"storePaymentMethod":false`,
			`"storePaymentMethod":false,"StorePaymentMethod":true`), msgForbiddenField, "forbidden_field"},
		{"stripe customer present", "stripe", body(stripePIBody + "&customer=cus_1"), msgForbiddenField, "forbidden_field"},
		{"stripe nested forbid present", "stripe", body(stripePIBody + "&payment_method_options[card][setup_future_usage]=off_session"), msgForbiddenField, "forbidden_field"},
		{"stripe forbid case variant", "stripe", body(stripePIBody + "&Customer=cus_1"), msgForbiddenField, "forbidden_field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validEnvelope(tc.base)
			tc.mut(e)
			p, perr := c.checkProxy(e)
			if perr == nil {
				t.Fatalf("accepted (plan for %s)", p.ep.id)
			}
			if p != nil {
				t.Errorf("plan returned with an error")
			}
			if perr.status != http.StatusBadRequest || perr.msg != tc.msg || perr.reason != tc.reason {
				t.Errorf("got %d %q reason %q, want 400 %q reason %q", perr.status, perr.msg, perr.reason, tc.msg, tc.reason)
			}
			// The alert names the matched endpoint once there is one (catalog text only).
			wantEP := map[string]string{"stripe": "payment_intents", "stripe_confirm": "confirm_payment_intent", "adyen": "payments",
				"mercadopago": "card_tokens", "payu": "submit_transaction", "pagarme": "orders"}[tc.base]
			if tc.reason == "" || tc.reason == ep {
				wantEP = ""
			}
			if perr.endpoint != wantEP {
				t.Errorf("endpoint = %q, want %q", perr.endpoint, wantEP)
			}
		})
	}
}

// TestCheckProxyDuplicateCardPlaceholder: a catalog listing {{pan}} at two positions still allows
// it at most once per request.
func TestCheckProxyDuplicateCardPlaceholder(t *testing.T) {
	c := testCatalog(t, "127.0.0.1:9")
	catEndpointByID(t, c, "adyen", "payments").positions["/additionalData/pan2"] = placeholder{kind: "pan"}
	e := validEnvelope("adyen")
	e.Request.Body = strings.Replace(adyenBody, `"reference":"ord-1"`, `"additionalData":{"pan2":"{{pan}}"}`, 1)
	_, perr := c.checkProxy(e)
	if perr == nil || perr.msg != msgPlaceholder || perr.reason != "placeholder" {
		t.Errorf("{{pan}} twice: got %+v", perr)
	}
	// Two expiry-year forms are the same card placeholder kind.
	catEndpointByID(t, c, "adyen", "payments").positions["/additionalData/yy"] = placeholder{kind: "exp_year", mod: "yy"}
	e.Request.Body = strings.Replace(adyenBody, `"reference":"ord-1"`, `"additionalData":{"yy":"{{exp_year:yy}}"}`, 1)
	if _, perr := c.checkProxy(e); perr == nil || perr.msg != msgPlaceholder {
		t.Errorf("{{exp_year}} and {{exp_year:yy}}: got %+v", perr)
	}
}

// TestCheckProxyArrayPosition: positions match array indexes exactly.
func TestCheckProxyArrayPosition(t *testing.T) {
	c := testCatalog(t, "127.0.0.1:9")
	e := validEnvelope("pagarme")
	e.Request.Body = strings.Replace(pagarmeBody, `"payments":[{`, `"payments":[{"payment_method":"pix"},{`, 1)
	_, perr := c.checkProxy(e)
	if perr == nil || perr.status != http.StatusBadRequest || perr.msg != msgPlaceholder || perr.reason != "placeholder" {
		t.Errorf("{{pan}} at /payments/1/...: got %+v", perr)
	}
}

// TestCheckProxyMemoryBound: the policy checks compare JSON Pointers in place, so a long key over a
// wide array in an accepted body costs its own size a few times per walk of the body, never once per
// element beneath it. The bound is the cost the key adds over a one-byte key, so the decoder's own
// cost per token cancels out.
func TestCheckProxyMemoryBound(t *testing.T) {
	c := testCatalog(t, "127.0.0.1:9")
	arr := "[" + strings.TrimSuffix(strings.Repeat("1,", 4000), ",") + "]"
	key := strings.Repeat("k", 8000)
	cost := func(key string) int {
		e := validEnvelope("adyen")
		e.Request.Body = strings.Replace(adyenBody, `{"amount"`, `{"`+key+`":`+arr+`,"amount"`, 1)
		if _, perr := c.checkProxy(e); perr != nil {
			t.Fatalf("checkProxy: %+v", perr)
		}
		return allocated(func() { _, _ = c.checkProxy(e) })
	}
	if n := cost(key) - cost("k"); n >= 64*len(key) {
		t.Errorf("a %d-byte key over 4000 elements added %d bytes to checkProxy, want < %d", len(key), n, 64*len(key))
	}
}

// TestCheckProxyHeaderCaseVariant: a credential header under any spelling of its
// name must exactly equal the template, and is never carried into the plan.
func TestCheckProxyHeaderCaseVariant(t *testing.T) {
	c := testCatalog(t, "127.0.0.1:9")
	for _, name := range []string{"authorization", "AUTHORIZATION", "Authorization", "aUtHoRiZaTiOn"} {
		e := validEnvelope("mercadopago")
		e.Request.Headers = map[string]string{name: "Bearer sk_attacker"}
		if _, perr := c.checkProxy(e); perr == nil || perr.msg != msgHeaderNotAllowed || perr.reason != "header" {
			t.Errorf("%s: Bearer sk_attacker: got %+v", name, perr)
		}
		e.Request.Headers = map[string]string{name: "Bearer {{secret:accessToken}}", "accept": "application/json"}
		p, perr := c.checkProxy(e)
		if perr != nil {
			t.Fatalf("%s: exact template rejected: %+v", name, *perr)
		}
		if !reflect.DeepEqual(p.headers, http.Header{"Accept": {"application/json"}}) {
			t.Errorf("%s: plan header names = %v, want only Accept (or its value differs)", name, slices.Sorted(maps.Keys(p.headers)))
		}
	}
}

// TestCheckProxySignerInputs: the payu signer's inputs must be present,
// non-placeholder strings or numbers.
func TestCheckProxySignerInputs(t *testing.T) {
	c := testCatalog(t, "127.0.0.1:9")
	cases := map[string][2]string{
		"referenceCode absent":      {`"referenceCode":"TestPayU",`, ``},
		"referenceCode placeholder": {`"referenceCode":"TestPayU"`, `"referenceCode":"{{name}}"`},
		"referenceCode object":      {`"referenceCode":"TestPayU"`, `"referenceCode":{"a":"b"}`},
		"referenceCode null":        {`"referenceCode":"TestPayU"`, `"referenceCode":null`},
		"value absent":              {`"value":3,`, ``},
		"value bool":                {`"value":3`, `"value":true`},
		"currency absent":           {`,"currency":"USD"`, ``},
		"currency array":            {`"currency":"USD"`, `"currency":["USD"]`},
	}
	for name, r := range cases {
		e := validEnvelope("payu")
		if !strings.Contains(payuBody, r[0]) {
			t.Fatalf("%s: fixture lacks %s", name, r[0])
		}
		e.Request.Body = strings.Replace(payuBody, r[0], r[1], 1)
		if _, perr := c.checkProxy(e); perr == nil || perr.status != http.StatusBadRequest || perr.msg != msgPlaceholder || perr.reason != "placeholder" {
			t.Errorf("%s: got %+v", name, perr)
		}
	}
	// Numbers and strings are both valid inputs.
	e := validEnvelope("payu")
	e.Request.Body = strings.Replace(payuBody, `"value":3`, `"value":"3.50"`, 1)
	if _, perr := c.checkProxy(e); perr != nil {
		t.Errorf("string value rejected: %+v", *perr)
	}
	// Even if a catalog listed a placeholder position at a signer input, the signer refuses it.
	catEndpointByID(t, c, "payu", "submit_transaction").positions["/transaction/order/referenceCode"] = placeholder{kind: "secret", arg: "apiKey"}
	e = validEnvelope("payu")
	e.Request.Body = strings.Replace(payuBody, `"referenceCode":"TestPayU"`, `"referenceCode":"{{secret:apiKey}}"`, 1)
	if _, perr := c.checkProxy(e); perr == nil || perr.msg != msgPlaceholder || perr.reason != "placeholder" {
		t.Errorf("listed placeholder at signer input: got %+v", perr)
	}
}

// TestCheckProxyEmptyBody: an empty body never passes, because every request must carry {{pan}}
// (the card-only rule). This holds even on an endpoint stripped in memory of its positions, pins and signer (a shape
// parseCatEndpoint refuses): there is no empty-body shortcut. A json body must parse (msgBadBody);
// an empty form body is zero fields, so it lacks {{pan}} (msgPlaceholder).
func TestCheckProxyEmptyBody(t *testing.T) {
	c := testCatalog(t, "127.0.0.1:9")
	ay := catEndpointByID(t, c, "adyen", "payments")
	e := validEnvelope("adyen")
	e.Request.Body = ""
	if _, perr := c.checkProxy(e); perr == nil || perr.msg != msgBadBody {
		t.Errorf("json empty body with positions and pins: got %+v", perr)
	}
	ay.positions, ay.pins = map[string]placeholder{}, map[string]catPin{}
	if _, perr := c.checkProxy(e); perr == nil || perr.msg != msgBadBody {
		t.Errorf("json empty body, no positions/pins/signer: got %+v", perr)
	}

	tk := catEndpointByID(t, c, "stripe", "tokens")
	e = newEnvelope("stripe_t", "POST", "/v1/tokens", nil, "")
	if _, perr := c.checkProxy(e); perr == nil || perr.msg != msgPlaceholder || perr.reason != "placeholder" {
		t.Errorf("form empty body: got %+v", perr)
	}
	tk.positions, tk.forbid = map[string]placeholder{}, map[string][]fieldValue{}
	if _, perr := c.checkProxy(e); perr == nil || perr.msg != msgPlaceholder || perr.reason != "placeholder" {
		t.Errorf("form empty body, no positions/pins/signer: got %+v", perr)
	}
}

// TestCheckProxyHardening covers additional checks: no body on GET/HEAD, an unknown signer fails
// closed, case-variant aliases of signer inputs, and form forbid sub-keys.
func TestCheckProxyHardening(t *testing.T) {
	c := testCatalog(t, "127.0.0.1:9")

	// (a) A GET or HEAD endpoint takes no body. parseCatEndpoint still accepts a GET card endpoint, so
	// this uses a parse-level fixture: confirm_payment_intent declared as GET. Since every request
	// must also carry {{pan}}, such an endpoint can never pass: with a body it is msgBadBody, and
	// without one it lacks {{pan}}.
	getJSON := strings.Replace(testCatalogJSON, `"id": "confirm_payment_intent", "method": "POST",`, `"id": "confirm_payment_intent", "method": "GET",`, 1)
	gc, err := parseCatalog([]byte(getJSON), "dev")
	if err != nil || catEndpointByID(t, gc, "stripe", "confirm_payment_intent").method != "GET" {
		t.Fatalf("GET fixture: %v", err)
	}
	e := validEnvelope("stripe_confirm")
	e.Request.Method = "GET"
	if _, perr := gc.checkProxy(e); perr == nil || perr.msg != msgBadBody || perr.reason != "body" || perr.endpoint != "confirm_payment_intent" {
		t.Errorf("GET with a body: got %+v", perr)
	}
	e.Request.Body = ""
	if _, perr := gc.checkProxy(e); perr == nil || perr.msg != msgPlaceholder || perr.reason != "placeholder" {
		t.Errorf("GET without a body (no {{pan}}): got %+v", perr)
	}
	// HEAD is not a catalog method; set it in memory to cover the HEAD half of the check.
	catEndpointByID(t, gc, "stripe", "confirm_payment_intent").method = "HEAD"
	e = validEnvelope("stripe_confirm")
	e.Request.Method = "HEAD"
	if _, perr := gc.checkProxy(e); perr == nil || perr.msg != msgBadBody || perr.reason != "body" {
		t.Errorf("HEAD with a body: got %+v", perr)
	}
	e.Request.Body = ""
	if _, perr := gc.checkProxy(e); perr == nil || perr.msg != msgPlaceholder {
		t.Errorf("HEAD without a body (no {{pan}}): got %+v", perr)
	}

	// (b) An unknown signer fails closed (parseCatEndpoint already refuses one).
	pu := catEndpointByID(t, c, "payu", "submit_transaction")
	pu.signer = "payu2"
	if _, perr := c.checkProxy(validEnvelope("payu")); perr == nil || perr.msg != msgEndpointNotAllowed || perr.reason != "endpoint" {
		t.Errorf("unknown signer: got %+v", perr)
	}
	pu.signer = "payu"

	// (c) A case-variant alias of a signer input.
	for i, r := range [][2]string{
		{`"referenceCode":"TestPayU",`, `"referenceCode":"TestPayU","ReferenceCode":"Other",`},
		{`"value":3,`, `"value":3,"VALUE":4,`},
		{`"TX_VALUE":{`, `"tx_value":{"currency":"COP"},"TX_VALUE":{`},
	} {
		if !strings.Contains(payuBody, r[0]) {
			t.Fatalf("case %d: fixture lacks %s", i, r[0])
		}
		e := validEnvelope("payu")
		e.Request.Body = strings.Replace(payuBody, r[0], r[1], 1)
		if _, perr := c.checkProxy(e); perr == nil || perr.msg != msgPlaceholder || perr.reason != "placeholder" {
			t.Errorf("signer input alias %d: got %+v", i, perr)
		}
	}

	// (d) A forbidden form field also forbids its bracketed sub-keys, under any case.
	for _, extra := range []string{"&customer[]=cus_1", "&customer[x]=cus_1", "&customer[x][y]=1", "&Customer[x]=cus_1",
		"&setup_future_usage[a]=off_session", "&payment_method_options[card][setup_future_usage][x]=1"} {
		e := validEnvelope("stripe")
		e.Request.Body = stripePIBody + extra
		if _, perr := c.checkProxy(e); perr == nil || perr.msg != msgForbiddenField || perr.reason != "forbidden_field" {
			t.Errorf("forbid sub-key %q: got %+v", extra, perr)
		}
	}
	// A key that is exactly the forbidden field plus "[" is refused too (validFormKey already refuses
	// it as a malformed key; the forbid check's ">=" covers it on its own as well).
	for _, extra := range []string{"&customer[=x", "&Customer[=x"} {
		e := validEnvelope("stripe")
		e.Request.Body = stripePIBody + extra
		if _, perr := c.checkProxy(e); perr == nil {
			t.Errorf("forbid key %q accepted", extra)
		}
	}
	// A key that only shares a prefix without "[" is not covered.
	e = validEnvelope("stripe")
	e.Request.Body = stripePIBody + "&customer_note=x"
	if _, perr := c.checkProxy(e); perr != nil {
		t.Errorf("customer_note rejected: %+v", *perr)
	}
}
