package main

import (
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Provider catalog: catalog.json
// ---------------------------------------------------------------------------

func TestParseCatalogValid(t *testing.T) {
	c := testCatalog(t, "127.0.0.1:9")
	if got := slices.Sorted(maps.Keys(c.accounts)); !slices.Equal(got, []string{"adyen_br", "mp_ar", "pagarme_br", "payu_co", "stripe_t"}) {
		t.Errorf("dev accounts = %v", got)
	}
	if got := slices.Sorted(maps.Keys(c.providers)); !slices.Equal(got, []string{"adyen", "mercadopago", "pagarme", "payu", "stripe"}) {
		t.Errorf("providers = %v", got)
	}
	prod, err := parseCatalog([]byte(testCatalogJSON), "prod")
	if err != nil {
		t.Fatalf("prod: %v", err)
	}
	if got := slices.Sorted(maps.Keys(prod.accounts)); !slices.Equal(got, []string{"adyen_br_live"}) {
		t.Errorf("prod accounts = %v", got)
	}
	if len(prod.providers) != 5 {
		t.Errorf("prod has %d providers, want all 5", len(prod.providers))
	}

	a := c.accounts["adyen_br"]
	if a.name != "adyen_br" || a.provider != "adyen" || a.env != "dev" || a.host != "127.0.0.1:9" || a.basePath != "/checkout" ||
		a.secretNames["apiKey"] != "projects/pci-cde-dev/secrets/adyen-br-key" || a.values["merchantAccount"] != "AcmeBR_ECOM" ||
		a.secrets == nil || len(a.secrets) != 0 {
		t.Errorf("adyen_br decoded as %+v", *a)
	}
	if s := c.accounts["stripe_t"]; s.basePath != "" || len(s.values) != 0 {
		t.Errorf("stripe_t decoded as %+v", *s)
	}

	// Stripe: form positions, forbid lists ("must be absent"), wildcard path and query keys.
	pi := catEndpointByID(t, c, "stripe", "payment_intents")
	if c.providers["stripe"].format != "form" || pi.method != "POST" || !slices.Equal(pi.path, []string{"v1", "payment_intents"}) || !pi.cardData ||
		pi.headers["Authorization"] != "Bearer {{secret:secretKey}}" || len(pi.headers) != 1 ||
		pi.positions["payment_method_data[card][number]"] != (placeholder{kind: "pan"}) || len(pi.positions) != 5 || pi.signer != "" {
		t.Errorf("stripe payment_intents decoded as %+v", *pi)
	}
	for _, addr := range []string{"setup_future_usage", "customer", "save_payment_method", "payment_method_options[card][setup_future_usage]"} {
		if f, ok := pi.forbid[addr]; !ok || f == nil || len(f) != 0 {
			t.Errorf("stripe forbid %s = %v (present %v), want empty", addr, f, ok)
		}
	}
	cpi := catEndpointByID(t, c, "stripe", "confirm_payment_intent")
	if cpi.method != "POST" || !slices.Equal(cpi.path, []string{"v1", "payment_intents", "{id}", "confirm"}) || !cpi.cardData ||
		!cpi.query["expand[]"] || len(cpi.query) != 1 || len(cpi.positions) != 4 {
		t.Errorf("stripe confirm_payment_intent decoded as %+v", *cpi)
	}

	// Adyen: canonical header name, account pin, forbid with an allowed literal.
	ay := catEndpointByID(t, c, "adyen", "payments")
	if ay.headers["X-Api-Key"] != "{{secret:apiKey}}" || len(ay.headers) != 1 {
		t.Errorf("adyen headers = %v", ay.headers)
	}
	if p := ay.pins["/merchantAccount"]; p.account != "merchantAccount" || p.literal != nil || len(ay.pins) != 1 {
		t.Errorf("adyen pin = %+v", p)
	}
	if f := ay.forbid["/storePaymentMethod"]; !slices.Equal(f, []fieldValue{{kind: "bool", text: "false"}}) {
		t.Errorf("adyen forbid storePaymentMethod = %v", f)
	}
	if f, ok := ay.forbid["/shopperReference"]; !ok || f == nil || len(f) != 0 {
		t.Errorf("adyen forbid shopperReference = %v", f)
	}

	// Mercado Pago: integer expiry.
	mp := catEndpointByID(t, c, "mercadopago", "card_tokens")
	if mp.positions["/expiration_month"] != (placeholder{kind: "exp_month", mod: "int"}) || mp.positions["/expiration_year"] != (placeholder{kind: "exp_year", mod: "int"}) {
		t.Errorf("mercadopago positions = %v", mp.positions)
	}

	// PayU: body secret, literal and account pins, signer.
	pu := catEndpointByID(t, c, "payu", "submit_transaction")
	if p := pu.pins["/command"]; p.account != "" || p.literal == nil || *p.literal != (fieldValue{kind: "string", text: "SUBMIT_TRANSACTION"}) {
		t.Errorf("payu /command pin = %+v", p)
	}
	if pu.pins["/merchant/apiLogin"].account != "apiLogin" || pu.pins["/transaction/order/accountId"].account != "accountId" ||
		pu.signer != "payu" || len(pu.headers) != 0 ||
		pu.positions["/merchant/apiKey"] != (placeholder{kind: "secret", arg: "apiKey"}) ||
		pu.positions["/transaction/order/signature"] != (placeholder{kind: "signature"}) ||
		pu.positions["/transaction/creditCard/expirationDate"] != (placeholder{kind: "exp", mod: "yyyy/mm"}) {
		t.Errorf("payu decoded as %+v", *pu)
	}

	// Pagar.me: Basic auth header, array-index position.
	pg := catEndpointByID(t, c, "pagarme", "orders")
	if pg.positions["/payments/0/credit_card/card/number"] != (placeholder{kind: "pan"}) || pg.headers["Authorization"] != "Basic {{basic:secretKey}}" {
		t.Errorf("pagarme decoded as %+v", *pg)
	}
}

// catalogMutation is one rule violation applied to testCatalogJSON: the first old is replaced by
// new, and parseCatalog must fail with an error containing want.
type catalogMutation struct{ name, old, new, want string }

// apply returns testCatalogJSON with m applied; ok is false when m.old is not in the fixture.
func (m catalogMutation) apply() (data string, ok bool) {
	switch m.name {
	case "trailing data":
		return testCatalogJSON + ` {}`, true
	case "root not an object":
		return `[]`, true
	}
	if !strings.Contains(testCatalogJSON, m.old) {
		return "", false
	}
	return strings.Replace(testCatalogJSON, m.old, m.new, 1), true
}

// catalogMutations has one mutation per catalog validation rule. TestParseCatalogRejects checks
// each; FuzzParseCatalog uses every mutated catalog as a seed.
func catalogMutations() []catalogMutation {
	const (
		stripeAcct = `"stripe_t": {"provider": "stripe", "env": "dev", "host": "upstream.test", "base_path": ""`
		adyenAcct  = `"adyen_br": {"provider": "adyen", "env": "dev", "host": "upstream.test", "base_path": "/checkout"`
		payuVals   = `"values": {"apiLogin": "pRRXKOl8ikMmt9u", "accountId": "512321", "merchantId": "508029", "hash": "sha256"}`
		cpiLine    = `"id": "confirm_payment_intent", "method": "POST", "path": "/v1/payment_intents/{id}/confirm", "query": ["expand[]"], "card_data": true,`
		tokensLine = `"id": "tokens", "method": "POST", "path": "/v1/tokens", "card_data": true,`
	)
	return []catalogMutation{
		// Strict JSON, unknown keys, wrong types.
		{"duplicate key", `"format": "form",`, `"format": "form", "format": "form",`, "strict JSON"},
		{"trailing data", "", "", "strict JSON"}, // special-cased below
		{"invalid utf-8", `AcmeBR_ECOM`, "Acme\xffBR", "strict JSON"},
		{"unknown root key", `"providers": {`, `"extra": {}, "providers": {`, `unknown key "extra"`},
		{"unknown provider key", `"format": "form",`, `"format": "form", "base": "x",`, `unknown key "base"`},
		{"unknown endpoint key", tokensLine, tokensLine + ` "bogus": true,`, `unknown key "bogus"`},
		{"unknown pin key", `{"account": "merchantAccount"}`, `{"account": "merchantAccount", "x": 1}`, `unknown key "x"`},
		{"unknown account key", stripeAcct, stripeAcct + `, "port": 1`, `unknown key "port"`},
		{"case-variant provider key", `"format": "form",`, `"Format": "form",`, `unknown key "Format"`},
		{"case-variant endpoint key", tokensLine, `"ID": "tokens", "method": "POST", "path": "/v1/tokens", "card_data": true,`, `unknown key "ID"`},
		{"case-variant account key", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "dev", "Host": "upstream.test", "base_path": ""`, `unknown key "Host"`},
		{"case-variant pin key", `{"literal": "SUBMIT_TRANSACTION"}`, `{"Literal": "SUBMIT_TRANSACTION"}`, `unknown key "Literal"`},
		{"wrong type", tokensLine, `"id": "tokens", "method": "POST", "path": "/v1/tokens", "card_data": "yes",`, "wrong type"},
		{"root not an object", "", "", "strict JSON"}, // special-cased below

		// Names.
		{"bad provider name", `"stripe": {`, `"Stripe": {`, `provider "Stripe": invalid name`},
		{"bad endpoint id", `"id": "tokens"`, `"id": "to kens"`, "invalid id"},
		{"bad account name", `"stripe_t": {`, `"stripe-t": {`, `account "stripe-t": invalid name`},

		// Provider format and endpoints.
		{"format not json/form", `"format": "form",`, `"format": "xml",`, `provider "stripe": format`},
		{"empty endpoints", `"providers": {`, `"providers": {"empty": {"format": "json", "endpoints": []},`, `provider "empty": no endpoints`},
		{"duplicate endpoint id", `"id": "tokens"`, `"id": "payment_intents"`, `endpoint "payment_intents": duplicate id`},
		{"method not allowed", tokensLine, `"id": "tokens", "method": "HEAD", "path": "/v1/tokens", "card_data": true,`, `endpoint "tokens": method`},
		{"method lowercase", tokensLine, `"id": "tokens", "method": "post", "path": "/v1/tokens", "card_data": true,`, `endpoint "tokens": method`},
		{"overlapping endpoints", cpiLine, `"id": "confirm_payment_intent", "method": "POST", "path": "/v1/{id}", "query": ["expand[]"], "card_data": true,`, "overlap"},

		// Paths.
		{"path without slash", `"/v1/tokens"`, `"v1/tokens"`, `endpoint "tokens": invalid path`},
		{"path empty segment", `"/v1/tokens"`, `"/v1//tokens"`, `endpoint "tokens": invalid path`},
		{"path trailing slash", `"/v1/tokens"`, `"/v1/tokens/"`, `endpoint "tokens": invalid path`},
		{"path dot-dot", `"/v1/tokens"`, `"/v1/../tokens"`, `endpoint "tokens": invalid path`},
		{"path dot", `"/v1/tokens"`, `"/v1/./tokens"`, `endpoint "tokens": invalid path`},
		{"path percent", `"/v1/tokens"`, `"/v1/tok%65ns"`, `endpoint "tokens": invalid path`},
		{"path query", `"/v1/tokens"`, `"/v1/tokens?x=1"`, `endpoint "tokens": invalid path`},
		{"path empty", `"/v1/tokens"`, `""`, `endpoint "tokens": invalid path`},
		{"wildcard bad name", `{id}/confirm"`, `{i-d}/confirm"`, `endpoint "confirm_payment_intent": invalid path`},
		{"wildcard empty", `{id}/confirm"`, `{}/confirm"`, `endpoint "confirm_payment_intent": invalid path`},
		{"wildcard unclosed", `{id}/confirm"`, `{id/confirm"`, `endpoint "confirm_payment_intent": invalid path`},
		{"wildcard partial segment", `{id}/confirm"`, `pi_{id}/confirm"`, `endpoint "confirm_payment_intent": invalid path`},
		{"wildcard repeated", `/v1/payment_intents/{id}/confirm"`, `/v1/{id}/{id}/confirm"`, `endpoint "confirm_payment_intent": invalid path`},
		{"query key invalid", `["expand[]"]`, `["expand[]x"]`, `query key`},
		{"query key duplicate", `["expand[]"]`, `["expand[]", "expand[]"]`, `query key`},

		// Placeholders and positions.
		{"unknown placeholder", `"card[number]": "{{pan}}"`, `"card[number]": "{{card}}"`, `position "card[number]": unknown placeholder`},
		{"unknown modifier", `"card[number]": "{{pan}}"`, `"card[number]": "{{pan:int}}"`, `position "card[number]": unknown placeholder`},
		{"not a placeholder", `"card[number]": "{{pan}}"`, `"card[number]": "4242"`, `position "card[number]": unknown placeholder`},
		// Every endpoint carries card data (the vault credential is never lent to a non-card call)
		// and lists a {{pan}} position.
		{"card_data false", tokensLine, `"id": "tokens", "method": "POST", "path": "/v1/tokens", "card_data": false,`, `endpoint "tokens": card_data must be true`},
		{"card_data absent", tokensLine, `"id": "tokens", "method": "POST", "path": "/v1/tokens",`, `endpoint "tokens": card_data must be true`},
		{"non-card endpoint (the old get_payment_intent shape)", `"endpoints": [`,
			`"endpoints": [{"id": "get_pi", "method": "GET", "path": "/v1/payment_intents/{id}", "headers": {"Authorization": "Bearer {{secret:secretKey}}"}},`,
			`endpoint "get_pi": card_data must be true`},
		{"no {{pan}} position, other card positions", `"card[number]": "{{pan}}",`, ``, `endpoint "tokens": no {{pan}} position`},
		{"no {{pan}} position, only credential positions", `"/transaction/creditCard/number": "{{pan}}",`, ``, `endpoint "submit_transaction": no {{pan}} position`},
		{"basic in body position", `"/merchant/apiKey": "{{secret:apiKey}}"`, `"/merchant/apiKey": "{{basic:apiKey}}"`, `position "/merchant/apiKey": {{basic:}}`},

		// Headers.
		{"header Host", `"X-API-Key": "{{secret:apiKey}}"`, `"Host": "{{secret:apiKey}}"`, `header "Host": vault-owned`},
		{"header Content-Type", `"X-API-Key": "{{secret:apiKey}}"`, `"content-type": "{{secret:apiKey}}"`, `header "Content-Type": vault-owned`},
		{"header Content-Length", `"X-API-Key": "{{secret:apiKey}}"`, `"Content-Length": "{{secret:apiKey}}"`, `header "Content-Length": vault-owned`},
		{"header User-Agent", `"X-API-Key": "{{secret:apiKey}}"`, `"User-Agent": "{{secret:apiKey}}"`, `header "User-Agent": vault-owned`},
		{"header Transfer-Encoding", `"X-API-Key": "{{secret:apiKey}}"`, `"Transfer-Encoding": "{{secret:apiKey}}"`, `header "Transfer-Encoding": vault-owned`},
		{"header platform-allowlisted", `"X-API-Key": "{{secret:apiKey}}"`, `"Idempotency-Key": "{{secret:apiKey}}"`, `header "Idempotency-Key": vault-owned`},
		{"header duplicate after canonicalization", `"X-API-Key": "{{secret:apiKey}}"`, `"X-API-Key": "{{secret:apiKey}}", "x-api-key": "{{secret:apiKey}}"`, "duplicate header"},
		{"header bad name", `"X-API-Key": "{{secret:apiKey}}"`, `"X API Key": "{{secret:apiKey}}"`, "invalid header name"},
		{"header card placeholder", `"X-API-Key": "{{secret:apiKey}}"`, `"X-API-Key": "{{pan}}"`, `header "X-Api-Key": card placeholder`},
		{"header card placeholder in template", `"X-API-Key": "{{secret:apiKey}}"`, `"X-API-Key": "Card {{exp:mm/yy}}"`, `header "X-Api-Key": card placeholder`},
		{"header no placeholder", `"X-API-Key": "{{secret:apiKey}}"`, `"X-API-Key": "static"`, `header "X-Api-Key": template`},
		{"header two placeholders", `"X-API-Key": "{{secret:apiKey}}"`, `"X-API-Key": "{{secret:apiKey}}{{secret:apiKey}}"`, `header "X-Api-Key": template`},
		{"header unknown placeholder", `"X-API-Key": "{{secret:apiKey}}"`, `"X-API-Key": "{{secret:api-key}}"`, `header "X-Api-Key": template`},
		{"header stray brace", `"X-API-Key": "{{secret:apiKey}}"`, `"X-API-Key": "{{secret:apiKey}}}"`, `header "X-Api-Key": template`},
		{"header control char", `"X-API-Key": "{{secret:apiKey}}"`, `"X-API-Key": "{{secret:apiKey}}\r\nX: y"`, `header "X-Api-Key": template`},

		// Signers.
		{"signature without signer", `"signer": "payu"`, `"signer": ""`, "{{signature}} without signer"},
		{"signature header without signer", `"X-API-Key": "{{secret:apiKey}}"`, `"X-API-Key": "{{secret:apiKey}}", "X-Signature": "{{signature}}"`, "{{signature}} without signer"},
		{"signer without signature", `"/transaction/order/signature": "{{signature}}",`, ``, "signer without {{signature}}"},
		{"unknown signer", `"signer": "payu"`, `"signer": "hmac"`, `unknown signer`},

		// Addresses.
		{"position and forbid", `"customer": [],`, `"customer": [], "payment_method_data[card][number]": [],`, `address "payment_method_data[card][number]" appears in more than one`},
		{"position and pin", `"pins": {"/merchantAccount"`, `"pins": {"/paymentMethod/cvc": {"literal": "1"}, "/merchantAccount"`, `address "/paymentMethod/cvc" appears in more than one`},
		{"pin and forbid", `"/shopperReference": []`, `"/shopperReference": [], "/merchantAccount": []`, `address "/merchantAccount" appears in more than one`},
		{"json pointer without slash", `"/paymentMethod/cvc"`, `"paymentMethod/cvc"`, `position "paymentMethod/cvc": invalid address`},
		{"json pointer bad escape", `"/paymentMethod/cvc"`, `"/payment~2Method/cvc"`, `position "/payment~2Method/cvc": invalid address`},
		{"json pointer trailing tilde", `"/paymentMethod/cvc"`, `"/paymentMethod/cvc~"`, `invalid address`},
		{"json pointer empty", `"/paymentMethod/cvc"`, `""`, `position "": invalid address`},
		{"json pointer empty token", `"/paymentMethod/cvc"`, `"/paymentMethod//cvc"`, `invalid address`},
		{"json pin bad pointer", `"/command": {`, `"command": {`, `pin "command": invalid address`},
		{"json forbid bad pointer", `"/shopperReference": []`, `"shopperReference": []`, `forbid "shopperReference": invalid address`},
		{"form forbid bad key", `"customer": []`, `"customer]": []`, `forbid "customer]": invalid address`},
		{"form position bad key", `"card[name]": "{{name}}"`, `"card.name": "{{name}}"`, `position "card.name": invalid address`},
		{"form position repeatable key", `"card[name]": "{{name}}"`, `"card[name][]": "{{name}}"`, `position "card[name][]": invalid address`},

		// Pins and forbid literals.
		{"pin both account and literal", `{"literal": "SUBMIT_TRANSACTION"}`, `{"literal": "SUBMIT_TRANSACTION", "account": "apiLogin"}`, `pin "/command": needs exactly one`},
		{"pin neither", `{"literal": "SUBMIT_TRANSACTION"}`, `{}`, `pin "/command": needs exactly one`},
		{"pin null literal", `{"literal": "SUBMIT_TRANSACTION"}`, `{"literal": null}`, `pin "/command": needs exactly one`},
		{"pin object literal", `{"literal": "SUBMIT_TRANSACTION"}`, `{"literal": {"a": 1}}`, `pin "/command": invalid literal`},
		{"pin placeholder literal", `{"literal": "SUBMIT_TRANSACTION"}`, `{"literal": "{{pan}}"}`, `pin "/command": invalid literal`},
		{"pin bad value name", `{"account": "merchantAccount"}`, `{"account": "merchant-account"}`, `pin "/merchantAccount": invalid account value name`},
		{"forbid not a list", `"/shopperReference": []`, `"/shopperReference": null`, `forbid "/shopperReference": must be a list`},
		{"forbid object literal", `"/shopperReference": []`, `"/shopperReference": [{}]`, `forbid "/shopperReference": invalid literal`},
		{"form forbid non-string literal", `"customer": []`, `"customer": [false]`, `forbid "customer": invalid literal`},

		// Accounts.
		{"account env", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "staging", "host": "upstream.test", "base_path": ""`, `account "stripe_t": env`},
		{"account env missing", stripeAcct, `"stripe_t": {"provider": "stripe", "host": "upstream.test", "base_path": ""`, `account "stripe_t": env`},
		{"account unknown provider", stripeAcct, `"stripe_t": {"provider": "strype", "env": "dev", "host": "upstream.test", "base_path": ""`, `account "stripe_t": unknown provider`},
		{"host uppercase", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "dev", "host": "Upstream.test", "base_path": ""`, `account "stripe_t": invalid host`},
		{"host scheme", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "dev", "host": "https://upstream.test", "base_path": ""`, `account "stripe_t": invalid host`},
		{"host path", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "dev", "host": "upstream.test/x", "base_path": ""`, `account "stripe_t": invalid host`},
		{"host userinfo", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "dev", "host": "a@upstream.test", "base_path": ""`, `account "stripe_t": invalid host`},
		{"host port too long", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "dev", "host": "upstream.test:123456", "base_path": ""`, `account "stripe_t": invalid host`},
		{"host port out of range", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "dev", "host": "upstream.test:65536", "base_path": ""`, `account "stripe_t": invalid host`},
		{"host empty label", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "dev", "host": "upstream..test", "base_path": ""`, `account "stripe_t": invalid host`},
		{"host empty", stripeAcct, `"stripe_t": {"provider": "stripe", "env": "dev", "host": "", "base_path": ""`, `account "stripe_t": invalid host`},
		{"base_path trailing slash", adyenAcct, `"adyen_br": {"provider": "adyen", "env": "dev", "host": "upstream.test", "base_path": "/checkout/"`, `account "adyen_br": invalid base_path`},
		{"base_path relative", adyenAcct, `"adyen_br": {"provider": "adyen", "env": "dev", "host": "upstream.test", "base_path": "checkout"`, `account "adyen_br": invalid base_path`},
		{"base_path slash", adyenAcct, `"adyen_br": {"provider": "adyen", "env": "dev", "host": "upstream.test", "base_path": "/"`, `account "adyen_br": invalid base_path`},
		{"base_path dot-dot", adyenAcct, `"adyen_br": {"provider": "adyen", "env": "dev", "host": "upstream.test", "base_path": "/a/.."`, `account "adyen_br": invalid base_path`},
		{"base_path wildcard", adyenAcct, `"adyen_br": {"provider": "adyen", "env": "dev", "host": "upstream.test", "base_path": "/{id}"`, `account "adyen_br": invalid base_path`},
		{"secret resource invalid", `"projects/pci-cde-dev/secrets/stripe-t-key"`, `"projects/pci-cde-dev/secrets/stripe-t-key/versions/1"`, `account "stripe_t": secret "secretKey": invalid Secret Manager resource`},
		{"secret resource not a resource", `"projects/pci-cde-dev/secrets/stripe-t-key"`, `"sk_test_123"`, `account "stripe_t": secret "secretKey": invalid Secret Manager resource`},
		{"secret name invalid", `{"secretKey": "projects/pci-cde-dev/secrets/stripe-t-key"}`, `{"secret-key": "projects/pci-cde-dev/secrets/stripe-t-key"}`, `account "stripe_t": invalid secret name`},
		{"value name invalid", `"merchantAccount": "AcmeBR_ECOM"`, `"merchant.account": "AcmeBR_ECOM"`, `account "adyen_br": invalid value name`},
		{"value empty", `"merchantAccount": "AcmeBR_ECOM"`, `"merchantAccount": ""`, `account "adyen_br": value "merchantAccount": invalid`},
		{"value placeholder", `"merchantAccount": "AcmeBR_ECOM"`, `"merchantAccount": "{{pan}}"`, `account "adyen_br": value "merchantAccount": invalid`},
		{"missing header secret", `{"secretKey": "projects/pci-cde-dev/secrets/stripe-t-key"}`, `{"secretKey2": "projects/pci-cde-dev/secrets/stripe-t-key"}`, `account "stripe_t": endpoint "payment_intents": missing secret "secretKey"`},
		{"missing basic secret", `"secretKey": "projects/pci-cde-dev/secrets/pagarme-br-key"`, `"key": "projects/pci-cde-dev/secrets/pagarme-br-key"`, `account "pagarme_br": endpoint "orders": missing secret "secretKey"`},
		{"missing position secret", `"apiKey": "projects/pci-cde-dev/secrets/payu-co-key"`, `"key": "projects/pci-cde-dev/secrets/payu-co-key"`, `account "payu_co": endpoint "submit_transaction": missing secret "apiKey"`},
		{"missing pin value", `"merchantAccount": "AcmeBR_ECOM"`, `"merchant": "AcmeBR_ECOM"`, `account "adyen_br": endpoint "payments": missing value "merchantAccount"`},
		{"missing pin value in prod account", `"merchantAccount": "AcmeBR_LIVE"`, `"merchant": "AcmeBR_LIVE"`, `account "adyen_br_live": endpoint "payments": missing value "merchantAccount"`},
		{"payu missing merchantId", payuVals, `"values": {"apiLogin": "pRRXKOl8ikMmt9u", "accountId": "512321", "hash": "sha256"}`, `account "payu_co": payu needs`},
		{"payu missing hash", payuVals, `"values": {"apiLogin": "pRRXKOl8ikMmt9u", "accountId": "512321", "merchantId": "508029"}`, `account "payu_co": payu needs`},
		{"payu bad hash", payuVals, `"values": {"apiLogin": "pRRXKOl8ikMmt9u", "accountId": "512321", "merchantId": "508029", "hash": "crc32"}`, `account "payu_co": payu needs`},
		{"payu hash case", payuVals, `"values": {"apiLogin": "pRRXKOl8ikMmt9u", "accountId": "512321", "merchantId": "508029", "hash": "SHA256"}`, `account "payu_co": payu needs`},
		// Dev secret variables (VAULT_DEV_SECRET_<ACCOUNT>_<NAME>, uppercased) must be unique across
		// every account of every environment.
		{"dev variable: secret names differ only in case", `"secrets": {"secretKey": "projects/pci-cde-dev/secrets/stripe-t-key"}`,
			`"secrets": {"secretKey": "projects/pci-cde-dev/secrets/stripe-t-key", "SECRETKEY": "projects/pci-cde-dev/secrets/stripe-t-key2"}`,
			`account "stripe_t" secret "SECRETKEY" and account "stripe_t" secret "secretKey" share dev variable VAULT_DEV_SECRET_STRIPE_T_SECRETKEY`},
		{"dev variable: account/secret split", `"accounts": {`,
			`"accounts": {"stripe": {"provider": "stripe", "env": "dev", "host": "upstream.test", "secrets": {"secretKey": "projects/x/secrets/a", "t_secretKey": "projects/x/secrets/b"}},`,
			`account "stripe" secret "t_secretKey" and account "stripe_t" secret "secretKey" share dev variable VAULT_DEV_SECRET_STRIPE_T_SECRETKEY`},
		{"dev variable: collision with a prod account", `"secrets": {"apiKey": "projects/pci-cde-dev/secrets/adyen-br-key"}`,
			`"secrets": {"apiKey": "projects/pci-cde-dev/secrets/adyen-br-key", "live_apiKey": "projects/pci-cde-dev/secrets/adyen-br-key2"}`,
			`account "adyen_br" secret "live_apiKey" and account "adyen_br_live" secret "apiKey" share dev variable VAULT_DEV_SECRET_ADYEN_BR_LIVE_APIKEY`},
	}
}

// TestParseCatalogRejects applies one mutation per validation rule to testCatalogJSON. Each must be
// rejected with an error naming the rule (want), and no error may name a secret resource.
func TestParseCatalogRejects(t *testing.T) {
	if _, err := parseCatalog([]byte(testCatalogJSON), "dev"); err != nil {
		t.Fatalf("fixture rejected: %v", err)
	}
	for _, c := range catalogMutations() {
		data, ok := c.apply()
		if !ok {
			t.Errorf("%s: mutation target not in fixture", c.name)
			continue
		}
		_, err := parseCatalog([]byte(data), "dev")
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not contain %q", c.name, err, c.want)
		}
		if strings.Contains(err.Error(), "projects/") || strings.Contains(err.Error(), "sk_test") {
			t.Errorf("%s: error names a secret resource", c.name)
		}
	}

	// The environment argument itself.
	for _, env := range []string{"", "staging", "Dev", "PROD"} {
		if _, err := parseCatalog([]byte(testCatalogJSON), env); err == nil {
			t.Errorf("env %q accepted", env)
		}
	}
}

// embeddedFixtures holds at least one example request per endpoint of the embedded catalog,
// keyed "provider/endpoint": each must pass checkProxy for the named dev account and match
// that endpoint. TestEmbeddedCatalog fails for an endpoint without one, so every catalog change
// adds its fixture here.
var embeddedFixtures = map[string]*proxyEnvelope{
	"stripe/tokens": newEnvelope("stripe_test", "POST", "/v1/tokens",
		map[string]string{"Idempotency-Key": "ord-1", "Authorization": "Bearer {{secret:secretKey}}"}, embeddedTokensBody),
}

func TestEmbeddedCatalog(t *testing.T) {
	for _, env := range []string{"dev", "prod"} {
		if _, err := parseCatalog(catalogJSON, env); err != nil {
			t.Fatalf("embedded catalog (%s): %v", env, err)
		}
	}
	c, _ := parseCatalog(catalogJSON, "dev")
	// Stripe ships POST /v1/tokens only: a single-use tok_ hand-off. POST /v1/payment_methods
	// creates a reusable, attachable PaymentMethod, which is storage, so it is not in the catalog.
	// customer (Connect: a token cloned from a customer's saved card) must be absent.
	tk := catEndpointByID(t, c, "stripe", "tokens")
	if c.providers["stripe"].format != "form" || len(c.providers["stripe"].endpoints) != 1 || !tk.cardData ||
		tk.method != "POST" || !slices.Equal(tk.path, []string{"v1", "tokens"}) || tk.positions["card[number]"] != (placeholder{kind: "pan"}) {
		t.Error("embedded stripe provider shape")
	}
	if f, ok := tk.forbid["customer"]; !ok || f == nil || len(f) != 0 || len(tk.forbid) != 1 {
		t.Error("embedded stripe tokens must forbid exactly customer (must be absent)")
	}
	// Every embedded endpoint carries card data and lists {{pan}} (parseCatEndpoint enforces both).
	for _, prov := range slices.Sorted(maps.Keys(c.providers)) {
		for _, ep := range c.providers[prov].endpoints {
			hasPAN := false
			for _, ph := range ep.positions {
				hasPAN = hasPAN || ph.kind == "pan"
			}
			if !ep.cardData || !hasPAN {
				t.Errorf("embedded endpoint %s/%s is not a card endpoint with a {{pan}} position", prov, ep.id)
			}
		}
	}
	if a := c.accounts["stripe_test"]; a == nil || a.host != "api.stripe.com" || a.secretNames["secretKey"] != "projects/pci-cde-dev/secrets/stripe-test-secret-key" {
		t.Error("embedded stripe_test account")
	}

	// Every endpoint has a fixture, every fixture passes and matches its endpoint, and (form) a
	// fixture with a forbidden field added is refused.
	for _, prov := range slices.Sorted(maps.Keys(c.providers)) {
		for _, ep := range c.providers[prov].endpoints {
			if embeddedFixtures[prov+"/"+ep.id] == nil {
				t.Errorf("embedded endpoint %s/%s has no fixture in embeddedFixtures", prov, ep.id)
			}
		}
	}
	for _, key := range slices.Sorted(maps.Keys(embeddedFixtures)) {
		e := embeddedFixtures[key]
		prov, id, _ := strings.Cut(key, "/")
		plan, perr := c.checkProxy(e)
		if perr != nil {
			t.Errorf("fixture %s rejected: %s (%s)", key, perr.msg, perr.reason)
			continue
		}
		if plan.prov.name != prov || plan.ep.id != id {
			t.Errorf("fixture %s matched %s/%s", key, plan.prov.name, plan.ep.id)
		}
		for _, addr := range slices.Sorted(maps.Keys(plan.ep.forbid)) {
			if plan.prov.format != "form" {
				break // appending a field is only this simple in a form body
			}
			bad := *e
			bad.Request.Body = e.Request.Body + "&" + addr + "=x"
			if _, perr := c.checkProxy(&bad); perr == nil || perr.msg != msgForbiddenField {
				t.Errorf("fixture %s with %s set was not refused as a forbidden field", key, addr)
			}
		}
	}
}

// TestEmbeddedCatalogProdAccounts pins the prod account set of the embedded catalog. It is empty
// today, so a prod boot is refused ("catalog has no accounts for env=prod",
// TestBootRefusesEmptyAccountSet). When the first reviewed prod account lands, this test changes
// to require at least one.
func TestEmbeddedCatalogProdAccounts(t *testing.T) {
	c, err := parseCatalog(catalogJSON, "prod")
	if err != nil {
		t.Fatalf("embedded catalog (prod): %v", err)
	}
	if n := len(c.accounts); n != 0 {
		t.Errorf("embedded catalog has %d prod accounts; update this test to require at least one", n)
	}
	t.Log("the embedded catalog has no prod account, so a prod boot is refused: a reviewed prod account must be added before the first prod deploy")
}

// egress-hosts.<env>.txt are the files the infra repo's firewall check diffs against:
// each must list exactly its environment's catalog account hosts, without ports.
func TestEgressHostsMatchCatalog(t *testing.T) {
	for _, env := range []string{"dev", "prod"} {
		raw, err := os.ReadFile("egress-hosts." + env + ".txt")
		if err != nil {
			t.Fatalf("cannot read egress-hosts.%s.txt", env)
		}
		var file []string
		for _, line := range strings.Split(string(raw), "\n") {
			if h := strings.TrimSpace(line); h != "" {
				file = append(file, h)
			}
		}
		slices.Sort(file)
		c, err := parseCatalog(catalogJSON, env)
		if err != nil {
			t.Fatalf("embedded catalog (%s): %v", env, err)
		}
		hosts := map[string]bool{}
		for _, a := range c.accounts {
			h, _, _ := strings.Cut(a.host, ":")
			hosts[h] = true
		}
		if want := slices.Sorted(maps.Keys(hosts)); !slices.Equal(file, want) {
			t.Errorf("egress-hosts.%s.txt %v != catalog hosts %v", env, file, want)
		}
	}
}
