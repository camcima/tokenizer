package main

import (
	"errors"
	"maps"
	"net/http"
	"net/textproto"
	"regexp"
	"slices"
	"strings"
)

// ---------------------------------------------------------------------------
// /proxy request policy
// ---------------------------------------------------------------------------

// proxyEnvelope is the /proxy request body: the platform names one of our accounts, a card
// token, and the provider request it wants sent, with placeholders where the vault fills in card
// data, secrets and signatures. It is built by a possibly-compromised platform; checkProxy decides
// whether it may proceed.
type proxyEnvelope struct {
	Account string `json:"account"`
	Token   string `json:"token"`
	Request struct {
		Method  string            `json:"method"`
		Path    string            `json:"path"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	} `json:"request"`
}

// proxyPlan is an envelope that passed checkProxy, resolved against the catalog. renderRequest
// builds the outgoing request from it; body is never substituted in place.
type proxyPlan struct {
	acct              *catAccount
	prov              *catProvider
	ep                *catEndpoint
	path              string      // validated path incl. "?query" if any
	headers           http.Header // platform headers that passed the global allowlist
	body              []byte
	occs              []occurrence
	usesCVV, usesName bool
	sent              []byte // the substituted body, set by renderRequest; the caller zeroes it after the response is read
}

// policyError is a checkProxy rejection. msg is a fixed msg* constant and reason a fixed alert
// reason; neither ever holds request-derived text.
type policyError struct {
	status      int
	msg, reason string // reason: "" for envelope errors, else the ALERT proxy_policy reason
	endpoint    string // id of the matched endpoint (catalog text), "" if rejected before matching
}

// platformHeaders is the global allowlist of headers the platform may send, besides the
// matched endpoint's header templates.
var platformHeaders = map[string]bool{"Accept": true, "Idempotency-Key": true, "X-Idempotency-Key": true}

// payuSignerInputs are the body fields the payu signer reads, as JSON Pointers.
var payuSignerInputs = []string{
	"/transaction/order/referenceCode",
	"/transaction/order/additionalValues/TX_VALUE/value",
	"/transaction/order/additionalValues/TX_VALUE/currency",
}

// proxyWildcardRe is what a "{name}" rule segment matches in a request path.
var proxyWildcardRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// checkProxy applies the catalog's rules to e. Checks run in a fixed order and the first failure
// wins: token, account, endpoint (method, path, query), headers, body parse, placeholder positions
// (including the required {{pan}}), pins, forbid, signer inputs. It touches no network and no
// database, and handleProxy runs it before any database call. Every rejection is 400.
// A GET or HEAD endpoint must have an empty body (checked right after the headers).
//
// Every request must contain a {{pan}} occurrence, or it is msgPlaceholder (reason
// "placeholder", so ALERT proxy_policy fires). The vault's credential is only for card-carrying calls;
// a request without the card, such as POST /v1/tokens with pii[id_number], would borrow it
// for a call the platform makes with its own keys. parseCatEndpoint requires a {{pan}} position
// on every endpoint, so a request that carries the card always can. There is no empty-body
// shortcut: an empty json body is msgBadBody, and an empty form body (zero fields) lacks {{pan}}.
// A GET or HEAD endpoint still parses, and its request must have no body; with the
// {{pan}} rule above, no request to one can pass. The body rule is kept so that the two stay
// independent if either changes.
// A position address present in the body must hold exactly its placeholder; any
// literal there (an object, a number, the platform's own API key at /merchant/apiKey, a raw PAN) is
// msgPlaceholder: credential fields only accept vault placeholders. Positions other than the
// {{pan}} one stay optional: a body may omit such a field entirely.
// A body field whose address differs from a position, pin or forbid address only in
// case ("/MerchantAccount" next to or instead of "/merchantAccount") fails that check (placeholder,
// pin or forbidden_field). Some provider parsers bind keys case-insensitively (Go's encoding/json,
// Jackson with ACCEPT_CASE_INSENSITIVE_PROPERTIES), and such an alias could supply a credential or
// override or bypass the checked field.
// Card placeholders are counted by kind, so "{{exp_year}}" and "{{exp_year:yy}}"
// together count as one card placeholder twice and are rejected.
func (c *catalog) checkProxy(e *proxyEnvelope) (*proxyPlan, *policyError) {
	if !tokenRe.MatchString(e.Token) {
		return nil, &policyError{status: http.StatusBadRequest, msg: msgInvalidToken}
	}
	acct := c.accounts[e.Account]
	if acct == nil {
		return nil, &policyError{status: http.StatusBadRequest, msg: msgUnknownAccount}
	}
	prov := c.providers[acct.provider]
	ep := matchEndpoint(prov, e.Request.Method, e.Request.Path)
	if ep == nil {
		return nil, &policyError{status: http.StatusBadRequest, msg: msgEndpointNotAllowed, reason: "endpoint"}
	}
	fail := func(msg, reason string) (*proxyPlan, *policyError) {
		return nil, &policyError{status: http.StatusBadRequest, msg: msg, reason: reason, endpoint: ep.id}
	}

	headers, ok := checkProxyHeaders(ep, e.Request.Headers)
	if !ok {
		return fail(msgHeaderNotAllowed, "header")
	}

	plan := &proxyPlan{acct: acct, prov: prov, ep: ep, path: e.Request.Path, headers: headers, body: []byte(e.Request.Body)}
	body := plan.body
	// A GET or HEAD request carries no body: a body there has no
	// defined meaning to the provider, so it is refused rather than sent or dropped.
	if (ep.method == http.MethodGet || ep.method == http.MethodHead) && len(body) != 0 {
		return fail(msgBadBody, "body")
	}

	occs, err := scanBody(prov.format, body)
	if errors.Is(err, errPlaceholder) {
		return fail(msgPlaceholder, "placeholder")
	}
	if err != nil {
		return fail(msgBadBody, "body")
	}
	addrs, err := bodyAddrs(prov.format, body)
	if err != nil {
		return fail(msgBadBody, "body") // unreachable: scanBody accepted the body
	}
	caseVariant := func(addr string) bool {
		for _, a := range addrs {
			if a != addr && strings.EqualFold(a, addr) {
				return true
			}
		}
		return false
	}

	cardKinds := map[string]bool{}
	occAt := map[string]bool{}
	for _, o := range occs {
		if want, ok := ep.positions[o.addr]; !ok || want != o.ph {
			return fail(msgPlaceholder, "placeholder")
		}
		if o.ph.isCard() {
			if cardKinds[o.ph.kind] {
				return fail(msgPlaceholder, "placeholder")
			}
			cardKinds[o.ph.kind] = true
		}
		occAt[o.addr] = true
	}
	for _, a := range addrs {
		if _, isPos := ep.positions[a]; isPos && !occAt[a] {
			return fail(msgPlaceholder, "placeholder")
		}
	}
	for _, addr := range slices.Sorted(maps.Keys(ep.positions)) {
		if caseVariant(addr) {
			return fail(msgPlaceholder, "placeholder")
		}
	}
	if !cardKinds["pan"] {
		return fail(msgPlaceholder, "placeholder") // no card in the request: see the {{pan}} rule above
	}
	plan.occs = occs
	plan.usesCVV, plan.usesName = cardKinds["cvv"], cardKinds["name"]

	for _, addr := range slices.Sorted(maps.Keys(ep.pins)) {
		pin := ep.pins[addr]
		var want fieldValue
		if pin.literal != nil {
			want = *pin.literal
		} else {
			// Account values compare as strings only: a JSON number never matches.
			v := acct.values[pin.account]
			if v == "" {
				return fail(msgPinMismatch, "pin") // unreachable: parseCatAccount requires the value
			}
			want = fieldValue{kind: "string", text: v}
		}
		got, found, err := readField(prov.format, body, addr)
		if err != nil || !found || got != want || caseVariant(addr) {
			return fail(msgPinMismatch, "pin")
		}
	}

	// In a form body, a forbidden field "addr" also forbids every key starting with
	// addr+"[" under any case ("customer[", "customer[]", "customer[x]", "Customer[x]"): many form
	// parsers (Stripe, Rack, PHP) nest those under the same field, so they would set it while avoiding
	// the exact key. (validFormKey already refuses "customer[" as malformed; ">=" covers it here too.)
	for _, addr := range slices.Sorted(maps.Keys(ep.forbid)) {
		got, found, err := readField(prov.format, body, addr)
		if err != nil || caseVariant(addr) || (found && !slices.Contains(ep.forbid[addr], got)) {
			return fail(msgForbiddenField, "forbidden_field")
		}
		if prov.format == "form" {
			prefix := addr + "["
			for _, a := range addrs {
				if len(a) >= len(prefix) && strings.EqualFold(a[:len(prefix)], prefix) {
					return fail(msgForbiddenField, "forbidden_field")
				}
			}
		}
	}

	// A signer input holding "{{" is a placeholder occurrence (scanBody lets no other "{{" through),
	// and signers never take placeholder values. A case-variant alias of an input could make the
	// provider sign or read a different value than the vault signed, so it is refused too.
	// A signer name this switch does not know fails closed (parseCatEndpoint already
	// refuses one; this keeps the two in step if a signer is ever added to one and not the other).
	switch ep.signer {
	case "":
	case "payu":
		for _, addr := range payuSignerInputs {
			got, found, err := readField(prov.format, body, addr)
			if err != nil || !found || (got.kind != "string" && got.kind != "number") ||
				strings.Contains(got.text, "{{") || caseVariant(addr) {
				return fail(msgPlaceholder, "placeholder")
			}
		}
	default:
		return fail(msgEndpointNotAllowed, "endpoint")
	}
	return plan, nil
}

// matchEndpoint returns the one endpoint of prov whose method and path match, with the query (if
// any) allowed by that endpoint, or nil. The path must start with "/" and contain no "%", "//" or
// "..". Literal segments compare exactly; a "{name}" segment matches proxyWildcardRe.
// A "?" with an empty query is rejected, as on the vault's own listeners.
func matchEndpoint(prov *catProvider, method, reqPath string) *catEndpoint {
	p, query, hasQuery := strings.Cut(reqPath, "?")
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "%") || strings.Contains(p, "//") || strings.Contains(p, "..") {
		return nil
	}
	segs := strings.Split(p[1:], "/")
	var match *catEndpoint
	n := 0
	for _, ep := range prov.endpoints {
		if ep.method == method && proxyPathMatch(ep.path, segs) {
			match = ep
			n++
		}
	}
	if n != 1 {
		return nil // parseCatProvider rejects overlapping rules, so n is 0 or 1
	}
	if hasQuery && !validProxyQuery(match, query) {
		return nil
	}
	return match
}

// proxyPathMatch reports whether request path segments segs match the rule segments rule.
func proxyPathMatch(rule, segs []string) bool {
	if len(rule) != len(segs) {
		return false
	}
	for i := range rule {
		if catIsWildcard(rule[i]) {
			if !proxyWildcardRe.MatchString(segs[i]) {
				return false
			}
		} else if rule[i] != segs[i] {
			return false
		}
	}
	return true
}

// validProxyQuery reports whether the raw query q is allowed by ep: parsed like a strict form body
// (formFields), every key listed in ep.query, and no decoded value containing "{{".
// Beyond that, the raw query may only hold [A-Za-z0-9._~%+=&[]-] (anything
// else percent-encoded), so no '#', '?', ';' or space reaches the URL builder, and a decoded value
// may not hold control characters (U+0000-U+001F, U+007F).
func validProxyQuery(ep *catEndpoint, q string) bool {
	if q == "" {
		return false
	}
	for i := 0; i < len(q); i++ {
		b := q[i]
		if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || strings.IndexByte("._~%+=&[]-", b) >= 0) {
			return false
		}
	}
	fields, err := formFields([]byte(q))
	if err != nil || len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		if !ep.query[f.key] || strings.Contains(f.value, "{{") ||
			strings.ContainsFunc(f.value, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return false
		}
	}
	return true
}

// checkProxyHeaders checks the platform's headers against ep and the global allowlist.
// Names are canonicalized and must be unique after that. A header named by one of ep's templates
// must equal the template exactly (placeholders unrendered) and is dropped, since the vault always
// renders and sets every template header itself. Any other header must be allowlisted with a value
// of 1-1024 bytes of printable ASCII without "{{"; those are returned.
func checkProxyHeaders(ep *catEndpoint, in map[string]string) (http.Header, bool) {
	out := http.Header{}
	seen := map[string]bool{}
	for _, k := range slices.Sorted(maps.Keys(in)) {
		v := in[k]
		name := textproto.CanonicalMIMEHeaderKey(k)
		if seen[name] {
			return nil, false
		}
		seen[name] = true
		if tmpl, ok := ep.headers[name]; ok {
			if v != tmpl {
				return nil, false
			}
			continue
		}
		if !platformHeaders[name] || len(v) < 1 || len(v) > 1024 || strings.Contains(v, "{{") ||
			strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
			return nil, false
		}
		out[name] = []string{v}
	}
	return out, true
}

// bodyAddrs returns the address of every field of a body: every value's JSON Pointer (json) or
// every key (form). Errors are those of jsonWalk and formFields.
func bodyAddrs(format string, body []byte) ([]string, error) {
	var addrs []string
	switch format {
	case "json":
		nodes, err := jsonWalk(body)
		if err != nil {
			return nil, err
		}
		for _, n := range nodes {
			if n.kind != "key" {
				addrs = append(addrs, n.ptr)
			}
		}
	case "form":
		fields, err := formFields(body)
		if err != nil {
			return nil, err
		}
		for _, f := range fields {
			addrs = append(addrs, f.key)
		}
	default:
		return nil, errBody
	}
	return addrs, nil
}
