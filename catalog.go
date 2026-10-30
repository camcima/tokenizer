package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// Provider catalog: catalog.json
// ---------------------------------------------------------------------------

// catalogJSON is the reviewed provider catalog, compiled into the binary. It is never read
// from disk at runtime, so the image digest attests the exact catalog. Adding a provider, endpoint
// or account is a PR that also updates egress-hosts.<env>.txt and the egress firewall rule;
// TestEgressHostsMatchCatalog keeps the files and the catalog in step.
//
//go:embed catalog.json
var catalogJSON []byte

// catalog is the parsed catalog.json: every provider, and the accounts of one environment.
type catalog struct {
	providers map[string]*catProvider
	accounts  map[string]*catAccount // only accounts whose env == the env passed to parseCatalog
}

type catProvider struct {
	name, format string
	endpoints    []*catEndpoint
}

// catEndpoint is one allowed provider call.
type catEndpoint struct {
	id, method string
	path       []string        // segments; "{name}" = wildcard [A-Za-z0-9_-]{1,128}
	query      map[string]bool // allowed query keys (usually empty)
	cardData   bool
	headers    map[string]string       // canonical header name → exact value template
	positions  map[string]placeholder  // address → the one placeholder allowed there
	pins       map[string]catPin       // address → required value
	forbid     map[string][]fieldValue // address → allowed literals; empty slice = must be absent
	signer     string                  // "" or "payu"
}

// catPin is a pinned body field: it must equal the named account value, or a fixed literal.
type catPin struct {
	account string      // name of an account value, or
	literal *fieldValue // a fixed literal
}

// catAccount is one of our provider accounts.
type catAccount struct {
	name, provider, env, host, basePath string
	secretNames                         map[string]string // name → Secret Manager resource
	values                              map[string]string
	secrets                             map[string]string // filled at boot by loadAccountSecrets
}

// Raw decode targets. Their JSON names are the catalog.json schema:
//
//	{"providers": {NAME: {"format": "json"|"form", "endpoints": [{"id", "method", "path", "query": [KEY],
//	   "card_data": true, "headers": {NAME: TEMPLATE}, "positions": {ADDR: PLACEHOLDER},
//	   "pins": {ADDR: {"account": VALUE_NAME} | {"literal": SCALAR}}, "forbid": {ADDR: [SCALAR]},
//	   "signer": "payu"}]}},
//	 "accounts": {NAME: {"provider", "env": "dev"|"prod", "host", "base_path",
//	   "secrets": {NAME: RESOURCE}, "values": {NAME: VALUE}}}}
type rawCatalog struct {
	Providers map[string]rawProvider `json:"providers"`
	Accounts  map[string]rawAccount  `json:"accounts"`
}

type rawProvider struct {
	Format    string        `json:"format"`
	Endpoints []rawEndpoint `json:"endpoints"`
}

type rawEndpoint struct {
	ID        string                     `json:"id"`
	Method    string                     `json:"method"`
	Path      string                     `json:"path"`
	Query     []string                   `json:"query"`
	CardData  bool                       `json:"card_data"`
	Headers   map[string]string          `json:"headers"`
	Positions map[string]string          `json:"positions"`
	Pins      map[string]rawPin          `json:"pins"`
	Forbid    map[string]json.RawMessage `json:"forbid"`
	Signer    string                     `json:"signer"`
}

type rawPin struct {
	Account *string         `json:"account"`
	Literal json.RawMessage `json:"literal"`
}

type rawAccount struct {
	Provider string            `json:"provider"`
	Env      string            `json:"env"`
	Host     string            `json:"host"`
	BasePath string            `json:"base_path"`
	Secrets  map[string]string `json:"secrets"`
	Values   map[string]string `json:"values"`
}

// The exact key sets of each catalog.json object that decodes into a struct.
var (
	catRootKeys     = map[string]bool{"providers": true, "accounts": true}
	catProviderKeys = map[string]bool{"format": true, "endpoints": true}
	catEndpointKeys = map[string]bool{"id": true, "method": true, "path": true, "query": true, "card_data": true,
		"headers": true, "positions": true, "pins": true, "forbid": true, "signer": true}
	catPinKeys     = map[string]bool{"account": true, "literal": true}
	catAccountKeys = map[string]bool{"provider": true, "env": true, "host": true, "base_path": true, "secrets": true, "values": true}
)

// Provider names, endpoint ids and account names are [a-z0-9_]{1,64}. They appear in
// logs and alerts (account=<a> endpoint=<id>), so a restricted alphabet rules out log injection.
var catNameRe = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// catHostRe is the account host shape: a lowercase DNS name or IPv4 address, optional port.
var catHostRe = regexp.MustCompile(`^[a-z0-9.-]+(:[0-9]{1,5})?$`)

// catSegmentRe is a literal path segment: RFC 3986 unreserved characters only.
// No percent-escapes, sub-delims or ':' in catalog paths, so a rule path has one
// spelling and cannot be normalized into another by the provider.
var catSegmentRe = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

// Catalog header templates may not name the headers the vault sets (Host,
// Content-Type, Content-Length, User-Agent), transfer and hop-by-hop headers, or the platform
// allowlist (Accept, Idempotency-Key, X-Idempotency-Key): a template there would compete with the
// vault's own value or with the platform's.
var catReservedHeaders = map[string]bool{
	"Host": true, "Content-Type": true, "Content-Length": true, "User-Agent": true, "Transfer-Encoding": true,
	"Connection": true, "Keep-Alive": true, "Proxy-Authorization": true, "Proxy-Connection": true, "Te": true,
	"Trailer": true, "Upgrade": true, "Content-Encoding": true,
	"Accept": true, "Idempotency-Key": true, "X-Idempotency-Key": true,
}

var catHeaderNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)

// parseCatalog parses and validates catalog.json. Every provider and every account in every
// environment is validated; only the accounts of env ("dev" or "prod") are kept. Errors name the
// provider, endpoint, account or address at fault, never a secret resource or account value.
// The comments on the helpers below explain where a rule is stricter than the bare format.
func parseCatalog(data []byte, env string) (*catalog, error) {
	if env != "dev" && env != "prod" {
		return nil, errors.New("catalog: environment must be dev or prod")
	}
	// jsonWalk is jsonStrict's parser: one value, no duplicate keys at any depth, no trailing data,
	// valid UTF-8. Its nodes also give every key's position for the exact-key check below.
	nodes, err := jsonWalk(data)
	if err != nil || nodes[0].kind != "object" {
		return nil, errors.New("catalog: not strict JSON (one object, no duplicate keys or trailing data, valid UTF-8)")
	}
	if err := catExactKeys(nodes); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var raw rawCatalog
	if err := dec.Decode(&raw); err != nil {
		// Never the decoder's message: an UnmarshalTypeError's Value can hold the offending number.
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) {
			return nil, fmt.Errorf("catalog: wrong type at %q", te.Field)
		}
		return nil, errors.New("catalog: invalid structure")
	}

	c := &catalog{providers: map[string]*catProvider{}, accounts: map[string]*catAccount{}}
	for _, name := range slices.Sorted(maps.Keys(raw.Providers)) {
		p, err := parseCatProvider(name, raw.Providers[name])
		if err != nil {
			return nil, err
		}
		c.providers[name] = p
	}
	// Dev secret variables (devSecretVar) must be unique across every account of
	// every environment, not only the loaded one: "a_b"/"c" and "a"/"b_c", or secrets "apiKey" and
	// "APIKEY", would otherwise share one variable, and the same image boots in both environments.
	devVar := map[string]string{} // dev variable → "account A secret S" that claimed it
	for _, name := range slices.Sorted(maps.Keys(raw.Accounts)) {
		a, err := parseCatAccount(name, raw.Accounts[name], c.providers)
		if err != nil {
			return nil, err
		}
		for _, s := range slices.Sorted(maps.Keys(a.secretNames)) {
			v, this := devSecretVar(name, s), fmt.Sprintf("account %q secret %q", name, s)
			if prev, ok := devVar[v]; ok {
				return nil, fmt.Errorf("catalog: %s and %s share dev variable %s", prev, this, v)
			}
			devVar[v] = this
		}
		if a.env == env {
			c.accounts[name] = a
		}
	}
	return c, nil
}

// catExactKeys checks every key of an object that decodes into a struct against that struct's
// exact key set. The struct objects sit at fixed depths: the root, /providers/P,
// /providers/P/endpoints/I, /providers/P/endpoints/I/pins/A and /accounts/A.
// encoding/json matches struct keys case-insensitively, so DisallowUnknownFields
// alone accepts "Format" for "format", and {"format":"json","Format":"form"} passes the
// duplicate-key check yet decodes as "form". Keys must be spelled exactly.
func catExactKeys(nodes []jsonNode) error {
	for _, n := range nodes {
		if n.kind != "key" {
			continue
		}
		// n.ptr is the parent's pointer plus one escaped token; tokens contain no raw "/".
		parentPtr := n.ptr[:strings.LastIndex(n.ptr, "/")]
		parent := strings.Split(parentPtr, "/")[1:]
		var allowed map[string]bool
		switch {
		case parentPtr == "":
			allowed = catRootKeys
		case len(parent) == 2 && parent[0] == "providers":
			allowed = catProviderKeys
		case len(parent) == 4 && parent[0] == "providers" && parent[2] == "endpoints":
			allowed = catEndpointKeys
		case len(parent) == 6 && parent[0] == "providers" && parent[2] == "endpoints" && parent[4] == "pins":
			allowed = catPinKeys
		case len(parent) == 2 && parent[0] == "accounts":
			allowed = catAccountKeys
		default:
			continue // a map key (names, addresses, headers) or inside a literal
		}
		if !allowed[n.text] {
			return fmt.Errorf("catalog: unknown key %q in %q", n.text, parentPtr)
		}
	}
	return nil
}

// parseCatProvider validates one provider and its endpoints.
// A provider must have at least one endpoint, and no two of its endpoints may share
// a method and overlapping paths (equal segment by segment, a wildcard matching anything), so a
// request path matches at most one rule.
func parseCatProvider(name string, rp rawProvider) (*catProvider, error) {
	if !catNameRe.MatchString(name) {
		return nil, fmt.Errorf("catalog: provider %q: invalid name", name)
	}
	if rp.Format != "json" && rp.Format != "form" {
		return nil, fmt.Errorf("catalog: provider %q: format must be json or form", name)
	}
	if len(rp.Endpoints) == 0 {
		return nil, fmt.Errorf("catalog: provider %q: no endpoints", name)
	}
	p := &catProvider{name: name, format: rp.Format}
	for i, re := range rp.Endpoints {
		e, err := parseCatEndpoint(p.format, i, re)
		if err != nil {
			return nil, fmt.Errorf("catalog: provider %q: %w", name, err)
		}
		for _, o := range p.endpoints {
			if o.id == e.id {
				return nil, fmt.Errorf("catalog: provider %q: endpoint %q: duplicate id", name, e.id)
			}
			if o.method == e.method && catPathsOverlap(o.path, e.path) {
				return nil, fmt.Errorf("catalog: provider %q: endpoints %q and %q overlap", name, o.id, e.id)
			}
		}
		p.endpoints = append(p.endpoints, e)
	}
	return p, nil
}

// parseCatEndpoint validates one endpoint rule of a provider with body format format.
// Additional rules: (1) {{basic:}} is header-only, (2) the payu signer needs a json
// provider (it reads body fields by JSON Pointer), (3) the whole-document address "" and empty JSON
// Pointer tokens are rejected, and (4) form positions and pins may not use a repeatable "[]" key (it
// names no single value).
// Every endpoint must have "card_data": true and list a {{pan}} position. The account credential
// is only for card-carrying calls; calls without card data (payments with a provider token,
// refunds, queries) are the platform's to make, with its own keys. A non-card endpoint would let
// the platform borrow the vault's credential for a call the vault has no reason to make,
// so it is refused here, and checkProxy refuses a request without a {{pan}} occurrence.
func parseCatEndpoint(format string, i int, re rawEndpoint) (*catEndpoint, error) {
	if !catNameRe.MatchString(re.ID) {
		return nil, fmt.Errorf("endpoint #%d: invalid id", i)
	}
	id := re.ID
	if !re.CardData {
		return nil, fmt.Errorf("endpoint %q: card_data must be true (non-card calls are made by the platform)", id)
	}
	switch re.Method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
	default:
		return nil, fmt.Errorf("endpoint %q: method %q not allowed", id, re.Method)
	}
	path, ok := parseCatPath(re.Path, true)
	if !ok {
		return nil, fmt.Errorf("endpoint %q: invalid path", id)
	}
	e := &catEndpoint{id: id, method: re.Method, path: path, cardData: re.CardData, query: map[string]bool{},
		headers: map[string]string{}, positions: map[string]placeholder{}, pins: map[string]catPin{},
		forbid: map[string][]fieldValue{}, signer: re.Signer}

	for _, k := range re.Query {
		if !validFormKey(k) || e.query[k] {
			return nil, fmt.Errorf("endpoint %q: query key %q invalid or repeated", id, k)
		}
		e.query[k] = true
	}

	usesSignature := false
	for _, k := range slices.Sorted(maps.Keys(re.Headers)) {
		if !catHeaderNameRe.MatchString(k) {
			return nil, fmt.Errorf("endpoint %q: invalid header name %q", id, k)
		}
		name := http.CanonicalHeaderKey(k)
		if catReservedHeaders[name] {
			return nil, fmt.Errorf("endpoint %q: header %q: vault-owned or platform header", id, name)
		}
		if _, dup := e.headers[name]; dup {
			return nil, fmt.Errorf("endpoint %q: duplicate header %q", id, name)
		}
		ph, ok := parseHeaderTemplate(re.Headers[k])
		if ok && ph.isCard() {
			return nil, fmt.Errorf("endpoint %q: header %q: card placeholder in header", id, name)
		}
		if !ok || (ph.kind != "secret" && ph.kind != "basic" && ph.kind != "signature") {
			return nil, fmt.Errorf("endpoint %q: header %q: template must hold exactly one {{secret:NAME}}, {{basic:NAME}} or {{signature}} in printable ASCII", id, name)
		}
		usesSignature = usesSignature || ph.kind == "signature"
		e.headers[name] = re.Headers[k]
	}

	hasPAN := false
	for _, addr := range slices.Sorted(maps.Keys(re.Positions)) {
		if !validCatAddress(format, addr) || (format == "form" && strings.HasSuffix(addr, "[]")) {
			return nil, fmt.Errorf("endpoint %q: position %q: invalid address", id, addr)
		}
		ph, ok := parsePlaceholder(re.Positions[addr])
		if !ok {
			return nil, fmt.Errorf("endpoint %q: position %q: unknown placeholder", id, addr)
		}
		if ph.kind == "basic" {
			return nil, fmt.Errorf("endpoint %q: position %q: {{basic:}} is only allowed in headers", id, addr)
		}
		hasPAN = hasPAN || ph.kind == "pan"
		usesSignature = usesSignature || ph.kind == "signature"
		e.positions[addr] = ph
	}
	if !hasPAN {
		return nil, fmt.Errorf("endpoint %q: no {{pan}} position", id)
	}

	for _, addr := range slices.Sorted(maps.Keys(re.Pins)) {
		if !validCatAddress(format, addr) || (format == "form" && strings.HasSuffix(addr, "[]")) {
			return nil, fmt.Errorf("endpoint %q: pin %q: invalid address", id, addr)
		}
		if _, dup := e.positions[addr]; dup {
			return nil, fmt.Errorf("endpoint %q: address %q appears in more than one of positions, pins and forbid", id, addr)
		}
		rp := re.Pins[addr]
		hasLiteral := len(rp.Literal) != 0 && string(rp.Literal) != "null"
		if (rp.Account != nil) == hasLiteral {
			return nil, fmt.Errorf("endpoint %q: pin %q: needs exactly one of account and literal", id, addr)
		}
		if rp.Account != nil {
			if !validSecretName(*rp.Account) {
				return nil, fmt.Errorf("endpoint %q: pin %q: invalid account value name", id, addr)
			}
			e.pins[addr] = catPin{account: *rp.Account}
			continue
		}
		v, ok := catLiteral(format, rp.Literal, false)
		if !ok {
			return nil, fmt.Errorf("endpoint %q: pin %q: invalid literal", id, addr)
		}
		e.pins[addr] = catPin{literal: &v}
	}

	for _, addr := range slices.Sorted(maps.Keys(re.Forbid)) {
		if !validCatAddress(format, addr) {
			return nil, fmt.Errorf("endpoint %q: forbid %q: invalid address", id, addr)
		}
		_, inPositions := e.positions[addr]
		_, inPins := e.pins[addr]
		if inPositions || inPins {
			return nil, fmt.Errorf("endpoint %q: address %q appears in more than one of positions, pins and forbid", id, addr)
		}
		var elems []json.RawMessage
		if !bytes.HasPrefix(bytes.TrimSpace(re.Forbid[addr]), []byte("[")) || json.Unmarshal(re.Forbid[addr], &elems) != nil {
			return nil, fmt.Errorf("endpoint %q: forbid %q: must be a list of allowed literals", id, addr)
		}
		allowed := []fieldValue{} // non-nil: an empty list means "must be absent"
		for _, el := range elems {
			v, ok := catLiteral(format, el, true)
			if !ok {
				return nil, fmt.Errorf("endpoint %q: forbid %q: invalid literal", id, addr)
			}
			allowed = append(allowed, v)
		}
		e.forbid[addr] = allowed
	}

	switch e.signer {
	case "":
		if usesSignature {
			return nil, fmt.Errorf("endpoint %q: {{signature}} without signer", id)
		}
	case "payu":
		if format != "json" {
			return nil, fmt.Errorf("endpoint %q: signer payu needs a json provider", id)
		}
		if !usesSignature {
			return nil, fmt.Errorf("endpoint %q: signer without {{signature}} position or header", id)
		}
	default:
		return nil, fmt.Errorf("endpoint %q: unknown signer %q", id, e.signer)
	}
	return e, nil
}

// parseCatPath splits a rule path ("/a/{name}/b") or a base path into segments. Every segment must
// be a literal of RFC 3986 unreserved characters other than "." and "..", or, if wildcards is set,
// "{name}" with name [A-Za-z0-9_]{1,64}, each name at most once.
func parseCatPath(p string, wildcards bool) ([]string, bool) {
	rest, ok := strings.CutPrefix(p, "/")
	if !ok || len(p) > 1024 {
		return nil, false
	}
	segs := strings.Split(rest, "/")
	names := map[string]bool{}
	for _, s := range segs {
		if inner, ok := strings.CutPrefix(s, "{"); ok && wildcards {
			name, ok := strings.CutSuffix(inner, "}")
			if !ok || !validSecretName(name) || names[name] {
				return nil, false
			}
			names[name] = true
			continue
		}
		if s == "." || s == ".." || !catSegmentRe.MatchString(s) {
			return nil, false
		}
	}
	return segs, true
}

// catIsWildcard reports whether a parsed path segment is a "{name}" wildcard.
func catIsWildcard(s string) bool { return strings.HasPrefix(s, "{") }

// catPathsOverlap reports whether some request path matches both segment patterns a and b.
func catPathsOverlap(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] && !catIsWildcard(a[i]) && !catIsWildcard(b[i]) {
			return false
		}
	}
	return true
}

// parseHeaderTemplate checks a header value template: 1-1024 bytes of printable ASCII holding
// exactly one vocabulary placeholder and no other '{' or '}'. It returns that placeholder; the
// caller decides which kinds are allowed.
func parseHeaderTemplate(t string) (placeholder, bool) {
	if len(t) == 0 || len(t) > 1024 {
		return placeholder{}, false
	}
	for i := 0; i < len(t); i++ {
		if t[i] < 0x20 || t[i] > 0x7e {
			return placeholder{}, false
		}
	}
	i := strings.Index(t, "{{")
	if i < 0 {
		return placeholder{}, false
	}
	j := strings.Index(t[i:], "}}")
	if j < 0 {
		return placeholder{}, false
	}
	ph, ok := parsePlaceholder(t[i : i+j+2])
	if !ok || strings.ContainsAny(t[:i]+t[i+j+2:], "{}") {
		return placeholder{}, false
	}
	return ph, true
}

// validCatAddress reports whether addr is a valid field address for format: a canonical form key
// (validFormKey) or a JSON Pointer (validJSONPointer).
func validCatAddress(format, addr string) bool {
	switch format {
	case "form":
		return validFormKey(addr)
	case "json":
		return validJSONPointer(addr)
	}
	return false
}

// validJSONPointer reports whether p is an RFC 6901 JSON Pointer naming a field: "/"-prefixed,
// "~" only as "~0" or "~1", valid UTF-8 at most 1 KiB, and (stricter than the RFC) not "" and with
// no empty token, control character or U+FFFD, which jsonWalk never produces for a body field.
func validJSONPointer(p string) bool {
	if !strings.HasPrefix(p, "/") || len(p) > 1024 || !utf8.ValidString(p) || strings.ContainsRune(p, utf8.RuneError) {
		return false
	}
	for _, tok := range strings.Split(p[1:], "/") {
		if tok == "" {
			return false
		}
		for i := 0; i < len(tok); i++ {
			switch {
			case tok[i] < 0x20 || tok[i] == 0x7f:
				return false
			case tok[i] == '~':
				if i+1 >= len(tok) || (tok[i+1] != '0' && tok[i+1] != '1') {
					return false
				}
				i++
			}
		}
	}
	return true
}

// catLiteral decodes one pin or forbid literal, a JSON scalar, into the fieldValue readField
// produces for that value: kind string with the decoded text, or kind number/bool/null with the raw
// JSON text. null is accepted only if allowNull (forbid lists).
// A string literal containing "{{" is rejected (a body field holding it would be a
// placeholder or rejected anyway), and form providers accept only string literals, since a form
// field is always a string and any other literal could never match.
func catLiteral(format string, raw json.RawMessage, allowNull bool) (fieldValue, bool) {
	nodes, err := jsonWalk(raw)
	if err != nil || len(nodes) != 1 {
		return fieldValue{}, false
	}
	n := nodes[0]
	switch n.kind {
	case "string":
		if strings.Contains(n.text, "{{") {
			return fieldValue{}, false
		}
	case "number", "bool":
		if format != "json" {
			return fieldValue{}, false
		}
	case "null":
		if format != "json" || !allowNull {
			return fieldValue{}, false
		}
	default:
		return fieldValue{}, false
	}
	return fieldValue{kind: n.kind, text: n.text}, true
}

// validCatHost reports whether h is a valid account host: catHostRe, DNS labels of 1-63 characters
// not starting or ending with '-', at most 253 characters, and a port (if any) in 1-65535.
// Stricter than the bare pattern, so the host has one spelling for url.URL, the TLS
// ServerName and the egress firewall list.
func validCatHost(h string) bool {
	if !catHostRe.MatchString(h) {
		return false
	}
	name, port, hasPort := strings.Cut(h, ":")
	if len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	if hasPort {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return true
}

// validCatValue reports whether an account value is 1-256 bytes of printable ASCII with no "{{".
// Values are identifiers (merchant accounts, account IDs, hash names) compared with
// body fields and fed to signers, so anything else is a catalog mistake.
func validCatValue(s string) bool {
	if len(s) < 1 || len(s) > 256 || strings.Contains(s, "{{") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// parseCatAccount validates one account against the parsed providers. Its errors name the
// account, endpoint and secret or value name, never a Secret Manager resource or a value.
func parseCatAccount(name string, ra rawAccount, providers map[string]*catProvider) (*catAccount, error) {
	if !catNameRe.MatchString(name) {
		return nil, fmt.Errorf("catalog: account %q: invalid name", name)
	}
	if ra.Env != "dev" && ra.Env != "prod" {
		return nil, fmt.Errorf("catalog: account %q: env must be dev or prod", name)
	}
	p := providers[ra.Provider]
	if p == nil {
		return nil, fmt.Errorf("catalog: account %q: unknown provider %q", name, ra.Provider)
	}
	if !validCatHost(ra.Host) {
		return nil, fmt.Errorf("catalog: account %q: invalid host", name)
	}
	if ra.BasePath != "" {
		if _, ok := parseCatPath(ra.BasePath, false); !ok {
			return nil, fmt.Errorf("catalog: account %q: invalid base_path", name)
		}
	}
	a := &catAccount{name: name, provider: ra.Provider, env: ra.Env, host: ra.Host, basePath: ra.BasePath,
		secretNames: map[string]string{}, values: map[string]string{}, secrets: map[string]string{}}
	for _, k := range slices.Sorted(maps.Keys(ra.Secrets)) {
		if !validSecretName(k) {
			return nil, fmt.Errorf("catalog: account %q: invalid secret name %q", name, k)
		}
		if !secretNameRe.MatchString(ra.Secrets[k]) {
			return nil, fmt.Errorf("catalog: account %q: secret %q: invalid Secret Manager resource name", name, k)
		}
		a.secretNames[k] = ra.Secrets[k]
	}
	for _, k := range slices.Sorted(maps.Keys(ra.Values)) {
		if !validSecretName(k) {
			return nil, fmt.Errorf("catalog: account %q: invalid value name %q", name, k)
		}
		if !validCatValue(ra.Values[k]) {
			return nil, fmt.Errorf("catalog: account %q: value %q: invalid", name, k)
		}
		a.values[k] = ra.Values[k]
	}

	// Every secret and value the provider's rules reference must exist.
	payu := false
	for _, e := range p.endpoints {
		var phs []placeholder
		for _, h := range slices.Sorted(maps.Keys(e.headers)) {
			ph, _ := parseHeaderTemplate(e.headers[h]) // validated by parseCatEndpoint
			phs = append(phs, ph)
		}
		for _, addr := range slices.Sorted(maps.Keys(e.positions)) {
			phs = append(phs, e.positions[addr])
		}
		for _, ph := range phs {
			if (ph.kind == "secret" || ph.kind == "basic") && a.secretNames[ph.arg] == "" {
				return nil, fmt.Errorf("catalog: account %q: endpoint %q: missing secret %q", name, e.id, ph.arg)
			}
		}
		for _, addr := range slices.Sorted(maps.Keys(e.pins)) {
			if v := e.pins[addr].account; v != "" && a.values[v] == "" {
				return nil, fmt.Errorf("catalog: account %q: endpoint %q: missing value %q", name, e.id, v)
			}
		}
		payu = payu || e.signer == "payu"
	}
	if h := a.values["hash"]; payu && (a.secretNames["apiKey"] == "" || a.values["merchantId"] == "" || (h != "md5" && h != "sha1" && h != "sha256")) {
		return nil, fmt.Errorf("catalog: account %q: payu needs secret apiKey, value merchantId and hash md5, sha1 or sha256", name)
	}
	return a, nil
}
