package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// Placeholders and strict body scanners
// ---------------------------------------------------------------------------

// placeholder is one entry of the fixed vocabulary: kind is pan, cvv, name, exp_month,
// exp_year, exp, secret, basic or signature; mod is the format modifier (int, yy, yyyy/mm,
// mm/yy) and arg the secret NAME of secret/basic.
type placeholder struct{ kind, mod, arg string }

// parsePlaceholder parses s, which must be exactly the whole "{{...}}" text of one vocabulary
// placeholder: no whitespace, no other kinds or modifiers, NAME matching [A-Za-z0-9_]{1,64}.
func parsePlaceholder(s string) (placeholder, bool) {
	inner, ok := strings.CutPrefix(s, "{{")
	if !ok {
		return placeholder{}, false
	}
	inner, ok = strings.CutSuffix(inner, "}}")
	if !ok {
		return placeholder{}, false
	}
	kind, mod, hasMod := strings.Cut(inner, ":")
	switch kind {
	case "pan", "cvv", "name", "signature":
		if !hasMod {
			return placeholder{kind: kind}, true
		}
	case "exp_month":
		if !hasMod || mod == "int" {
			return placeholder{kind: kind, mod: mod}, true
		}
	case "exp_year":
		if !hasMod || mod == "yy" || mod == "int" {
			return placeholder{kind: kind, mod: mod}, true
		}
	case "exp":
		if hasMod && (mod == "yyyy/mm" || mod == "mm/yy") {
			return placeholder{kind: kind, mod: mod}, true
		}
	case "secret", "basic":
		if hasMod && validSecretName(mod) {
			return placeholder{kind: kind, arg: mod}, true
		}
	}
	return placeholder{}, false
}

// validSecretName reports whether s matches [A-Za-z0-9_]{1,64}.
func validSecretName(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// isCard reports whether p is filled from card data (pan, cvv, name and the expiry forms).
func (p placeholder) isCard() bool {
	switch p.kind {
	case "pan", "cvv", "name", "exp_month", "exp_year", "exp":
		return true
	}
	return false
}

// isNumber reports whether p is replaced, quotes included, by a bare number (the :int forms).
func (p placeholder) isNumber() bool { return p.mod == "int" }

// String returns the canonical "{{kind[:mod|:arg]}}" text; parsePlaceholder(p.String()) == p.
func (p placeholder) String() string {
	s := p.kind
	if p.mod != "" {
		s += ":" + p.mod
	}
	if p.arg != "" {
		s += ":" + p.arg
	}
	return "{{" + s + "}}"
}

// occurrence is one placeholder found in a body by scanBody.
type occurrence struct {
	addr       string // JSON Pointer (json) or decoded field name (form)
	ph         placeholder
	start, end int // byte span of the raw value (JSON: including the quotes)
}

// fieldValue is a body field read by readField. kind is string, number, bool, null, object or
// array; text is the decoded string, or the raw JSON text of anything else (numbers exactly as
// written, so "3.50" stays "3.50").
type fieldValue struct{ kind, text string }

var (
	errBody        = errors.New("invalid body")            // parse/strictness failure
	errPlaceholder = errors.New("invalid placeholder use") // placeholder-looking text where it is not allowed
)

// JSON nesting deeper than 64 objects/arrays is rejected. Provider bodies nest a
// handful of levels; the cap bounds work on pathological input well below encoding/json's own.
const maxJSONDepth = 64

// jsonNode is one token of a JSON body as walked by jsonWalk, in document order. Values carry the
// JSON Pointer of the value; a "key" node carries the pointer of the member it names. text is the
// decoded string (string, key) or the raw text (number, bool, null, object, array); [start, end)
// is the raw span, strings including their quotes.
type jsonNode struct {
	ptr        string
	kind       string // key string number bool null object array
	text       string
	start, end int
}

// jsonPointerEscaper escapes one RFC 6901 reference token ("~" first, then "/").
var jsonPointerEscaper = strings.NewReplacer("~", "~0", "/", "~1")

// jsonWalk parses b strictly and returns every key and value with its pointer and raw span. b must
// be valid UTF-8 holding exactly one JSON value (whitespace around it only), with no duplicate keys
// in any object (compared after decoding escapes) and at most maxJSONDepth levels of nesting.
// Any failure is errBody.
// A string or key whose decoded text contains U+FFFD is rejected. encoding/json
// silently decodes a lone surrogate escape ("\ud800") to U+FFFD, which other parsers reject or
// keep, so such a body could be read differently by the provider; a literal or escaped U+FFFD is
// indistinguishable after decoding and goes with it. A UTF-8 BOM is invalid JSON and rejected.
// A key whose decoded text contains a control character (U+0000-U+001F) is
// rejected, so a provider parser that truncates at NUL or strips control characters cannot alias
// "merchantAccount\u0000" to "merchantAccount" and bypass a pin or forbid rule.
//
// Raw spans: Token() leaves InputOffset at the end of the token it returned, and the separators
// before the next token (whitespace, ':' and ',') are consumed only by the next call. So a token
// starts at the first byte after the previous token's end that is not whitespace, ':' or ',', and
// ends at the new InputOffset. Each span is checked against the token (quotes, delimiter byte,
// number text) and any mismatch fails closed.
func jsonWalk(b []byte) ([]jsonNode, error) {
	if !utf8.Valid(b) {
		return nil, errBody
	}
	type frame struct {
		ptr   string
		array bool
		index int             // next array index
		keys  map[string]bool // object keys seen
		key   string          // pending member key (object)
		node  int             // index of the container's node
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var nodes []jsonNode
	var stack []*frame
	prev := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, errBody
		}
		end := int(dec.InputOffset())
		start := prev
		for start < end && (b[start] == ' ' || b[start] == '\t' || b[start] == '\n' || b[start] == '\r' || b[start] == ':' || b[start] == ',') {
			start++
		}
		prev = end
		if start >= end || end > len(b) {
			return nil, errBody
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}

		// An object member key.
		if top != nil && !top.array && top.key == "" && tok != json.Delim('}') {
			k, ok := tok.(string)
			if !ok || !jsonStringSpan(b, start, end) || strings.ContainsRune(k, utf8.RuneError) ||
				strings.ContainsFunc(k, func(r rune) bool { return r < 0x20 }) || top.keys[k] {
				return nil, errBody
			}
			top.keys[k] = true
			top.key = "/" + jsonPointerEscaper.Replace(k) // non-empty even for the "" key
			nodes = append(nodes, jsonNode{ptr: top.ptr + top.key, kind: "key", text: k, start: start, end: end})
			continue
		}

		// A closing delimiter ends the top frame's container.
		if tok == json.Delim('}') || tok == json.Delim(']') {
			if top == nil || end != start+1 || b[start] != byte(tok.(json.Delim)) {
				return nil, errBody
			}
			stack = stack[:len(stack)-1]
			nodes[top.node].end = end
			nodes[top.node].text = string(b[nodes[top.node].start:end])
		} else {
			// A value: its pointer comes from the enclosing container.
			ptr := ""
			if top != nil {
				if top.array {
					ptr = top.ptr + "/" + strconv.Itoa(top.index)
					top.index++
				} else {
					ptr = top.ptr + top.key
					top.key = ""
				}
			}
			n := jsonNode{ptr: ptr, start: start, end: end}
			switch t := tok.(type) {
			case json.Delim:
				if end != start+1 || b[start] != byte(t) || len(stack) >= maxJSONDepth {
					return nil, errBody
				}
				n.kind = "object"
				f := &frame{ptr: ptr, node: len(nodes), keys: map[string]bool{}}
				if t == json.Delim('[') {
					n.kind, f.array, f.keys = "array", true, nil
				}
				stack = append(stack, f)
			case string:
				if !jsonStringSpan(b, start, end) || strings.ContainsRune(t, utf8.RuneError) {
					return nil, errBody
				}
				n.kind, n.text = "string", t
			case json.Number:
				n.kind, n.text = "number", string(t)
			case bool:
				n.kind, n.text = "bool", strconv.FormatBool(t)
			case nil:
				n.kind, n.text = "null", "null"
			default:
				return nil, errBody
			}
			if n.kind != "string" && n.kind != "object" && n.kind != "array" && string(b[start:end]) != n.text {
				return nil, errBody
			}
			nodes = append(nodes, n)
		}

		// The root value is complete: only whitespace may follow.
		if len(stack) == 0 {
			if len(bytes.TrimLeft(b[end:], " \t\r\n")) != 0 {
				return nil, errBody
			}
			return nodes, nil
		}
	}
}

// jsonStringSpan reports whether b[start:end] looks like one complete JSON string token: it starts
// and ends with a quote and has no unescaped quote in between.
func jsonStringSpan(b []byte, start, end int) bool {
	if end-start < 2 || b[start] != '"' || b[end-1] != '"' {
		return false
	}
	for i := start + 1; i < end-1; i++ {
		switch b[i] {
		case '\\':
			i++
		case '"':
			return false
		}
	}
	return true
}

// jsonStrict checks that b is valid UTF-8 holding exactly one JSON value with no trailing data and
// no duplicate keys at any depth (see jsonWalk). It returns errBody or nil.
func jsonStrict(b []byte) error {
	_, err := jsonWalk(b)
	return err
}

// formField is one key=value pair of a form body, decoded, with the raw value's byte span.
type formField struct {
	key, value string
	start, end int
}

// formFields parses a form body strictly into its fields, in order. Keys must be canonical (see
// validFormKey) and unique unless they end in "[]". Any failure is errBody, except that a body
// whose only failure is a key containing "{{" is errPlaceholder (strictness failures win).
// Stricter than url.ParseQuery, so no two parsers can split the body differently:
// every raw byte must be visible ASCII (0x21-0x7E; spaces as "+", everything else percent-encoded),
// ';' is rejected outright (some parsers treat it as a separator), every '&'-separated segment must
// be key=value with a non-empty key (no empty segments, no bare keys), percent-escapes must be
// valid and the decoded key and value must be valid UTF-8. An empty body is zero fields.
func formFields(b []byte) ([]formField, error) {
	if len(b) == 0 {
		return nil, nil
	}
	for _, c := range b {
		if c < 0x21 || c > 0x7e || c == ';' {
			return nil, errBody
		}
	}
	var fields []formField
	seen := map[string]bool{}
	placeholderKey := false
	pos := 0
	for _, seg := range strings.Split(string(b), "&") {
		rawKey, rawVal, ok := strings.Cut(seg, "=")
		if !ok || rawKey == "" {
			return nil, errBody
		}
		key, err1 := url.QueryUnescape(rawKey)
		val, err2 := url.QueryUnescape(rawVal)
		if err1 != nil || err2 != nil || !utf8.ValidString(key) || !utf8.ValidString(val) {
			return nil, errBody
		}
		if !validFormKey(key) {
			if !strings.Contains(key, "{{") {
				return nil, errBody
			}
			placeholderKey = true
		}
		if seen[key] && !strings.HasSuffix(key, "[]") {
			return nil, errBody
		}
		seen[key] = true
		vstart := pos + len(rawKey) + 1
		fields = append(fields, formField{key: key, value: val, start: vstart, end: vstart + len(rawVal)})
		pos += len(seg) + 1
	}
	if placeholderKey {
		return nil, errPlaceholder
	}
	return fields, nil
}

// formKeyRe is the canonical form key grammar: a name, then [segment] groups, then an optional
// final "[]".
var formKeyRe = regexp.MustCompile(`^[A-Za-z0-9_-]+(\[[A-Za-z0-9_-]+\])*(\[\])?$`)

// validFormKey reports whether a decoded form key is canonical.
// Bracket-parsing servers (Rack, PHP, qs) normalize malformed keys, mapping
// "customer]", "[customer" or "a[b]c" onto other names, and NUL or control bytes can truncate a
// key. Such aliases would bypass duplicate detection and the pin/forbid rules, which match the
// flat decoded name. So a key must be a name of [A-Za-z0-9_-] followed by zero or more non-empty
// [segment] groups of the same characters and at most one trailing "[]". Stricter than a plain
// bracket grammar: "." is excluded (PHP rewrites "a.b" to "a_b") and "[]" is allowed only last
// (a mid-key "[]" appends to an array whose element a name cannot address uniquely).
func validFormKey(k string) bool {
	return formKeyRe.MatchString(k)
}

// scanBody parses body strictly in format ("json" or "form") and returns every placeholder
// occurrence, sorted by start. Text containing "{{" anywhere a placeholder is not allowed is
// errPlaceholder, never passed through: every decoded JSON string or form value containing "{{"
// is either an occurrence or an error, so no placeholder can skip the position check.
//   - json: a string value containing "{{" (after decoding escapes) must be raw-exactly '"' + a
//     vocabulary placeholder + '"'; a key containing "{{" is always an error.
//   - form: a value containing "{{" (after percent-decoding) must be raw-exactly a vocabulary
//     placeholder, and never under a "[]" key (repeatable, so not a unique position); a key
//     containing "{{" is always an error.
//
// Strictness failures (errBody) take precedence over placeholder failures.
func scanBody(format string, body []byte) ([]occurrence, error) {
	var occs []occurrence
	switch format {
	case "json":
		nodes, err := jsonWalk(body)
		if err != nil {
			return nil, err
		}
		for _, n := range nodes {
			if !strings.Contains(n.text, "{{") || (n.kind != "key" && n.kind != "string") {
				continue
			}
			if n.kind == "key" {
				return nil, errPlaceholder
			}
			raw := string(body[n.start+1 : n.end-1])
			ph, ok := parsePlaceholder(raw)
			if !ok || raw != n.text {
				return nil, errPlaceholder
			}
			occs = append(occs, occurrence{addr: n.ptr, ph: ph, start: n.start, end: n.end})
		}
	case "form":
		fields, err := formFields(body)
		if err != nil {
			return nil, err
		}
		for _, f := range fields {
			if strings.Contains(f.key, "{{") {
				return nil, errPlaceholder
			}
			if !strings.Contains(f.value, "{{") {
				continue
			}
			raw := string(body[f.start:f.end])
			ph, ok := parsePlaceholder(raw)
			if !ok || raw != f.value || strings.HasSuffix(f.key, "[]") {
				return nil, errPlaceholder
			}
			occs = append(occs, occurrence{addr: f.key, ph: ph, start: f.start, end: f.end})
		}
	default:
		return nil, errBody
	}
	return occs, nil
}

// readField returns the value at addr (a JSON Pointer for json, a decoded field name for form).
// found is false when the body is valid but has no such field. A body failing the strict parse is
// errBody (errPlaceholder for a form key containing "{{"). Form values are always kind "string".
// A form key that appears more than once (only possible for "[]" keys) has no single
// value, so reading it is errBody rather than picking one.
func readField(format string, body []byte, addr string) (fieldValue, bool, error) {
	switch format {
	case "json":
		nodes, err := jsonWalk(body)
		if err != nil {
			return fieldValue{}, false, err
		}
		for _, n := range nodes {
			if n.kind != "key" && n.ptr == addr {
				return fieldValue{kind: n.kind, text: n.text}, true, nil
			}
		}
		return fieldValue{}, false, nil
	case "form":
		fields, err := formFields(body)
		if err != nil {
			return fieldValue{}, false, err
		}
		var v fieldValue
		found := false
		for _, f := range fields {
			if f.key == addr {
				if found {
					return fieldValue{}, false, errBody
				}
				v, found = fieldValue{kind: "string", text: f.value}, true
			}
		}
		return v, found, nil
	}
	return fieldValue{}, false, errBody
}

// encodeValue encodes v for substitution in format: json as a quoted JSON string, or as a bare
// number when number is set; form as url.QueryEscape(v).
// A number is emitted bare only when v is 1-18 ASCII digits, and then in canonical
// form ("03" → 3; a leading zero is invalid JSON). Anything else is encoded as a string, so the
// output is always a valid JSON value or form value; callers only pass digits. An unknown format is
// a programming error and panics.
func encodeValue(format string, v string, number bool) []byte {
	if number && len(v) >= 1 && len(v) <= 18 && strings.Trim(v, "0123456789") == "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			v = strconv.FormatInt(n, 10)
			if format == "json" {
				return []byte(v)
			}
		}
	}
	switch format {
	case "json":
		out, err := json.Marshal(v)
		if err != nil {
			panic("encodeValue: marshal failed")
		}
		return out
	case "form":
		return []byte(url.QueryEscape(v))
	}
	panic("encodeValue: unknown format")
}

// substitute returns a copy of body with each span occs[i] replaced by repl[i]; every other byte is
// unchanged. occs must be sorted by start, non-overlapping and within body, with one repl each;
// anything else is a programming error and panics (a fixed message, never body bytes).
func substitute(body []byte, occs []occurrence, repl [][]byte) []byte {
	if len(occs) != len(repl) {
		panic("substitute: invalid spans")
	}
	out := make([]byte, 0, len(body))
	prev := 0
	for i, o := range occs {
		if o.start < prev || o.end < o.start || o.end > len(body) {
			panic("substitute: invalid spans")
		}
		out = append(out, body[prev:o.start]...)
		out = append(out, repl[i]...)
		prev = o.end
	}
	return append(out, body[prev:]...)
}
