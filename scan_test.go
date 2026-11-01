package main

import (
	"encoding/json"
	"errors"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Placeholders and strict body scanners
// ---------------------------------------------------------------------------

func TestParsePlaceholder(t *testing.T) {
	cases := []struct {
		s              string
		card, number   bool
		kind, mod, arg string
	}{
		{"{{pan}}", true, false, "pan", "", ""},
		{"{{cvv}}", true, false, "cvv", "", ""},
		{"{{name}}", true, false, "name", "", ""},
		{"{{exp_month}}", true, false, "exp_month", "", ""},
		{"{{exp_month:int}}", true, true, "exp_month", "int", ""},
		{"{{exp_year}}", true, false, "exp_year", "", ""},
		{"{{exp_year:yy}}", true, false, "exp_year", "yy", ""},
		{"{{exp_year:int}}", true, true, "exp_year", "int", ""},
		{"{{exp:yyyy/mm}}", true, false, "exp", "yyyy/mm", ""},
		{"{{exp:mm/yy}}", true, false, "exp", "mm/yy", ""},
		{"{{secret:secretKey}}", false, false, "secret", "", "secretKey"},
		{"{{secret:A_9}}", false, false, "secret", "", "A_9"},
		{"{{secret:" + strings.Repeat("a", 64) + "}}", false, false, "secret", "", strings.Repeat("a", 64)},
		{"{{basic:apiKey}}", false, false, "basic", "", "apiKey"},
		{"{{signature}}", false, false, "signature", "", ""},
	}
	for _, c := range cases {
		p, ok := parsePlaceholder(c.s)
		if !ok {
			t.Errorf("%s rejected", c.s)
			continue
		}
		if p.kind != c.kind || p.mod != c.mod || p.arg != c.arg {
			t.Errorf("%s parsed as %+v", c.s, p)
		}
		if p.String() != c.s {
			t.Errorf("%s round-trips to %s", c.s, p.String())
		}
		if p.isCard() != c.card || p.isNumber() != c.number {
			t.Errorf("%s: isCard=%v isNumber=%v", c.s, p.isCard(), p.isNumber())
		}
	}
	for _, s := range []string{
		"{{ pan }}", "{{pan:int}}", "{{exp_year:yyyy}}", "{{secret:}}", "{{secret:a b}}", "{{foo}}", "{pan}",
		"", "{{}}", "{{pan}", "{pan}}", "{{{pan}}}", "{{PAN}}", "{{pan}} ", " {{pan}}", "{{pan:}}",
		"{{cvv:int}}", "{{name:x}}", "{{signature:x}}", "{{exp}}", "{{exp:}}", "{{exp:yy/mm}}",
		"{{exp_month:}}", "{{exp_month:yy}}", "{{exp_year:}}", "{{secret}}", "{{basic}}", "{{basic:}}",
		"{{secret:" + strings.Repeat("a", 65) + "}}", "{{secret:a-b}}", "{{secret:a:b}}", "{{secret:a/b}}",
		"{{secret:é}}", "{{pan}}{{cvv}}", "{{exp_month:int:int}}",
	} {
		if p, ok := parsePlaceholder(s); ok {
			t.Errorf("%q accepted as %+v", s, p)
		}
	}
}

// checkOccurrences checks that occs are exactly want (addr → placeholder text), in body order, and that each
// span slices back to the raw value text (rawQuoted adds the JSON quotes).
func checkOccurrences(t *testing.T, body string, occs []occurrence, want [][2]string, rawQuoted bool) {
	t.Helper()
	if len(occs) != len(want) {
		t.Fatalf("got %d occurrences, want %d", len(occs), len(want))
	}
	for i, o := range occs {
		if o.addr != want[i][0] || o.ph.String() != want[i][1] {
			t.Errorf("occurrence %d: %s %s, want %s %s", i, o.addr, o.ph, want[i][0], want[i][1])
		}
		raw := want[i][1]
		if rawQuoted {
			raw = `"` + raw + `"`
		}
		if o.start < 0 || o.end > len(body) || o.start >= o.end || body[o.start:o.end] != raw {
			t.Errorf("occurrence %d: span [%d,%d) does not slice back to %s", i, o.start, o.end, raw)
		}
		if i > 0 && occs[i-1].end > o.start {
			t.Errorf("occurrence %d not after occurrence %d", i, i-1)
		}
	}
}

func TestScanJSON(t *testing.T) {
	body := `{"a":{"n":"{{pan}}","m":"{{exp_month:int}}"},"x/y":"{{cvv}}","arr":[{"k":"{{name}}"}]}`
	occs, err := scanBody("json", []byte(body))
	if err != nil {
		t.Fatalf("scanBody: %v", err)
	}
	checkOccurrences(t, body, occs, [][2]string{
		{"/a/n", "{{pan}}"}, {"/a/m", "{{exp_month:int}}"}, {"/x~1y", "{{cvv}}"}, {"/arr/0/k", "{{name}}"},
	}, true)

	// Whitespace everywhere, escapes and multi-byte UTF-8 in the strings before each placeholder, and
	// keys needing "~0"/"~1" escaping and decoded escapes, all keep the spans exact.
	body = " {\n\t\"d\\\"esc\" : \"caf\u00e9 \\u00e9 \\\"q\\\" \\\\ \\n \\ud83d\\ude00 \U0001F600\" ,\r\n" +
		"  \"~a/b\"  :  \"{{secret:k_1}}\" , \"\\u0061rr\" : [ 1 , 2.50 , true , null , { } , [ ] ,\n" +
		"  \"{{exp:mm/yy}}\" , [ \"{{signature}}\" ] ] , \"\" : \"{{basic:B}}\" } \n"
	occs, err = scanBody("json", []byte(body))
	if err != nil {
		t.Fatalf("scanBody (whitespace/escapes): %v", err)
	}
	checkOccurrences(t, body, occs, [][2]string{
		{"/~0a~1b", "{{secret:k_1}}"}, {"/arr/6", "{{exp:mm/yy}}"}, {"/arr/7/0", "{{signature}}"}, {"/", "{{basic:B}}"},
	}, true)

	// A body with no placeholders has no occurrences; a top-level placeholder has the root address.
	if occs, err := scanBody("json", []byte(`{"a":"b","c":[1,{"d":"{x}"}]}`)); err != nil || len(occs) != 0 {
		t.Errorf("no placeholders: %d occurrences, err %v", len(occs), err)
	}
	occs, err = scanBody("json", []byte(` "{{pan}}" `))
	if err != nil {
		t.Fatalf("top-level placeholder: %v", err)
	}
	checkOccurrences(t, ` "{{pan}}" `, occs, [][2]string{{"", "{{pan}}"}}, true)

	if _, err := scanBody("xml", []byte(`<a/>`)); !errors.Is(err, errBody) {
		t.Errorf("unknown format: %v", err)
	}
}

// TestJSONSpans checks every string token's span (not just placeholders) against the decoded value,
// by slicing the raw text and unmarshalling it.
func TestJSONSpans(t *testing.T) {
	body := "{\"k\\u00e9y\":[\"a\\\"b\",\"\\ud83d\\ude00\",\"\u65e5\u672c\",{\"x\" :\"\\/\\b\\f\\n\\r\\t\"}], \"n\":-1.5e+3}"
	nodes, err := jsonWalk([]byte(body), true)
	if err != nil {
		t.Fatalf("jsonWalk: %v", err)
	}
	strs := 0
	for i, n := range nodes {
		raw := body[n.start:n.end]
		switch n.kind {
		case "string", "key":
			strs++
			var s string
			if err := json.Unmarshal([]byte(raw), &s); err != nil || s != n.text {
				t.Errorf("%s %s: span %q does not decode to the token", n.kind, jsonPointer(nodes, i), raw)
			}
		case "number":
			if raw != n.text {
				t.Errorf("%s %s: span %q, text %q", n.kind, jsonPointer(nodes, i), raw, n.text)
			}
		case "object", "array":
			// Containers keep no text; their span is one complete JSON value of their kind.
			if n.text != "" || !json.Valid([]byte(raw)) || raw[0] != map[string]byte{"object": '{', "array": '['}[n.kind] {
				t.Errorf("%s %s: span %q, text %q", n.kind, jsonPointer(nodes, i), raw, n.text)
			}
		}
	}
	if strs != 7 {
		t.Errorf("%d string/key nodes, want 7", strs)
	}
}

// TestJSONPointer: pointers assembled from the nodes' segs, and compared in place exactly or up to
// case, match the RFC 6901 pointer of every key and value.
func TestJSONPointer(t *testing.T) {
	body := `{"a":{"b/c":[1,{"~":true}]},"":"e","K":[[]],"x":{"k":null}}`
	nodes, err := jsonWalk([]byte(body), true)
	if err != nil {
		t.Fatalf("jsonWalk: %v", err)
	}
	want := []string{
		"", "/a", "/a", "/a/b~1c", "/a/b~1c", "/a/b~1c/0", "/a/b~1c/1", "/a/b~1c/1/~0", "/a/b~1c/1/~0",
		"/", "/", "/K", "/K", "/K/0", "/x", "/x", "/x/k", "/x/k",
	}
	if len(nodes) != len(want) {
		t.Fatalf("%d nodes, want %d", len(nodes), len(want))
	}
	for i, w := range want {
		if got := jsonPointer(nodes, i); got != w {
			t.Errorf("node %d (%s): pointer %q, want %q", i, nodes[i].kind, got, w)
		}
		if !jsonPointerIs(nodes, i, w, false) || !jsonPointerIs(nodes, i, w, true) {
			t.Errorf("node %d: does not match its own pointer %q", i, w)
		}
		for _, other := range []string{w + "/0", w + "x", "/q" + w, "x" + w} {
			if jsonPointerIs(nodes, i, other, false) || jsonPointerIs(nodes, i, other, true) {
				t.Errorf("node %d (%q) matches %q", i, w, other)
			}
		}
	}
	// Folding matches what strings.EqualFold matches on the whole pointer, including a non-ASCII
	// fold (KELVIN SIGN folds to "K") and nothing that differs in more than case.
	for _, c := range []struct {
		i    int
		addr string
		fold bool
	}{
		{1, "/A", true}, {4, "/A/B~1C", true}, {11, "/k", true}, {11, "/L", false}, {11, "/\u212a", true},
		{13, "/k/0", true}, {16, "/X/K", true}, {4, "/a/b~1c/", false}, {4, "/a/b/c", false}, {9, "", false},
		{0, "/", false},
	} {
		if strings.EqualFold(jsonPointer(nodes, c.i), c.addr) != c.fold {
			t.Fatalf("case %q: fixture disagrees with strings.EqualFold", c.addr)
		}
		if got := jsonPointerIs(nodes, c.i, c.addr, true); got != c.fold {
			t.Errorf("node %d fold-matches %q: %v, want %v", c.i, c.addr, got, c.fold)
		}
		if c.addr != jsonPointer(nodes, c.i) && jsonPointerIs(nodes, c.i, c.addr, false) {
			t.Errorf("node %d exactly matches %q", c.i, c.addr)
		}
	}
	if nodes, err := jsonWalk([]byte(body), false); err != nil || nodes != nil {
		t.Errorf("validate-only walk: %d nodes, err %v", len(nodes), err)
	}
}

// allocated returns the bytes f allocates.
func allocated(f func()) int {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return int(after.TotalAlloc - before.TotalAlloc)
}

// TestJSONWalkMemoryBound: walking a body costs memory linear in its size. Three shapes would cost
// memory growing with the square of the input if the walker or scanner copied per node: a long key
// over a wide array (each element's JSON Pointer would copy the key), deep nesting around a long
// string (each container's text would copy the string), and many placeholders under a long key
// (each occurrence's address would copy the key). Each bound is the cost one feature adds over a
// twin body without it, so encoding/json's own cost per token (its Token loop alone allocates about
// 6x the wide body) cancels out.
func TestJSONWalkMemoryBound(t *testing.T) {
	wide := func(key string) []byte {
		return []byte(`{"` + key + `":[` + strings.TrimSuffix(strings.Repeat("1,", 4000), ",") + `]}`)
	}
	many := func(key string) []byte {
		return []byte(`{"` + key + `":[` + strings.TrimSuffix(strings.Repeat(`"{{pan}}",`, 2600), ",") + `]}`)
	}
	key, str, manyKey := strings.Repeat("k", 8000), strings.Repeat("s", 16000), strings.Repeat("k", 32000)
	cases := []struct {
		name          string
		with, without []byte
		limit         int
	}{
		{"an 8000-byte key over 4000 elements", wide(key), wide("k"), 8 * len(key)},
		{"64 levels of nesting around a 16000-byte string",
			[]byte(strings.Repeat("[", maxJSONDepth) + `"` + str + `"` + strings.Repeat("]", maxJSONDepth)),
			[]byte(`"` + str + `"`), 2 * len(str)},
	}
	for _, c := range cases {
		for _, b := range [][]byte{c.with, c.without} {
			if err := jsonStrict(b); err != nil {
				t.Fatalf("%s: jsonStrict: %v", c.name, err)
			}
			if occs, err := scanBody("json", b); err != nil || len(occs) != 0 {
				t.Fatalf("%s: scanBody: %d occurrences, err %v", c.name, len(occs), err)
			}
		}
		strict := allocated(func() { _ = jsonStrict(c.with) }) - allocated(func() { _ = jsonStrict(c.without) })
		if strict >= c.limit {
			t.Errorf("%s added %d bytes to jsonStrict, want < %d", c.name, strict, c.limit)
		}
		scan := allocated(func() { _, _ = scanBody("json", c.with) }) - allocated(func() { _, _ = scanBody("json", c.without) })
		if scan >= c.limit {
			t.Errorf("%s added %d bytes to scanBody, want < %d", c.name, scan, c.limit)
		}
	}

	// 2600 placeholders (58 KB) are refused, and under a 32000-byte key cost no more than under a
	// one-byte key: the cap is reached before any address is built.
	manyLong, manyShort := many(manyKey), many("k")
	for _, b := range [][]byte{manyLong, manyShort} {
		if _, err := scanBody("json", b); !errors.Is(err, errPlaceholder) {
			t.Fatalf("2600 placeholders: %v", err)
		}
	}
	scan := allocated(func() { _, _ = scanBody("json", manyLong) }) - allocated(func() { _, _ = scanBody("json", manyShort) })
	if scan >= 8*len(manyKey) {
		t.Errorf("a %d-byte key over 2600 placeholders added %d bytes to scanBody, want < %d", len(manyKey), scan, 8*len(manyKey))
	}
}

// TestScanOccurrenceCap: up to maxOccurrences placeholder occurrences are returned; one more is
// errPlaceholder, unless the body also fails the strict parse.
func TestScanOccurrenceCap(t *testing.T) {
	jsonBody := func(n int) string {
		return `[` + strings.TrimSuffix(strings.Repeat(`"{{signature}}",`, n), ",") + `]`
	}
	formBody := func(n int) string {
		var parts []string
		for i := range n {
			parts = append(parts, "a"+strconv.Itoa(i)+"={{signature}}")
		}
		return strings.Join(parts, "&")
	}
	for format, mk := range map[string]func(int) string{"json": jsonBody, "form": formBody} {
		occs, err := scanBody(format, []byte(mk(maxOccurrences)))
		if err != nil || len(occs) != maxOccurrences {
			t.Fatalf("%s: %d placeholders: %d occurrences, err %v", format, maxOccurrences, len(occs), err)
		}
		if format == "json" && (occs[0].addr != "/0" || occs[maxOccurrences-1].addr != "/63") {
			t.Errorf("json: addresses %q .. %q", occs[0].addr, occs[maxOccurrences-1].addr)
		}
		if _, err := scanBody(format, []byte(mk(maxOccurrences+1))); !errors.Is(err, errPlaceholder) {
			t.Errorf("%s: %d placeholders: %v", format, maxOccurrences+1, err)
		}
	}
	if _, err := scanBody("json", []byte(jsonBody(maxOccurrences+1)+" {}")); !errors.Is(err, errBody) {
		t.Errorf("json: too many placeholders and trailing data: %v", err)
	}
	if _, err := scanBody("form", []byte(formBody(maxOccurrences+1)+"&a0=x")); !errors.Is(err, errBody) {
		t.Errorf("form: too many placeholders and a duplicate key: %v", err)
	}
}

func TestScanForm(t *testing.T) {
	body := "card[number]={{pan}}&type=card"
	occs, err := scanBody("form", []byte(body))
	if err != nil {
		t.Fatalf("scanBody: %v", err)
	}
	checkOccurrences(t, body, occs, [][2]string{{"card[number]", "{{pan}}"}}, false)

	body = "a%5Bb%5D=x+y%26&card[exp_month]={{exp_month:int}}&expand[]=a&expand[]=b&e=&card[cvc]={{cvv}}"
	occs, err = scanBody("form", []byte(body))
	if err != nil {
		t.Fatalf("scanBody: %v", err)
	}
	checkOccurrences(t, body, occs, [][2]string{{"card[exp_month]", "{{exp_month:int}}"}, {"card[cvc]", "{{cvv}}"}}, false)

	// An empty form body is zero fields.
	if occs, err := scanBody("form", nil); err != nil || len(occs) != 0 {
		t.Errorf("empty form: %d occurrences, err %v", len(occs), err)
	}
	// Malformed forms.
	for _, b := range []string{
		"&", "a=1&", "&a=1", "a=1&&b=2", "a", "a=1&b", "=1", "a=%zz", "%zz=1", "a=%", "a=1;b=2", "a=1 2",
		"a=\x00", "a=caf\xc3\xa9", "a=%ff", "a=%c3", "a=\x7f",
	} {
		if _, err := scanBody("form", []byte(b)); !errors.Is(err, errBody) {
			t.Errorf("form %q: %v", b, err)
		}
	}
}

func TestScanRejectsDisguisedPlaceholders(t *testing.T) {
	for _, b := range []string{
		// Escape-disguised: the decoded text is a placeholder but the raw bytes are not.
		`{"n":"\u007b\u007bpan}}"}`,
		`{"n":"\u007B\u007Bpan\u007D\u007D"}`,
		`{"n":"{\u007bpan}}"}`,
		`{"n":"{{p\u0061n}}"}`,
		`{"n":"{{pan\u007d\u007d"}`,
		`{"n":"{{pan}\u007d"}`,
		`"\u007b\u007bpan}}"`,
		// Placeholders in keys.
		`{"{{pan}}":1}`,
		`{"a":{"x{{cvv}}y":"v"}}`,
		`{"\u007b\u007bpan}}":1}`,
		// Partial, concatenated, or not in the vocabulary.
		`{"n":"x{{pan}}"}`,
		`{"n":"{{pan}}x"}`,
		`{"n":" {{pan}}"}`,
		`{"n":"{{pan}}{{cvv}}"}`,
		`{"n":"{{exp_month}}/{{exp_year}}"}`,
		`{"n":"{{foo}}"}`,
		`{"n":"{{ pan }}"}`,
		`{"n":"{{pan"}`,
		`{"n":"{{"}`,
		`{"n":["ok","{{pan:int}}"]}`,
	} {
		if _, err := scanBody("json", []byte(b)); !errors.Is(err, errPlaceholder) {
			t.Errorf("json %s: %v", b, err)
		}
	}
	for _, b := range []string{
		"n=%7B%7Bpan%7D%7D",
		"n=%7b%7bpan%7d%7d",
		"n={%7Bpan}}",
		"n={{p%61n}}",
		"{{pan}}=1",
		"%7B%7Bpan%7D%7D=1",
		"a[{{cvv}}]=1",
		"n=x{{pan}}",
		"n={{pan}}{{cvv}}",
		"n={{foo}}",
		"n={{+pan+}}",
		"n={{",
		"expand[]={{pan}}",
		"{{pan}}[]=x",
	} {
		if _, err := scanBody("form", []byte(b)); !errors.Is(err, errPlaceholder) {
			t.Errorf("form %s: %v", b, err)
		}
	}
}

func TestJSONStrict(t *testing.T) {
	for _, b := range []string{
		`{"a":1}`, `[]`, `"x"`, `1`, `true`, `null`, " {\"a\":[1,{\"a\":2}],\"b\":{\"a\":3}} \n",
		`{"a":{"b":1},"c":{"b":1}}`, `{"é":1,"e":2}`, `{"a":"\ufffe"}`, `{"a\u007f ":"\u0000\n"}`,
	} {
		if err := jsonStrict([]byte(b)); err != nil {
			t.Errorf("%s rejected: %v", b, err)
		}
	}
	deep := strings.Repeat("[", maxJSONDepth) + strings.Repeat("]", maxJSONDepth)
	if err := jsonStrict([]byte(deep)); err != nil {
		t.Errorf("depth %d rejected: %v", maxJSONDepth, err)
	}
	for _, b := range []string{
		// Duplicate keys: top level, nested, inside an array, after decoding escapes, container values.
		`{"a":1,"a":2}`, `{"x":{"a":1,"b":2,"a":3}}`, `[{"a":1},{"b":1,"b":1}]`, `{"a":1,"\u0061":2}`,
		`{"a":{},"a":[]}`,
		// Trailing data.
		`{}{}`, `{} {}`, `{}x`, `1 2`, `"a""b"`, `{}]`,
		// Invalid UTF-8, and a BOM.
		"{\"a\":\"\xff\"}", "{\"\xc3\":1}", "\xef\xbb\xbf{}",
		// Empty.
		``, ` `, "\n",
		// Malformed.
		`{`, `{"a"}`, `{"a":}`, `{"a" 1}`, `[1,]`, `{"a":1,}`, `[,1]`, `{'a':1}`, `[01]`, `NaN`, `"\x"`,
		// Control characters in keys (a NUL-truncating parser would alias them).
		`{"merchantAccount\u0000":"x"}`, `{"merchantAccount":"a","merchantAccount\u0000":"b"}`,
		`{"a\n":1}`, `{"x":{"\u001f":1}}`, `{"\u0000":1}`, `{"a\tb":1}`,
		// Replacement character and lone surrogates.
		`"\ud800"`, `{"\udc00":1}`, `"\ufffd"`, "\"\xef\xbf\xbd\"",
		// Too deep.
		strings.Repeat("[", maxJSONDepth+1) + strings.Repeat("]", maxJSONDepth+1),
		strings.Repeat(`{"a":`, maxJSONDepth+1) + "1" + strings.Repeat("}", maxJSONDepth+1),
	} {
		if err := jsonStrict([]byte(b)); !errors.Is(err, errBody) {
			t.Errorf("%q: %v", b, err)
		}
	}
	// Strictness failures win over placeholder failures, and scanBody applies them too.
	if _, err := scanBody("json", []byte(`{"{{pan}}":1,"{{pan}}":2}`)); !errors.Is(err, errBody) {
		t.Errorf("duplicate placeholder keys: %v", err)
	}
	if _, err := scanBody("json", []byte(`{"n":"{{pan}}"} {}`)); !errors.Is(err, errBody) {
		t.Errorf("trailing data: %v", err)
	}
}

func TestScanFormDuplicates(t *testing.T) {
	for _, b := range []string{
		"a=1&a=2", "a=1&a=1", "card[number]={{pan}}&card[number]=4242", "a=1&%61=2",
		"card%5Bnumber%5D=1&card[number]=2",
		// Aliases a bracket parser would merge with an earlier key are not canonical.
		"customer]=x&customer=y", "customer=y&[customer=x", "a=1&a%00=2",
	} {
		if _, err := scanBody("form", []byte(b)); !errors.Is(err, errBody) {
			t.Errorf("%s: %v", b, err)
		}
	}
	for _, b := range []string{"expand[]=a&expand[]=b", "expand[]=a&expand[]=a&x=1"} {
		if _, err := scanBody("form", []byte(b)); err != nil {
			t.Errorf("%s rejected: %v", b, err)
		}
	}
}

// TestScanFormKeys: form keys must be canonical (a name, [segment] groups, an optional final "[]"),
// so a provider's bracket parsing cannot alias one key onto another.
func TestScanFormKeys(t *testing.T) {
	for _, k := range []string{
		"card[number]", "payment_method_data[card][exp_month]", "expand[]", "metadata[order_id]",
		"type", "items[0][price]", "x-y", "A_9", "a[b-c][]",
	} {
		if _, err := scanBody("form", []byte(url.QueryEscape(k)+"=1")); err != nil {
			t.Errorf("escaped key %s rejected: %v", k, err)
		}
		if _, err := scanBody("form", []byte(k+"=1")); err != nil {
			t.Errorf("raw key %s rejected: %v", k, err)
		}
	}
	for _, k := range []string{
		"customer]", "[customer", "a[b]c", "a[[b]]", "a%00", "]]customer]]", "card[number]]", "a[]b",
		"a[][b]", "a[", "a]", "[]", "a[b", "a.b", "a+b", "a%20b", "a%0A", "a%7F", "caf%C3%A9", "a%5B%5Db",
		"a[b%00]",
	} {
		if _, err := scanBody("form", []byte(k+"=1")); !errors.Is(err, errBody) {
			t.Errorf("key %s: %v", k, err)
		}
		if _, _, err := readField("form", []byte(k+"=1"), "a"); !errors.Is(err, errBody) {
			t.Errorf("readField key %s: %v", k, err)
		}
	}
	// A key containing "{{" is still errPlaceholder, but a strictness failure anywhere wins.
	if _, err := scanBody("form", []byte("{{pan}}=1&a=2")); !errors.Is(err, errPlaceholder) {
		t.Errorf("placeholder key: %v", err)
	}
	if _, err := scanBody("form", []byte("{{pan}}=1&customer]=2")); !errors.Is(err, errBody) {
		t.Errorf("placeholder key then bad key: %v", err)
	}
}

func TestReadField(t *testing.T) {
	body := []byte(`{"s":"a\"b","amt":{"value":65000,"tax":3.50},"ok":true,"no":false,"z":null,` +
		`"o":{"k":[1, 2]},"a/b":["x"],"e":""}`)
	for addr, want := range map[string]fieldValue{
		"/s":         {"string", `a"b`},
		"/amt/value": {"number", "65000"},
		"/amt/tax":   {"number", "3.50"},
		"/ok":        {"bool", "true"},
		"/no":        {"bool", "false"},
		"/z":         {"null", "null"},
		"/o":         {"object", `{"k":[1, 2]}`},
		"/o/k":       {"array", "[1, 2]"},
		"/o/k/1":     {"number", "2"},
		"/a~1b/0":    {"string", "x"},
		"/e":         {"string", ""},
		"":           {"object", string(body)},
	} {
		got, ok, err := readField("json", body, addr)
		if err != nil || !ok || got != want {
			t.Errorf("json %q: %+v ok=%v err=%v, want %+v", addr, got, ok, err, want)
		}
	}
	for _, addr := range []string{"/missing", "/amt/missing", "/o/k/2", "/a/b/0", "/s/0", "s", "/amt/value/x"} {
		if _, ok, err := readField("json", body, addr); ok || err != nil {
			t.Errorf("json %q: ok=%v err=%v", addr, ok, err)
		}
	}
	if _, _, err := readField("json", []byte(`{"a":1,"a":2}`), "/a"); !errors.Is(err, errBody) {
		t.Errorf("json duplicate: %v", err)
	}

	form := []byte("referenceCode=ord+1%2F2&amount=65000&e=&card[number]={{pan}}&x[]=1&x[]=2&y[]=3")
	for addr, want := range map[string]fieldValue{
		"referenceCode": {"string", "ord 1/2"},
		"amount":        {"string", "65000"},
		"e":             {"string", ""},
		"card[number]":  {"string", "{{pan}}"},
		"y[]":           {"string", "3"},
	} {
		got, ok, err := readField("form", form, addr)
		if err != nil || !ok || got != want {
			t.Errorf("form %q: %+v ok=%v err=%v, want %+v", addr, got, ok, err, want)
		}
	}
	if _, ok, err := readField("form", form, "missing"); ok || err != nil {
		t.Errorf("form missing: ok=%v err=%v", ok, err)
	}
	if _, _, err := readField("form", form, "x[]"); !errors.Is(err, errBody) {
		t.Errorf("form repeated [] key: %v", err)
	}
	if _, _, err := readField("form", []byte("a=1&a=2"), "a"); !errors.Is(err, errBody) {
		t.Errorf("form duplicate: %v", err)
	}
	if _, _, err := readField("xml", form, "a"); !errors.Is(err, errBody) {
		t.Errorf("unknown format: %v", err)
	}
}

func TestEncodeValue(t *testing.T) {
	for _, c := range []struct {
		format, v string
		number    bool
		want      string
	}{
		{"json", "4242", false, `"4242"`},
		{"json", `Jo "Q" \ é`, false, `"Jo \"Q\" \\ é"`},
		{"json", "3", true, "3"},
		{"json", "03", true, "3"},
		{"json", "2030", true, "2030"},
		{"json", "0", true, "0"},
		{"json", "", true, `""`},
		{"json", "3a", true, `"3a"`},
		{"json", "-3", true, `"-3"`},
		{"form", "Jo Q&a=b", false, "Jo+Q%26a%3Db"},
		{"form", "03", true, "3"},
		{"form", "x y", true, "x+y"},
	} {
		if got := string(encodeValue(c.format, c.v, c.number)); got != c.want {
			t.Errorf("encodeValue(%s, %q, %v) = %s, want %s", c.format, c.v, c.number, got, c.want)
		}
	}
}

func TestSubstitute(t *testing.T) {
	body := `{"card":{"number":"{{pan}}","exp_month":"{{exp_month:int}}","name":"{{name}}"},"amount":100}`
	occs, err := scanBody("json", []byte(body))
	if err != nil {
		t.Fatalf("scanBody: %v", err)
	}
	repl := [][]byte{encodeValue("json", "4242", false), encodeValue("json", "03", true), encodeValue("json", `A "B"`, false)}
	got := substitute([]byte(body), occs, repl)
	want := `{"card":{"number":"4242","exp_month":3,"name":"A \"B\""},"amount":100}`
	if string(got) != want {
		t.Errorf("json substitute: %s", got)
	}
	if err := jsonStrict(got); err != nil {
		t.Errorf("substituted body is not strict JSON: %v", err)
	}

	form := "type=card&card[number]={{pan}}&card[exp_year]={{exp_year:int}}&x=%7Bok"
	occs, err = scanBody("form", []byte(form))
	if err != nil {
		t.Fatalf("scanBody: %v", err)
	}
	got = substitute([]byte(form), occs, [][]byte{encodeValue("form", "4242", false), encodeValue("form", "2030", true)})
	if string(got) != "type=card&card[number]=4242&card[exp_year]=2030&x=%7Bok" {
		t.Errorf("form substitute: %s", got)
	}

	// No occurrences: the body is returned unchanged (as a copy).
	in := []byte(`{"a":1}`)
	got = substitute(in, nil, nil)
	if string(got) != `{"a":1}` {
		t.Errorf("no occurrences: %s", got)
	}

	// Mismatched or out-of-order spans are a programming error and panic.
	for i, c := range []struct {
		occs []occurrence
		repl [][]byte
	}{
		{[]occurrence{{start: 0, end: 1}}, nil},
		{[]occurrence{{start: 2, end: 4}, {start: 3, end: 5}}, [][]byte{nil, nil}},
		{[]occurrence{{start: 3, end: 2}}, [][]byte{nil}},
		{[]occurrence{{start: 0, end: 99}}, [][]byte{nil}},
		{[]occurrence{{start: -1, end: 1}}, [][]byte{nil}},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("case %d did not panic", i)
				}
			}()
			substitute(in, c.occs, c.repl)
		}()
	}
}
