package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Fuzz targets
// ---------------------------------------------------------------------------
//
// Each target checks an invariant of the code under test, not just the absence of a panic. The
// f.Add seeds (and any files under testdata/fuzz/<Name>) run as ordinary tests in `go test`;
// `make fuzz` and `make fuzz-long` run the fuzzing engine on each target.
//
// Failure messages name the invariant and an index, never the input: an input may hold a PAN, and
// the fuzzing engine already saves a failing input under testdata/fuzz.

// fuzzFill returns the value a fuzz target substitutes for p: digits with a leading zero for the
// number forms (canonicalised by encodeValue), otherwise text that needs escaping in both
// formats (quotes, backslash, control and separator characters, multi-byte UTF-8, U+2028, and a
// placeholder-looking "{{pan}}", which is plain data once substituted).
func fuzzFill(p placeholder) (v string, number bool) {
	if p.isNumber() {
		return "07", true
	}
	return "Zoë \"Q\" \\ O'Neil\n\t&a=b;c+d %7B{{pan}}</x>\u2028日本", false
}

// checkScanResult checks the occurrences scanBody returned for body in format: in order and
// in range, each span slicing to exactly the placeholder text ('"'-quoted for json), each address
// reading back as that placeholder, form addresses canonical, and the body with every occurrence
// substituted strictly valid in format, with each address now reading back as its value.
func checkScanResult(t *testing.T, format string, body []byte, occs []occurrence) {
	t.Helper()
	repl := make([][]byte, len(occs))
	want := make([]fieldValue, len(occs))
	prev := 0
	for i, o := range occs {
		if o.start < prev || o.end < o.start || o.end > len(body) {
			t.Fatalf("occurrence %d: span out of order or out of range", i)
		}
		prev = o.end
		raw := o.ph.String()
		if format == "json" {
			raw = `"` + raw + `"`
		}
		if string(body[o.start:o.end]) != raw {
			t.Fatalf("occurrence %d: span does not slice to exactly the placeholder", i)
		}
		if p, ok := parsePlaceholder(o.ph.String()); !ok || p != o.ph {
			t.Fatalf("occurrence %d: placeholder does not round-trip", i)
		}
		if format == "form" && !validFormKey(o.addr) {
			t.Fatalf("occurrence %d: address is not a canonical form key", i)
		}
		got, found, err := readField(format, body, o.addr)
		if err != nil || !found || got != (fieldValue{kind: "string", text: o.ph.String()}) {
			t.Fatalf("occurrence %d: address does not read back as the placeholder", i)
		}
		v, number := fuzzFill(o.ph)
		repl[i] = encodeValue(format, v, number)
		want[i] = fieldValue{kind: "string", text: v}
		if number {
			want[i].text = "7"
			if format == "json" {
				want[i].kind = "number"
			}
		}
	}
	out := substitute(body, occs, repl)
	switch format {
	case "json":
		if err := jsonStrict(out); err != nil {
			t.Fatalf("substituted body is not strict JSON")
		}
	case "form":
		if _, err := formFields(out); err != nil {
			t.Fatalf("substituted body is not a strict form")
		}
	}
	for i, o := range occs {
		got, found, err := readField(format, out, o.addr)
		if err != nil || !found || got != want[i] {
			t.Fatalf("occurrence %d: substituted value does not read back at its address", i)
		}
	}
}

// checkScanError checks that a failed scan returns no occurrences and one of the two scan errors.
func checkScanError(t *testing.T, occs []occurrence, err error) {
	t.Helper()
	if occs != nil {
		t.Fatal("occurrences returned with an error")
	}
	if !errors.Is(err, errBody) && !errors.Is(err, errPlaceholder) {
		t.Fatal("error is neither errBody nor errPlaceholder")
	}
}

func FuzzScanJSON(f *testing.F) {
	for _, s := range []string{
		// Valid bodies, with and without placeholders.
		`{"a":{"n":"{{pan}}","m":"{{exp_month:int}}"},"x/y":"{{cvv}}","arr":[{"k":"{{name}}"}]}`,
		" {\n\t\"d\\\"esc\" : \"caf\u00e9 \\u00e9 \\\"q\\\" \\\\ \\n \\ud83d\\ude00 \U0001F600\" ,\r\n" +
			"  \"~a/b\"  :  \"{{secret:k_1}}\" , \"\\u0061rr\" : [ 1 , 2.50 , true , null , { } , [ ] ,\n" +
			"  \"{{exp:mm/yy}}\" , [ \"{{signature}}\" ] ] , \"\" : \"{{basic:B}}\" } \n",
		`{"a":"b","c":[1,{"d":"{x}"}]}`,
		` "{{pan}}" `,
		`{"card":{"number":"{{pan}}","exp_month":"{{exp_month:int}}","name":"{{name}}"},"amount":100}`,
		`{"y":"{{exp_year}}","yy":"{{exp_year:yy}}","yi":"{{exp_year:int}}","e":"{{exp:yyyy/mm}}"}`,
		"{\"k\\u00e9y\":[\"a\\\"b\",\"\\ud83d\\ude00\",\"\u65e5\u672c\",{\"x\" :\"\\/\\b\\f\\n\\r\\t\"}], \"n\":-1.5e+3}",
		`{"a":1}`, `[]`, `"x"`, `1`, `true`, `null`, `{"a":{"b":1},"c":{"b":1}}`, `{"é":1,"e":2}`,
		`{"a":"\ufffe"}`, `{"a\u007f ":"\u0000\n"}`,
		strings.Repeat("[", maxJSONDepth) + strings.Repeat("]", maxJSONDepth),
		// Escape-disguised placeholders, placeholders in keys, partial or unknown placeholders.
		`{"n":"\u007b\u007bpan}}"}`, `{"n":"{\u007bpan}}"}`, `{"n":"{{p\u0061n}}"}`, `{"n":"{{pan}\u007d"}`,
		`"\u007b\u007bpan}}"`, `{"{{pan}}":1}`, `{"a":{"x{{cvv}}y":"v"}}`, `{"\u007b\u007bpan}}":1}`,
		`{"n":"x{{pan}}"}`, `{"n":"{{pan}}x"}`, `{"n":"{{pan}}{{cvv}}"}`, `{"n":"{{exp_month}}/{{exp_year}}"}`,
		`{"n":"{{foo}}"}`, `{"n":"{{ pan }}"}`, `{"n":"{{pan"}`, `{"n":"{{"}`, `{"n":["ok","{{pan:int}}"]}`,
		// Duplicate keys (also after decoding escapes), trailing data, bad UTF-8, BOM, malformed.
		`{"a":1,"a":2}`, `[{"a":1},{"b":1,"b":1}]`, `{"a":1,"\u0061":2}`, `{"{{pan}}":1,"{{pan}}":2}`,
		`{"n":"{{pan}}"} {}`, `{}x`, `1 2`, `"a""b"`, "{\"a\":\"\xff\"}", "\xef\xbb\xbf{}", ``, `{`, `{"a":}`,
		`[1,]`, `[01]`, `NaN`, `"\x"`,
		// Control characters in keys, lone surrogates and U+FFFD, too deep.
		`{"merchantAccount":"a","merchantAccount\u0000":"b"}`, `{"a\tb":1}`, `"\ud800"`, `{"\udc00":1}`,
		`"\ufffd"`, strings.Repeat(`{"a":`, maxJSONDepth+1) + "1" + strings.Repeat("}", maxJSONDepth+1),
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		occs, err := scanBody("json", body)
		if err != nil {
			checkScanError(t, occs, err)
			return
		}
		checkScanResult(t, "json", body, occs)
	})
}

func FuzzScanForm(f *testing.F) {
	seeds := []string{
		// Valid bodies, with and without placeholders.
		"card[number]={{pan}}&type=card",
		"a%5Bb%5D=x+y%26&card[exp_month]={{exp_month:int}}&expand[]=a&expand[]=b&e=&card[cvc]={{cvv}}",
		"type=card&card[number]={{pan}}&card[exp_year]={{exp_year:int}}&x=%7Bok",
		"referenceCode=ord+1%2F2&amount=65000&e=&card[number]={{pan}}&x[]=1&x[]=2&y[]=3",
		"card[name]={{name}}&card[exp]={{exp:mm/yy}}&key={{secret:sk}}&sig={{signature}}",
		"", "expand[]=a&expand[]=b", "expand[]=a&expand[]=a&x=1",
		// Malformed.
		"&", "a=1&", "&a=1", "a=1&&b=2", "a", "a=1&b", "=1", "a=%zz", "%zz=1", "a=%", "a=1;b=2", "a=1 2",
		"a=\x00", "a=caf\xc3\xa9", "a=%ff", "a=%c3", "a=\x7f",
		// Disguised, misplaced or unknown placeholders.
		"n=%7B%7Bpan%7D%7D", "n={%7Bpan}}", "n={{p%61n}}", "{{pan}}=1", "%7B%7Bpan%7D%7D=1", "a[{{cvv}}]=1",
		"n=x{{pan}}", "n={{pan}}{{cvv}}", "n={{foo}}", "n={{+pan+}}", "n={{", "expand[]={{pan}}", "{{pan}}[]=x",
		"{{pan}}=1&a=2", "{{pan}}=1&customer]=2",
		// Duplicate keys and bracket aliases.
		"a=1&a=2", "card[number]={{pan}}&card[number]=4242", "a=1&%61=2", "card%5Bnumber%5D=1&card[number]=2",
		"customer]=x&customer=y", "customer=y&[customer=x", "a=1&a%00=2",
	}
	for _, k := range []string{
		"card[number]", "payment_method_data[card][exp_month]", "expand[]", "metadata[order_id]", "type",
		"items[0][price]", "x-y", "A_9", "a[b-c][]",
		"customer]", "[customer", "a[b]c", "a[[b]]", "a%00", "]]customer]]", "card[number]]", "a[]b", "a[][b]",
		"a[", "a]", "[]", "a[b", "a.b", "a+b", "a%20b", "a%0A", "a%7F", "caf%C3%A9", "a%5B%5Db", "a[b%00]",
	} {
		seeds = append(seeds, k+"=1", url.QueryEscape(k)+"={{pan}}")
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		occs, err := scanBody("form", body)
		if err != nil {
			checkScanError(t, occs, err)
			return
		}
		checkScanResult(t, "form", body, occs)
	})
}

func FuzzParsePlaceholder(f *testing.F) {
	for _, s := range []string{
		"{{pan}}", "{{cvv}}", "{{name}}", "{{exp_month}}", "{{exp_month:int}}", "{{exp_year}}", "{{exp_year:yy}}",
		"{{exp_year:int}}", "{{exp:yyyy/mm}}", "{{exp:mm/yy}}", "{{secret:secretKey}}", "{{secret:A_9}}",
		"{{secret:" + strings.Repeat("a", 64) + "}}", "{{basic:apiKey}}", "{{signature}}",
		"{{ pan }}", "{{pan:int}}", "{{exp_year:yyyy}}", "{{secret:}}", "{{secret:a b}}", "{{foo}}", "{pan}",
		"", "{{}}", "{{pan}", "{pan}}", "{{{pan}}}", "{{PAN}}", "{{pan}} ", " {{pan}}", "{{pan:}}",
		"{{cvv:int}}", "{{name:x}}", "{{signature:x}}", "{{exp}}", "{{exp:}}", "{{exp:yy/mm}}",
		"{{exp_month:}}", "{{exp_month:yy}}", "{{exp_year:}}", "{{secret}}", "{{basic}}", "{{basic:}}",
		"{{secret:" + strings.Repeat("a", 65) + "}}", "{{secret:a-b}}", "{{secret:a:b}}", "{{secret:a/b}}",
		"{{secret:é}}", "{{pan}}{{cvv}}", "{{exp_month:int:int}}", "{{secret:{{pan}}}}",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, ok := parsePlaceholder(s)
		if !ok {
			if p != (placeholder{}) {
				t.Fatal("rejected text returned a non-zero placeholder")
			}
			return
		}
		if q, ok := parsePlaceholder(p.String()); !ok || q != p {
			t.Fatal("parsePlaceholder(p.String()) != p")
		}
		if p.String() != s {
			t.Fatal("accepted text is not the canonical form")
		}
		if strings.LastIndex(s, "{{") != 0 {
			t.Fatal("accepted text contains a \"{{\" other than the leading one")
		}
	})
}

// panForms returns pan, pan grouped in fours from the left with single spaces, and with single
// hyphens: the forms a provider response may echo.
func panForms(pan string) [3]string {
	var spaced, hyphen []byte
	for i := 0; i < len(pan); i++ {
		if i > 0 && i%4 == 0 {
			spaced = append(spaced, ' ')
			hyphen = append(hyphen, '-')
		}
		spaced = append(spaced, pan[i])
		hyphen = append(hyphen, pan[i])
	}
	return [3]string{pan, string(spaced), string(hyphen)}
}

// fuzzPAN turns s into a 13–19-digit Luhn-valid PAN: s itself when it already is one, otherwise
// its first 12–18 ASCII digits plus the Luhn check digit. ok is false when s has fewer than 12
// digits. Every valid PAN is reachable, so the fuzzer explores PANs instead of rarely hitting one.
func fuzzPAN(s string) (string, bool) {
	if len(s) >= 13 && len(s) <= 19 && luhnValid(s) {
		return s, true
	}
	var d []byte
	for i := 0; i < len(s) && len(d) < 18; i++ {
		if s[i] >= '0' && s[i] <= '9' {
			d = append(d, s[i])
		}
	}
	if len(d) < 12 {
		return "", false
	}
	for c := byte('0'); c <= '9'; c++ {
		if luhnValid(string(d) + string(c)) {
			return string(d) + string(c), true
		}
	}
	return "", false // unreachable: exactly one check digit makes any digit string Luhn-valid
}

func FuzzMaskPAN(f *testing.F) {
	amex := "378282246310005"
	for _, c := range []struct{ body, pan string }{
		{`{"n":"4242424242424242","f":"4242 4242 4242 4242"}`, testPAN},
		{amex + " x " + amex + " y 3782 8224 6310 005", amex},
		{`{"id":"pm_123","last4":"4242","n":"4242 4242 4242"}`, testPAN},
		{`{"f":"4242-4242-4242-4242","a":"3782-8224-6310-005"}`, testPAN},
		{"x 3782-8224-6310-005 y", amex},
		{testPAN + testPAN[4:], testPAN},
		{testPAN + testPAN[4:] + testPAN[4:], testPAN},
		{"4242 4242 4242 4242 4242 4242 4242", testPAN},
		{"4242-4242-4242-4242-4242-4242-4242", testPAN},
		{"4242 4242-4242 4242", testPAN},
		{"x 99" + testPAN + "77 y", testPAN},
		{"4222222222222" + "2222222222", "4222222222222"},
		{"4000000000000000006", "4000000000000000006"},
		{"", testPAN},
	} {
		f.Add([]byte(c.body), c.pan)
	}
	f.Fuzz(func(t *testing.T, body []byte, s string) {
		pan, ok := fuzzPAN(s)
		if !ok {
			return
		}
		in := bytes.Clone(body)
		forms := panForms(pan)
		had := false
		for _, form := range forms {
			had = had || bytes.Contains(in, []byte(form))
		}
		out, found := maskPAN(body, pan)
		for i, form := range forms {
			if bytes.Contains(out, []byte(form)) {
				t.Fatalf("output still contains PAN form %d", i)
			}
		}
		if found != had {
			t.Fatalf("found=%v, but the input contained a PAN form: %v", found, had)
		}
		if !found && !bytes.Equal(out, in) {
			t.Fatal("nothing found, but the body changed")
		}
	})
}

func FuzzParseCatalog(f *testing.F) {
	f.Add([]byte(testCatalogJSON))
	f.Add(catalogJSON)
	for _, m := range catalogMutations() {
		if data, ok := m.apply(); ok {
			f.Add([]byte(data))
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, env := range []string{"dev", "prod"} {
			c, err := parseCatalog(data, env)
			if err != nil {
				if c != nil {
					t.Fatal("catalog returned with an error")
				}
				continue
			}
			for name, p := range c.providers {
				for i, e := range p.endpoints {
					pan := false
					for _, ph := range e.positions {
						pan = pan || ph == (placeholder{kind: "pan"})
					}
					if !pan || !e.cardData {
						t.Fatalf("provider %s endpoint %d: accepted without card_data and a {{pan}} position", name, i)
					}
				}
			}
			for name, a := range c.accounts {
				if a.env != env || c.providers[a.provider] == nil {
					t.Fatalf("account %s: kept for another environment or with an unknown provider", name)
				}
			}
		}
	})
}

func FuzzCheckSession(f *testing.F) {
	now := testNow
	ok := func(exp time.Time) string { return "Bearer " + mintSession(testHMACKey, exp) }
	valid := ok(now.Add(time.Minute))
	for _, s := range []string{
		valid, ok(now.Add(15 * time.Minute)), ok(now.Add(time.Second)), ok(now.Add(15*time.Minute + time.Second)),
		ok(now), ok(now.Add(-time.Second)), signRaw("9223372036854775807"),
		"Bearer " + mintSession(bytes.Repeat([]byte{1}, 32), now.Add(time.Minute)),
		mintSession(testHMACKey, now.Add(time.Minute)), "bearer " + mintSession(testHMACKey, now.Add(time.Minute)),
		"Bearer  " + mintSession(testHMACKey, now.Add(time.Minute)), valid + " ", "", "Bearer ",
		strings.Replace(valid, "v1.", "v2.", 1), strings.Replace(valid, "v1.", "V1.", 1), valid + ".x",
		"Bearer v1." + strconv.FormatInt(now.Unix()+60, 10), upperMAC(valid), valid[:len(valid)-1], valid + "0",
		signedExp(now.Add(time.Minute)), signRaw(""), signRaw("10000000000000000000"),
		signRaw("9999999999999999999"), signRaw("17x"), signRaw("１７"),
		signRaw("000" + strconv.FormatInt(now.Unix()+60, 10)),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, authz string) {
		got := checkSession(testHMACKey, authz, now)
		switch got {
		case "", "format", "hmac", "expired":
		default:
			t.Fatal("checkSession returned an unknown reason")
		}
		if checkSession(nil, authz, now) == "" || checkSession(testHMACKey[:31], authz, now) == "" {
			t.Fatal("a key shorter than 32 bytes authenticated a token")
		}
		if got != "" {
			return
		}
		// Accepted: authz must be exactly a correctly signed token whose expiry is in the window.
		rest, _ := strings.CutPrefix(authz, "Bearer v1.")
		exp, _, _ := strings.Cut(rest, ".")
		m := hmac.New(sha256.New, testHMACKey)
		m.Write([]byte("v1." + exp))
		n, err := strconv.ParseInt(exp, 10, 64)
		if authz != "Bearer v1."+exp+"."+hex.EncodeToString(m.Sum(nil)) || strings.Trim(exp, "0123456789") != "" ||
			err != nil || n <= now.Unix() || n > now.Unix()+sessionMaxAhead {
			t.Fatal("accepted a token that is not a correctly signed v1 token within the window")
		}
	})
}

func FuzzNormalizePAN(f *testing.F) {
	for _, s := range []string{
		"4242 4242 4242 4242", "4242-4242-4242-4242", "4242424242424242", "4222222222222", "6200000000000005",
		"4000000000000000006", "4000056655665556", "5555555555554444", "378282246310005", "6011111111111117",
		"424242424242", "42424242424242424242", "4242a42424242424", "4242424242424241", "4242\t4242424242424242",
		"", " - ", "４２４２４２４２４２４２４２４２", "4242.4242.4242.4242", "+4242424242424242", "1234567890123",
		"--4242 4242-4242 4242--",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, ok := normalizePAN(s)
		if !ok {
			if got != "" {
				t.Fatal("rejected input returned a non-empty result")
			}
			return
		}
		if len(got) < 13 || len(got) > 19 || strings.Trim(got, "0123456789") != "" || !luhnValid(got) {
			t.Fatal("accepted result is not 13-19 ASCII digits passing Luhn")
		}
		if got != strings.NewReplacer(" ", "", "-", "").Replace(s) {
			t.Fatal("accepted result is not the input with spaces and hyphens removed")
		}
	})
}
