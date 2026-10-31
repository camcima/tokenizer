package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"math"
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// testReceiptKey is the fixed test-only signing key derived from testReceiptSeed, so receipts are
// reproducible and match the key every test vault signs with.
var testReceiptKey = ed25519.NewKeyFromSeed(testReceiptSeed)

func testReceiptPub() ed25519.PublicKey { return testReceiptKey.Public().(ed25519.PublicKey) }

func testReceipt() receipt {
	return receipt{
		Token:    "tok_0123456789abcdef0123456789abcdef",
		BIN:      "42424242",
		Last4:    "4242",
		ExpMonth: "12",
		ExpYear:  "2030",
		IAT:      1793456789,
	}
}

// signRawReceipt signs arbitrary prefix and payload part bytes with the test key, so a test can
// build receipts the vault would never produce and check that only the intended rule rejects them.
func signRawReceipt(prefix, payloadPart string) string {
	sig := ed25519.Sign(testReceiptKey, []byte(prefix+payloadPart))
	return prefix + payloadPart + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// receiptPayload returns the decoded payload of a receipt produced by signReceipt.
func receiptPayload(t *testing.T, s string) []byte {
	t.Helper()
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		t.Fatalf("receipt has %d parts", len(parts))
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal("payload part does not decode")
	}
	return b
}

func TestReceiptBIN(t *testing.T) {
	cases := []struct{ pan, want string }{
		{"4242424242424242", "42424242"},  // 16 digits
		{"4222222222222", "422222"},       // 13 digits
		{"30569309025904", "305693"},      // 14 digits
		{"378282246310005", "378282"},     // 15 digits
		{"62000000000000017", "620000"},   // 17 digits
		{"620000000000000017", "620000"},  // 18 digits
		{"4000000000000000006", "400000"}, // 19 digits
	}
	for i, c := range cases {
		got := cardBIN(c.pan)
		if got != c.want {
			t.Errorf("case %d (len %d): bin length %d, want %d", i, len(c.pan), len(got), len(c.want))
		}
		if !strings.HasPrefix(c.pan, got) {
			t.Errorf("case %d (len %d): bin is not a prefix of the card number", i, len(c.pan))
		}
		if len(got)+4 > 12 {
			t.Errorf("case %d (len %d): bin plus last4 exposes %d digits", i, len(c.pan), len(got)+4)
		}
		if len(got)+4 >= len(c.pan) {
			t.Errorf("case %d (len %d): bin plus last4 covers the whole card number", i, len(c.pan))
		}
	}
}

func TestReceiptRoundTrip(t *testing.T) {
	in := testReceipt()
	s := signReceipt(testReceiptKey, in)
	if !strings.HasPrefix(s, receiptPrefix) || !strings.HasPrefix(s, "rcpt.v1.") {
		t.Fatal("receipt does not start with rcpt.v1.")
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		t.Fatalf("receipt has %d parts, want 4", len(parts))
	}
	b64url := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	for _, i := range []int{2, 3} {
		if !b64url.MatchString(parts[i]) {
			t.Errorf("part %d is not unpadded base64url", i)
		}
	}
	got, ok := verifyReceipt(testReceiptPub(), s)
	if !ok {
		t.Fatal("valid receipt rejected")
	}
	if got != in {
		t.Errorf("decoded receipt differs from the signed one")
	}
	if p := receiptPayload(t, s); bytes.HasSuffix(p, []byte("\n")) {
		t.Error("payload ends with a newline")
	}
}

func TestReceiptNameRoundTrip(t *testing.T) {
	for i, name := range []string{"José Ñúñez", "O'Brien & Sons <x>"} {
		in := testReceipt()
		in.Name = name
		s := signReceipt(testReceiptKey, in)
		got, ok := verifyReceipt(testReceiptPub(), s)
		if !ok {
			t.Errorf("case %d: valid receipt rejected", i)
			continue
		}
		if got.Name != name {
			t.Errorf("case %d: name changed in the round trip", i)
		}
		p := receiptPayload(t, s)
		if !bytes.Contains(p, []byte(name)) {
			t.Errorf("case %d: payload does not carry the name bytes verbatim", i)
		}
		if bytes.Contains(p, []byte(`\u00`)) {
			t.Errorf("case %d: payload contains escaped characters", i)
		}
	}
	p, err := encodeReceipt(receipt{Name: "O'Brien & Sons <x>"})
	if err != nil {
		t.Fatal("encodeReceipt failed")
	}
	for _, c := range []string{"&", "<", ">"} {
		if !bytes.Contains(p, []byte(c)) {
			t.Errorf("payload lacks a raw %q", c)
		}
	}
}

func TestReceiptOmitsEmptyName(t *testing.T) {
	p, err := encodeReceipt(testReceipt())
	if err != nil {
		t.Fatal("encodeReceipt failed")
	}
	if bytes.Contains(p, []byte(`"name"`)) {
		t.Error("payload has a name key for a card without a name")
	}
	want := `{"token":"tok_0123456789abcdef0123456789abcdef","bin":"42424242","last4":"4242",` +
		`"exp_month":"12","exp_year":"2030","iat":1793456789}`
	if string(p) != want {
		t.Errorf("payload (len %d) is not the compact JSON in key order", len(p))
	}
	if p := receiptPayload(t, signReceipt(testReceiptKey, testReceipt())); bytes.Contains(p, []byte(`"name"`)) {
		t.Error("signed payload has a name key for a card without a name")
	}
}

func TestVerifyReceiptRejects(t *testing.T) {
	in := testReceipt()
	in.Name = "Zoë Ångström" // its payload encodes with "-" or "_" and a length that is not a multiple of 3
	good := signReceipt(testReceiptKey, in)
	parts := strings.Split(good, ".")
	payloadPart, sigPart := parts[2], parts[3]
	payload, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		t.Fatal("payload part does not decode")
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil {
		t.Fatal("signature part does not decode")
	}

	otherPub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)).Public().(ed25519.PublicKey)

	tampered := bytes.Replace(payload, []byte(`"last4":"4242"`), []byte(`"last4":"4243"`), 1)
	if bytes.Equal(tampered, payload) {
		t.Fatal("tamper target not found in payload")
	}
	if !bytes.Contains(payload, []byte(`"name":"`+in.Name+`"`)) {
		t.Fatal("name not found in payload")
	}
	flippedSig := bytes.Clone(sig)
	flippedSig[0] ^= 1

	stdPart := base64.StdEncoding.EncodeToString(payload)
	if !strings.ContainsAny(stdPart, "+/") {
		t.Fatal("standard encoding of the test payload has no '+' or '/'")
	}
	if !strings.HasSuffix(base64.URLEncoding.EncodeToString(payload), "=") {
		t.Fatal("padded encoding of the test payload has no '='")
	}

	unknownKey := base64.RawURLEncoding.EncodeToString(bytes.Replace(payload, []byte(`{`), []byte(`{"extra":1,`), 1))
	enc := base64.RawURLEncoding.EncodeToString
	// The trailing character of an unpadded base64url string can carry unused low bits; setting
	// them gives a second spelling of the same bytes, which must not verify as a distinct receipt.
	nonCanonical := []byte(payloadPart)
	if len(payload)%3 == 0 {
		t.Fatal("test payload length leaves no unused bits")
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, nonCanonical[len(nonCanonical)-1])
	nonCanonical[len(nonCanonical)-1] = alphabet[last^1]
	if b, err := base64.RawURLEncoding.DecodeString(string(nonCanonical)); err != nil || !bytes.Equal(b, payload) {
		t.Fatal("non-canonical spelling does not decode to the same payload under lenient decoding")
	}

	p := testReceiptPub()
	cases := []struct {
		name string
		pub  ed25519.PublicKey
		s    string
	}{
		{"wrong public key", otherPub, good},
		{"short public key", p[:16], good},
		{"nil public key", nil, good},
		{"tampered payload byte", p, receiptPrefix + enc(tampered) + "." + sigPart},
		{"flipped signature byte", p, receiptPrefix + payloadPart + "." + enc(flippedSig)},
		{"truncated signature", p, receiptPrefix + payloadPart + "." + enc(sig[:63])},
		{"empty signature", p, receiptPrefix + payloadPart + "."},
		{"version v2, old signature", p, "rcpt.v2." + payloadPart + "." + sigPart},
		{"version v2, re-signed", p, signRawReceipt("rcpt.v2.", payloadPart)},
		{"prefix foo, re-signed", p, signRawReceipt("foo.v1.", payloadPart)},
		{"uppercase prefix, re-signed", p, signRawReceipt("RCPT.v1.", payloadPart)},
		{"three parts", p, "rcpt.v1." + payloadPart},
		{"five parts", p, good + ".x"},
		{"five parts, empty tail", p, good + "."},
		{"padded payload, re-signed", p, signRawReceipt(receiptPrefix, base64.URLEncoding.EncodeToString(payload))},
		{"padded signature", p, receiptPrefix + payloadPart + "." + base64.URLEncoding.EncodeToString(sig)},
		{"standard encoding, re-signed", p, signRawReceipt(receiptPrefix, base64.RawStdEncoding.EncodeToString(payload))},
		{"newline in payload part, re-signed", p, signRawReceipt(receiptPrefix, payloadPart[:4]+"\n"+payloadPart[4:])},
		{"newline in signature part", p, receiptPrefix + payloadPart + "." + sigPart[:4] + "\r\n" + sigPart[4:]},
		{"non-canonical payload bits, re-signed", p, signRawReceipt(receiptPrefix, string(nonCanonical))},
		{"unknown key, re-signed", p, signRawReceipt(receiptPrefix, unknownKey)},
		{"case-folded key, re-signed", p, signRawReceipt(receiptPrefix,
			enc(bytes.Replace(payload, []byte(`"last4"`), []byte(`"LAST4"`), 1)))},
		{"duplicate key, re-signed", p, signRawReceipt(receiptPrefix,
			enc(bytes.Replace(payload, []byte(`{`), []byte(`{"last4":"0000",`), 1)))},
		{"trailing data, re-signed", p, signRawReceipt(receiptPrefix, enc(append(bytes.Clone(payload), []byte(" {}")...)))},
		{"missing key, re-signed", p, signRawReceipt(receiptPrefix,
			enc([]byte(`{"token":"tok_0123456789abcdef0123456789abcdef","bin":"42424242","last4":"4242","exp_month":"12","iat":1}`)))},
		{"null value, re-signed", p, signRawReceipt(receiptPrefix,
			enc(bytes.Replace(payload, []byte(`"exp_year":"2030"`), []byte(`"exp_year":null`), 1)))},
		{"empty name, re-signed", p, signRawReceipt(receiptPrefix,
			enc(bytes.Replace(payload, []byte(`"name":"`+in.Name+`"`), []byte(`"name":""`), 1)))},
		{"null name, re-signed", p, signRawReceipt(receiptPrefix,
			enc(bytes.Replace(payload, []byte(`"name":"`+in.Name+`"`), []byte(`"name":null`), 1)))},
		{"wrong value type, re-signed", p, signRawReceipt(receiptPrefix,
			enc(bytes.Replace(payload, []byte(`"iat":1793456789`), []byte(`"iat":"1793456789"`), 1)))},
		{"json null payload, re-signed", p, signRawReceipt(receiptPrefix, enc([]byte("null")))},
		{"json array payload, re-signed", p, signRawReceipt(receiptPrefix, enc([]byte("[]")))},
		{"empty object payload, re-signed", p, signRawReceipt(receiptPrefix, enc([]byte("{}")))},
		{"empty payload, re-signed", p, signRawReceipt(receiptPrefix, "")},
		{"invalid json, re-signed", p, signRawReceipt(receiptPrefix, enc([]byte(`{"token":`)))},
		{"empty string", p, ""},
		{"dots only", p, "..."},
		{"prefix only", p, receiptPrefix},
	}
	for _, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: verifyReceipt panicked", c.name)
				}
			}()
			if got, ok := verifyReceipt(c.pub, c.s); ok || got != (receipt{}) {
				t.Errorf("%s: accepted (ok=%v) or returned a non-zero receipt", c.name, ok)
			}
		}()
	}
}

// maxNameReceipt returns the longest receipt the vault can issue: a 100-rune name whose every rune
// JSON-escapes to six bytes (U+2028 is written as \u2028) and the largest iat.
func maxNameReceipt() receipt {
	r := testReceipt()
	r.Name = strings.Repeat("\u2028", 100)
	r.IAT = math.MaxInt64
	return r
}

func TestVerifyReceiptLengthCap(t *testing.T) {
	if n := base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize); n != 86 {
		t.Fatalf("a signature encodes to %d characters, want 86", n)
	}
	if !validName(maxNameReceipt().Name) {
		t.Fatal("the longest-encoding name is not a name the vault accepts")
	}
	longest := signReceipt(testReceiptKey, maxNameReceipt())
	if len(longest) > maxReceiptLen {
		t.Fatalf("the longest receipt the vault issues is %d bytes, over the %d-byte cap", len(longest), maxReceiptLen)
	}
	// receipt.go and the READMEs quote this figure.
	if len(longest) != 1097 {
		t.Fatalf("the longest receipt the vault issues is %d bytes, want the documented 1097", len(longest))
	}
	if got, ok := verifyReceipt(testReceiptPub(), longest); !ok || got != maxNameReceipt() {
		t.Fatal("the longest receipt the vault issues did not verify")
	}

	// A correctly signed receipt is accepted at the longest length up to the cap and rejected at
	// the shortest length over it (unpadded base64url never has a length of 4k+1, so not every
	// length occurs). The vault never issues one this long; the name is just a way to reach it.
	var under, over string
	for n := 1; over == ""; n++ {
		r := testReceipt()
		r.Name = strings.Repeat("a", n)
		if s := signReceipt(testReceiptKey, r); len(s) <= maxReceiptLen {
			under = s
		} else {
			over = s
		}
	}
	if len(under) < maxReceiptLen-1 || len(over) > maxReceiptLen+2 {
		t.Fatalf("receipts of %d and %d bytes do not bracket the %d-byte cap", len(under), len(over), maxReceiptLen)
	}
	if _, ok := verifyReceipt(testReceiptPub(), under); !ok {
		t.Errorf("a correctly signed receipt of %d bytes was rejected", len(under))
	}
	if _, ok := verifyReceipt(testReceiptPub(), over); ok {
		t.Errorf("a correctly signed receipt of %d bytes was accepted", len(over))
	}
}

// An oversized or wrongly sized signature part is rejected before it is scanned or decoded, so
// hostile input costs no allocation proportional to its size.
func TestVerifyReceiptSignatureBounds(t *testing.T) {
	good := signReceipt(testReceiptKey, testReceipt())
	parts := strings.Split(good, ".")
	payloadPart, sigPart := parts[2], parts[3]
	huge := receiptPrefix + payloadPart + "." + strings.Repeat("A", 8<<20)
	cases := []struct{ name, s string }{
		{"8 MiB signature part", huge},
		{"signature part of 87 characters", receiptPrefix + payloadPart + "." + sigPart + "A"},
		{"signature part of 85 characters", receiptPrefix + payloadPart + "." + sigPart[:85]},
	}
	for _, c := range cases {
		if _, ok := verifyReceipt(testReceiptPub(), c.s); ok {
			t.Errorf("%s: accepted", c.name)
		}
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range 4 {
		verifyReceipt(testReceiptPub(), huge)
	}
	runtime.ReadMemStats(&after)
	if n := after.TotalAlloc - before.TotalAlloc; n > 1<<20 {
		t.Errorf("rejecting an 8 MiB signature part allocated %d bytes", n)
	}
}

func TestReceiptSignatureCoversPrefix(t *testing.T) {
	s := signReceipt(testReceiptKey, testReceipt())
	payloadPart := strings.Split(s, ".")[2]
	bare := ed25519.Sign(testReceiptKey, []byte(payloadPart))
	forged := receiptPrefix + payloadPart + "." + base64.RawURLEncoding.EncodeToString(bare)
	if _, ok := verifyReceipt(testReceiptPub(), forged); ok {
		t.Error("signature over the bare payload part verified")
	}
	if _, ok := verifyReceipt(testReceiptPub(), signRawReceipt(receiptPrefix, payloadPart)); !ok {
		t.Error("signature over prefix and payload part did not verify")
	}
}

// readmeReceiptVerifier returns the fenced Go code of the "#### 11.4 " section of a README: the
// receipt verifier published for the platform. Lines are returned as written, fences excluded.
func readmeReceiptVerifier(doc string) (code string, blocks int) {
	var b strings.Builder
	inSection, inGo, inFence := false, false, false
	for _, line := range strings.Split(doc, "\n") {
		if !inFence && strings.HasPrefix(line, "#") {
			if inSection {
				break
			}
			inSection = strings.HasPrefix(line, "#### 11.4 ")
			continue
		}
		if !inSection {
			continue
		}
		if strings.HasPrefix(line, "```") {
			if !inFence {
				inFence, inGo = true, line == "```go"
				if inGo {
					blocks++
				}
			} else {
				inFence, inGo = false, false
			}
			continue
		}
		if inGo {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String(), blocks
}

// The receipt verifier published in the three READMEs is one piece of code: it must be the same
// in every language and keep the checks verifyReceipt relies on (length cap, bounded split, exact
// signature length, canonical base64url, signature over the prefixed payload part, no unknown
// keys).
func TestReadmeReceiptVerifier(t *testing.T) {
	want := []string{
		`strings.SplitN(s, ".", 5)`,
		`base64.RawURLEncoding.Strict()`,
		`ed25519.Verify(pub, []byte("rcpt.v1."+parts[2])`,
		`DisallowUnknownFields()`,
		`const maxReceiptLen = 2048`,
		`len(s) > maxReceiptLen`,
		`len(parts[3]) != 86`,
	}
	var first string
	for i, f := range []string{"README.md", "README.es.md", "README.pt-BR.md"} {
		doc, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		code, blocks := readmeReceiptVerifier(string(doc))
		if blocks == 0 {
			t.Fatalf("%s: no Go block in the receipt verifier section", f)
		}
		for _, w := range want {
			if !strings.Contains(code, w) {
				t.Errorf("%s: verifier lacks %s", f, w)
			}
		}
		if i == 0 {
			first = code
		} else if code != first {
			t.Errorf("%s: verifier differs from README.md", f)
		}
	}
}
