package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Test failure messages never print a PAN, expiry or CVV: they print a case index or a length.

func TestLuhn(t *testing.T) {
	for i, s := range []string{"4242424242424242", "4000056655665556", "5555555555554444",
		"378282246310005", "6011111111111117", "4222222222222", "6200000000000005"} {
		if !luhnValid(s) {
			t.Errorf("valid case %d (len %d) rejected", i, len(s))
		}
	}
	for i, s := range []string{"4242424242424241", "1234567890123", ""} {
		if luhnValid(s) {
			t.Errorf("invalid case %d (len %d) accepted", i, len(s))
		}
	}
}

func TestNormalizePAN(t *testing.T) {
	ok := []struct{ in, want string }{
		{"4242 4242 4242 4242", "4242424242424242"},
		{"4242-4242-4242-4242", "4242424242424242"},
		{"4242424242424242", "4242424242424242"},
		{"4222222222222", "4222222222222"},             // 13 digits
		{"6200000000000005", "6200000000000005"},       // 16 digits, non-Visa
		{"4000000000000000006", "4000000000000000006"}, // 19 digits
	}
	for i, c := range ok {
		got, valid := normalizePAN(c.in)
		if !valid {
			t.Errorf("ok case %d (len %d) rejected", i, len(c.in))
			continue
		}
		if got != c.want {
			t.Errorf("ok case %d: normalized len %d, want len %d (or digits differ)", i, len(got), len(c.want))
		}
	}

	reject := []string{
		"424242424242",           // 12 digits
		"42424242424242424242",   // 20 digits
		"4242a42424242424",       // letter
		"4242424242424241",       // Luhn failure
		"4242\t4242424242424242", // tab is not stripped
		"",                       // empty
		" - ",                    // separators only
		"４２４２４２４２４２４２４２４２",    // full-width digits
		"4242.4242.4242.4242", // dot is not stripped
		"+4242424242424242",   // sign
	}
	for i, s := range reject {
		if got, valid := normalizePAN(s); valid || got != "" {
			t.Errorf("reject case %d (len %d) accepted or returned non-empty", i, len(s))
		}
	}
}

func TestValidExpiry(t *testing.T) {
	now := time.Date(2026, 10, 30, 15, 4, 5, 0, time.UTC)
	ok := []struct{ m, y string }{
		{"10", "2026"}, // current month
		{"12", "2026"},
		{"01", "2027"},
		{"01", "2030"},
	}
	for i, c := range ok {
		if !validExpiry(c.m, c.y, now) {
			t.Errorf("ok case %d rejected", i)
		}
	}
	reject := []struct{ m, y string }{
		{"09", "2026"}, // last month
		{"12", "2025"}, // last year
		{"1", "2030"},
		{"13", "2030"},
		{"00", "2030"},
		{"12", "30"},
		{"12", "20301"},
		{"1a", "2030"},
		{"", ""},
		{"12", ""},
		{"", "2030"},
		{" 1", "2030"},
		{"12", "２０３０"},
	}
	for i, c := range reject {
		if validExpiry(c.m, c.y, now) {
			t.Errorf("reject case %d accepted", i)
		}
	}
}

// The month comparison is done in UTC: 2026-11-01 00:30 in UTC+02:00 is still October in UTC.
func TestValidExpiryUsesUTC(t *testing.T) {
	loc := time.FixedZone("UTC+2", 2*3600)
	now := time.Date(2026, 11, 1, 0, 30, 0, 0, loc) // == 2026-10-31 22:30 UTC
	if !validExpiry("10", "2026", now) {
		t.Error("current UTC month rejected when local zone is already in the next month")
	}
}

func TestValidCVV(t *testing.T) {
	for i, s := range []string{"123", "1234", "000"} {
		if !validCVV(s) {
			t.Errorf("ok case %d rejected", i)
		}
	}
	for i, s := range []string{"12", "12345", "12a", "", " 123", "１２３"} {
		if validCVV(s) {
			t.Errorf("reject case %d accepted", i)
		}
	}
}

func TestTokenFormatAndUniqueness(t *testing.T) {
	seen := make(map[string]bool, 100000)
	for i := 0; i < 100000; i++ {
		tok := newToken()
		if !tokenRe.MatchString(tok) {
			t.Fatalf("bad token format %q", tok)
		}
		if seen[tok] {
			t.Fatal("duplicate token")
		}
		seen[tok] = true
	}
}

func TestTokenRe(t *testing.T) {
	for i, s := range []string{
		"tok_" + strings.Repeat("A", 32), // uppercase hex
		"tok_" + strings.Repeat("a", 31),
		"tok_" + strings.Repeat("a", 33),
		"tok_" + strings.Repeat("g", 32),
		"TOK_" + strings.Repeat("a", 32),
		"tok_" + strings.Repeat("a", 32) + "\n",
		"",
	} {
		if tokenRe.MatchString(s) {
			t.Errorf("reject case %d matched", i)
		}
	}
}

func testDEK(t *testing.T) []byte {
	t.Helper()
	dek := make([]byte, 32)
	rand.Read(dek)
	return dek
}

func TestSealUnseal(t *testing.T) {
	dek := testDEK(t)
	pt := []byte(`{"pan":"4242424242424242","exp_month":"12","exp_year":"2030"}`)

	blob := seal(dek, pt)
	if len(blob) != 12+len(pt)+16 {
		t.Fatalf("blob len %d, want %d", len(blob), 12+len(pt)+16)
	}
	if bytes.Contains(blob, []byte("4242424242424242")) {
		t.Fatal("blob contains plaintext PAN")
	}
	got, err := unseal(dek, blob)
	if err != nil {
		t.Fatal("round trip unseal failed")
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round trip mismatch (got len %d, want len %d)", len(got), len(pt))
	}

	// Empty plaintext round-trips too.
	if got, err := unseal(dek, seal(dek, nil)); err != nil || len(got) != 0 {
		t.Fatal("empty plaintext round trip failed")
	}

	// Tampering with the nonce, the ciphertext, or the tag is detected.
	for _, off := range []int{0, 20, len(blob) - 1} {
		bad := bytes.Clone(blob)
		bad[off] ^= 0x01
		if _, err := unseal(dek, bad); err == nil {
			t.Errorf("tampered byte at offset %d accepted", off)
		}
	}

	// Wrong DEK.
	if _, err := unseal(testDEK(t), blob); err == nil {
		t.Error("wrong DEK accepted")
	}

	// Truncated blobs (shorter than nonce+tag) return an error, not a panic.
	for n := 0; n < 28; n++ {
		if _, err := unseal(dek, blob[:n]); err == nil {
			t.Errorf("blob of len %d accepted", n)
		}
	}
	if _, err := unseal(dek, nil); err == nil {
		t.Error("nil blob accepted")
	}
	// Truncated by one byte (tag damaged).
	if _, err := unseal(dek, blob[:len(blob)-1]); err == nil {
		t.Error("blob truncated by one byte accepted")
	}

	// Non-AES-256 keys are refused by unseal.
	for _, n := range []int{0, 16, 24, 31, 33} {
		if _, err := unseal(make([]byte, n), blob); err == nil {
			t.Errorf("DEK of len %d accepted", n)
		}
	}

	// Errors never carry plaintext or key material: they are static strings.
	if _, err := unseal(dek, blob[:5]); err == nil || strings.Contains(err.Error(), "4242") {
		t.Error("unexpected error text")
	}

	// A fresh random nonce per seal.
	nonces := make(map[string]bool, 10000)
	for i := 0; i < 10000; i++ {
		b := seal(dek, pt)
		nonces[string(b[:12])] = true
	}
	if len(nonces) != 10000 {
		t.Fatalf("got %d distinct nonces from 10000 seals", len(nonces))
	}
}

func TestSealRejectsNonAES256Key(t *testing.T) {
	for _, n := range []int{0, 16, 24, 31, 33} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("seal with DEK of len %d did not panic", n)
				}
			}()
			seal(make([]byte, n), []byte("x"))
		}()
	}
}

// The sealed plaintext is exactly json.Marshal(card{PAN, ExpMonth, ExpYear}) with these keys
// and no CVV (§8.1); it must round-trip through seal/unseal.
func TestCardJSONSealRoundTrip(t *testing.T) {
	c := card{PAN: "4242424242424242", ExpMonth: "12", ExpYear: "2030"}
	pt, err := json.Marshal(c)
	if err != nil {
		t.Fatal("marshal failed")
	}
	if want := `{"pan":"4242424242424242","exp_month":"12","exp_year":"2030"}`; string(pt) != want {
		t.Fatalf("card JSON shape differs (len %d, want len %d)", len(pt), len(want))
	}
	dek := testDEK(t)
	out, err := unseal(dek, seal(dek, pt))
	if err != nil {
		t.Fatal("unseal failed")
	}
	var got card
	if err := json.Unmarshal(out, &got); err != nil || got != c {
		t.Fatal("card did not round-trip")
	}
	zero(pt)
	zero(out)
}

func TestZero(t *testing.T) {
	b := []byte("4242424242424242")
	zero(b)
	for i, c := range b {
		if c != 0 {
			t.Fatalf("byte %d not zeroed", i)
		}
	}
	zero(nil) // must not panic
}
