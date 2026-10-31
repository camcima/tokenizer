package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

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

// validName: 1–100 runes (not bytes), valid UTF-8, no control rune. Failure messages print
// only case indexes.
func TestValidName(t *testing.T) {
	for i, s := range []string{
		"J",
		"JANE Q DOE",
		"José Ñúñez",
		"O'Brien-Smith",
		strings.Repeat("a", 100),
		strings.Repeat("é", 100), // 100 runes, 200 bytes
		strings.Repeat("😀", 100), // 100 runes, 400 bytes
	} {
		if !validName(s) {
			t.Errorf("ok case %d rejected", i)
		}
	}
	for i, s := range []string{
		"",
		strings.Repeat("a", 101),
		strings.Repeat("é", 101),
		strings.Repeat("😀", 101),
		"a\u0007b",
		"a\x00b",
		"a\tb",
		"a\nb",
		"a\rb",
		"a\x7fb",       // DEL
		"a\u0085b",     // C1 control (NEL)
		"a\u009fb",     // C1 control
		"Jos\xff",      // invalid UTF-8
		"Jos\xc3",      // truncated multi-byte sequence
		"Jos\uFFFD",    // what encoding/json makes of invalid UTF-8
		"\xed\xa0\x80", // UTF-8-encoded surrogate
	} {
		if validName(s) {
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

	blob := seal(dek, pt, nil)
	if len(blob) != 12+len(pt)+16 {
		t.Fatalf("blob len %d, want %d", len(blob), 12+len(pt)+16)
	}
	if bytes.Contains(blob, []byte("4242424242424242")) {
		t.Fatal("blob contains plaintext PAN")
	}
	got, err := unseal(dek, blob, nil)
	if err != nil {
		t.Fatal("round trip unseal failed")
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round trip mismatch (got len %d, want len %d)", len(got), len(pt))
	}

	// Empty plaintext round-trips too.
	if got, err := unseal(dek, seal(dek, nil, nil), nil); err != nil || len(got) != 0 {
		t.Fatal("empty plaintext round trip failed")
	}

	// Tampering with the nonce, the ciphertext, or the tag is detected.
	for _, off := range []int{0, 20, len(blob) - 1} {
		bad := bytes.Clone(blob)
		bad[off] ^= 0x01
		if _, err := unseal(dek, bad, nil); err == nil {
			t.Errorf("tampered byte at offset %d accepted", off)
		}
	}

	// Wrong DEK.
	if _, err := unseal(testDEK(t), blob, nil); err == nil {
		t.Error("wrong DEK accepted")
	}

	// Truncated blobs (shorter than nonce+tag) return an error, not a panic.
	for n := 0; n < 28; n++ {
		if _, err := unseal(dek, blob[:n], nil); err == nil {
			t.Errorf("blob of len %d accepted", n)
		}
	}
	if _, err := unseal(dek, nil, nil); err == nil {
		t.Error("nil blob accepted")
	}
	// Truncated by one byte (tag damaged).
	if _, err := unseal(dek, blob[:len(blob)-1], nil); err == nil {
		t.Error("blob truncated by one byte accepted")
	}

	// Non-AES-256 keys are refused by unseal.
	for _, n := range []int{0, 16, 24, 31, 33} {
		if _, err := unseal(make([]byte, n), blob, nil); err == nil {
			t.Errorf("DEK of len %d accepted", n)
		}
	}

	// Errors never carry plaintext or key material: they are static strings.
	if _, err := unseal(dek, blob[:5], nil); err == nil || strings.Contains(err.Error(), "4242") {
		t.Error("unexpected error text")
	}

	// A fresh random nonce per seal.
	nonces := make(map[string]bool, 10000)
	for i := 0; i < 10000; i++ {
		b := seal(dek, pt, nil)
		nonces[string(b[:12])] = true
	}
	if len(nonces) != 10000 {
		t.Fatalf("got %d distinct nonces from 10000 seals", len(nonces))
	}
}

// A card ciphertext opens only with the additional data it was sealed with, so a blob copied
// under another token fails closed. Every failure is errUnseal, never a panic.
func TestSealUnsealAAD(t *testing.T) {
	dek := testDEK(t)
	pt := []byte(`{"pan":"4242424242424242","exp_month":"12","exp_year":"2030"}`)
	tokA, tokB := newToken(), newToken()
	blob := seal(dek, pt, cardAAD(tokA))

	if want := "pan-vault/card/1\x00" + tokA; string(cardAAD(tokA)) != want {
		t.Fatal("cardAAD is not the versioned prefix followed by the token")
	}
	got, err := unseal(dek, blob, cardAAD(tokA))
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatal("round trip with the sealing AAD failed")
	}

	mustFail := func(what string, aad []byte) {
		t.Helper()
		defer func() {
			if recover() != nil {
				t.Errorf("%s: unseal panicked", what)
			}
		}()
		out, err := unseal(dek, blob, aad)
		if !errors.Is(err, errUnseal) || out != nil {
			t.Errorf("%s: accepted, or failed with another error", what)
		}
	}
	mustFail("another token", cardAAD(tokB))
	mustFail("nil AAD", nil)
	mustFail("empty AAD", []byte{})
	mustFail("empty token", cardAAD(""))
	mustFail("token one char short", cardAAD(tokA[:len(tokA)-1]))
	mustFail("token one char long", cardAAD(tokA+"0"))
	mustFail("bare token without prefix", []byte(tokA))
	mustFail("prefix of another version", []byte("pan-vault/card/2\x00"+tokA))

	// The primitive stays general: no AAD on both sides still round-trips, and a blob sealed
	// without AAD does not open under a card AAD.
	plain := seal(dek, pt, nil)
	if got, err := unseal(dek, plain, nil); err != nil || !bytes.Equal(got, pt) {
		t.Fatal("round trip without AAD failed")
	}
	if _, err := unseal(dek, plain, cardAAD(tokA)); !errors.Is(err, errUnseal) {
		t.Error("a blob sealed without AAD opened under a card AAD")
	}
	// The AAD is authenticated, not encrypted: it never appears in the blob.
	if bytes.Contains(blob, []byte(tokA)) {
		t.Error("blob contains the token")
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
			seal(make([]byte, n), []byte("x"), nil)
		}()
	}
}

// The sealed plaintext is exactly json.Marshal(card{PAN, ExpMonth, ExpYear}) with these keys
// and no CVV; it must round-trip through seal/unseal.
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
	tok := newToken()
	out, err := unseal(dek, seal(dek, pt, cardAAD(tok)), cardAAD(tok))
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

// ---------------------------------------------------------------------------
// CVV cache
// ---------------------------------------------------------------------------

func TestCVVSingleUse(t *testing.T) {
	clk := &fakeClock{t: testNow}
	c := newCVVCache(15*time.Minute, clk.now)
	c.put("tok_a", testCVV)
	if c.take("tok_a") != testCVV {
		t.Fatal("first take did not return the cached CVV")
	}
	if c.take("tok_a") != "" {
		t.Fatal("second take returned a CVV")
	}
	if c.take("tok_absent") != "" {
		t.Fatal("take of an absent token returned a CVV")
	}
}

func TestCVVExpiry(t *testing.T) {
	clk := &fakeClock{t: testNow}
	c := newCVVCache(15*time.Minute, clk.now)

	c.put("tok_a", testCVV)
	clk.advance(15*time.Minute - time.Second)
	if c.take("tok_a") != testCVV {
		t.Fatal("CVV expired before its TTL")
	}

	c.put("tok_b", testCVV)
	clk.advance(15*time.Minute + time.Second)
	if c.take("tok_b") != "" {
		t.Fatal("CVV returned after its TTL")
	}

	// An entry is expired at exactly put+TTL.
	c.put("tok_c", testCVV)
	clk.advance(15 * time.Minute)
	if c.take("tok_c") != "" {
		t.Fatal("CVV returned at exactly put+TTL")
	}
}

// A put below the cap does not sweep (routine expiry is the ticker's job), so an expired entry
// stays until sweep runs. An expired entry is never returned meanwhile.
func TestCVVSweep(t *testing.T) {
	clk := &fakeClock{t: testNow}
	c := newCVVCache(15*time.Minute, clk.now)
	c.put("tok_a", testCVV)
	clk.advance(16 * time.Minute)
	c.put("tok_b", testCVV)
	c.mu.Lock()
	n := len(c.m)
	_, hasA := c.m["tok_a"]
	c.mu.Unlock()
	if n != 2 || !hasA {
		t.Fatalf("after a put below the cap the cache holds %d entries (expired entry present: %v), want 2", n, hasA)
	}
	if removed := c.sweep(); removed != 1 {
		t.Fatalf("sweep removed %d entries, want 1", removed)
	}
	c.mu.Lock()
	n = len(c.m)
	_, hasA = c.m["tok_a"]
	c.mu.Unlock()
	if n != 1 || hasA {
		t.Fatalf("after sweep the cache holds %d entries (expired entry present: %v), want 1", n, hasA)
	}
	if c.take("tok_b") != testCVV {
		t.Fatal("sweep removed a live entry")
	}
}

func TestCVVConcurrentTake(t *testing.T) {
	c := newCVVCache(15*time.Minute, func() time.Time { return testNow })
	c.put("tok_a", testCVV)
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		hits int
	)
	start := make(chan struct{})
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if c.take("tok_a") != "" {
				mu.Lock()
				hits++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if hits != 1 {
		t.Fatalf("%d concurrent takes received the CVV, want exactly 1", hits)
	}
}

func TestCVVSweepRemovesExpiredWithoutTraffic(t *testing.T) {
	clk := &fakeClock{t: testNow}
	c := newCVVCache(cvvCacheTTL, clk.now)
	c.put("tok_a", testCVV)
	ref := storedCVV(c, "tok_a")
	if len(ref) == 0 {
		t.Fatal("put stored no CVV bytes")
	}
	clk.advance(cvvCacheTTL + time.Second)
	if n := c.sweep(); n != 1 {
		t.Fatalf("sweep removed %d entries, want 1", n)
	}
	if n := cvvCacheLen(c); n != 0 {
		t.Fatalf("after sweep the cache holds %d entries, want 0", n)
	}
	if !allZero(ref) {
		t.Fatal("sweep left the removed CVV bytes in memory")
	}
	if n := c.sweep(); n != 0 {
		t.Fatalf("second sweep removed %d entries, want 0", n)
	}
}

func TestCVVRunStopsOnCancel(t *testing.T) {
	clk := &fakeClock{t: testNow}
	c := newCVVCache(cvvCacheTTL, clk.now)
	c.put("tok_a", testCVV)
	clk.advance(cvvCacheTTL + time.Second)

	// run sweeps on its ticker with no other traffic.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.run(ctx, time.Millisecond)
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for cvvCacheLen(c) != 0 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("run did not sweep the expired entry within 2s")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return within 2s of cancellation")
	}

	// An already-cancelled context returns promptly too.
	done = make(chan struct{})
	go func() {
		c.run(ctx, time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run with a cancelled context did not return within 2s")
	}
}

func TestCVVDrop(t *testing.T) {
	c := newCVVCache(cvvCacheTTL, func() time.Time { return testNow })
	c.put("tok_a", testCVV)
	ref := storedCVV(c, "tok_a")
	c.drop("tok_a")
	if !allZero(ref) {
		t.Fatal("drop left the removed CVV bytes in memory")
	}
	if c.take("tok_a") != "" {
		t.Fatal("take after drop returned a CVV")
	}
	c.drop("tok_a")      // absent: no-op
	c.drop("tok_absent") // never cached: no-op
	if n := cvvCacheLen(c); n != 0 {
		t.Fatalf("cache holds %d entries after drops, want 0", n)
	}
}

func TestCVVDropConcurrentTake(t *testing.T) {
	c := newCVVCache(cvvCacheTTL, func() time.Time { return testNow })
	c.put("tok_a", testCVV)
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		hits int
		bad  int
	)
	start := make(chan struct{})
	for i := 0; i < 25; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			if got := c.take("tok_a"); got != "" {
				mu.Lock()
				hits++
				if got != testCVV {
					bad++
				}
				mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			c.drop("tok_a")
		}()
	}
	close(start)
	wg.Wait()
	if hits > 1 || bad != 0 {
		t.Fatalf("%d takes received a CVV (%d corrupted), want at most 1 intact", hits, bad)
	}
	if n := cvvCacheLen(c); n != 0 {
		t.Fatalf("cache holds %d entries, want 0", n)
	}
}

func TestCVVCap(t *testing.T) {
	c := newCVVCache(cvvCacheTTL, func() time.Time { return testNow })
	fillCVVCache(c, "tok_fill_", cvvCacheMax, testNow.Add(time.Hour))
	if c.put("tok_new", testCVV) {
		t.Fatal("put into a full cache reported success")
	}
	if n := cvvCacheLen(c); n != cvvCacheMax {
		t.Fatalf("cache holds %d entries, want %d", n, cvvCacheMax)
	}
	if c.take("tok_new") != "" {
		t.Fatal("take returned a CVV refused by a full cache")
	}
	// Freeing one slot lets the next put in.
	c.drop("tok_fill_0")
	if !c.put("tok_new", testCVV) {
		t.Fatal("put with a free slot reported failure")
	}
	if c.take("tok_new") != testCVV {
		t.Fatal("take did not return the CVV cached into the freed slot")
	}
}

func TestCVVCapAfterSweep(t *testing.T) {
	clk := &fakeClock{t: testNow}
	c := newCVVCache(cvvCacheTTL, clk.now)
	fillCVVCache(c, "tok_fill_", cvvCacheMax-1, testNow.Add(time.Hour))
	fillCVVCache(c, "tok_old_", 1, testNow.Add(time.Minute))
	if n := cvvCacheLen(c); n != cvvCacheMax {
		t.Fatalf("cache holds %d entries, want %d", n, cvvCacheMax)
	}
	// The new put arrives at the instant the old entry expires.
	clk.advance(time.Minute)
	if !c.put("tok_new", testCVV) {
		t.Fatal("put refused although an expired entry could be swept")
	}
	if n := cvvCacheLen(c); n != cvvCacheMax {
		t.Fatalf("cache holds %d entries, want %d", n, cvvCacheMax)
	}
	if c.take("tok_new") != testCVV {
		t.Fatal("take did not return the CVV cached after the sweep")
	}
}

func TestCVVTakeZeroes(t *testing.T) {
	c := newCVVCache(cvvCacheTTL, func() time.Time { return testNow })
	c.put("tok_a", testCVV)
	ref := storedCVV(c, "tok_a")
	if len(ref) == 0 {
		t.Fatal("put stored no CVV bytes")
	}
	if c.take("tok_a") != testCVV {
		t.Fatal("take did not return the cached CVV")
	}
	if !allZero(ref) {
		t.Fatal("take left the removed CVV bytes in memory")
	}

	// An expired entry removed by take is zeroed as well.
	clk := &fakeClock{t: testNow}
	c = newCVVCache(cvvCacheTTL, clk.now)
	c.put("tok_b", testCVV)
	ref = storedCVV(c, "tok_b")
	clk.advance(cvvCacheTTL)
	if c.take("tok_b") != "" {
		t.Fatal("take returned an expired CVV")
	}
	if !allZero(ref) {
		t.Fatal("take left an expired CVV's bytes in memory")
	}
}
