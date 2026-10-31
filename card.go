package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// Card primitives
// ---------------------------------------------------------------------------

// card is the encrypted record: plaintext is json.Marshal(card{...}).
// CVV is never part of it. Keep values of this type scoped to a single request.
// Name is the optional cardholder name. omitempty keeps the plaintext of a card stored
// without a name byte-identical to before, and old rows decode with Name == "".
type card struct {
	PAN      string `json:"pan"`
	ExpMonth string `json:"exp_month"`
	ExpYear  string `json:"exp_year"`
	Name     string `json:"name,omitempty"`
}

var (
	expMonthRe = regexp.MustCompile(`^(0[1-9]|1[0-2])$`)
	expYearRe  = regexp.MustCompile(`^[0-9]{4}$`)
	tokenRe    = regexp.MustCompile(`^tok_[0-9a-f]{32}$`)
)

// luhnValid reports whether digits is a non-empty ASCII digit string passing the Luhn check.
func luhnValid(digits string) bool {
	if digits == "" {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		c := digits[i]
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// normalizePAN strips spaces and hyphens, then requires ASCII digits only, length 13–19,
// and a passing Luhn check. On failure it returns ("", false).
// Only ' ' and '-' are stripped; any other separator (tab, dot, NBSP) or
// non-ASCII digit (e.g. full-width) rejects the PAN.
func normalizePAN(s string) (string, bool) {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ' || c == '-':
			continue
		case c >= '0' && c <= '9':
			b = append(b, c)
		default:
			zero(b)
			return "", false
		}
	}
	defer zero(b)
	if len(b) < 13 || len(b) > 19 || !luhnValid(string(b)) {
		return "", false
	}
	return string(b), true
}

// validExpiry checks exp_month (exactly "01"–"12") and exp_year (exactly four digits), and
// requires (year, month) >= the current month in UTC.
func validExpiry(month, year string, now time.Time) bool {
	if !expMonthRe.MatchString(month) || !expYearRe.MatchString(year) {
		return false
	}
	// Both strings are validated ASCII digits, so this cannot overflow or misparse.
	m := int(month[0]-'0')*10 + int(month[1]-'0')
	y := 0
	for i := 0; i < len(year); i++ {
		y = y*10 + int(year[i]-'0')
	}
	u := now.UTC()
	cy, cm := u.Year(), int(u.Month())
	return y > cy || (y == cy && m >= cm)
}

// validCVV reports whether s is 3–4 ASCII digits. Presence is the caller's concern.
func validCVV(s string) bool {
	if len(s) < 3 || len(s) > 4 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// validName reports whether s is an acceptable cardholder name: 1–100 runes, valid
// UTF-8, and no control rune (unicode.IsControl: C0, DEL, C1). Presence is the caller's concern.
// U+FFFD is rejected too. encoding/json silently replaces invalid UTF-8 in a
// string with U+FFFD, so without this a body carrying invalid UTF-8 would be stored, not
// rejected. No real name contains the replacement character.
func validName(s string) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > 100 {
		return false
	}
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// newToken returns "tok_" + 32 lowercase hex chars from 16 bytes of crypto/rand.
func newToken() string {
	var b [16]byte
	// crypto/rand.Read is deliberately called without error handling: since Go 1.24 it never
	// returns an error and irrecoverably crashes the process if the OS RNG fails, which is
	// exactly the wanted behaviour (a crypto/rand failure panics and is not recoverable).
	rand.Read(b[:])
	return "tok_" + hex.EncodeToString(b[:])
}

const (
	gcmNonceSize = 12
	gcmTagSize   = 16
	dekSize      = 32 // AES-256
)

var errUnseal = errors.New("unseal failed")

// newGCM builds AES-256-GCM for dek.
// Only 32-byte keys are accepted (AES-256); aes.NewCipher would
// otherwise silently accept 16/24-byte keys and downgrade to AES-128/192.
func newGCM(dek []byte) (cipher.AEAD, error) {
	if len(dek) != dekSize {
		return nil, errUnseal
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, errUnseal
	}
	gcm, err := cipher.NewGCM(block) // 12-byte nonce, 16-byte tag
	if err != nil {
		return nil, errUnseal
	}
	return gcm, nil
}

// cardAADPrefix versions the additional data a card is sealed with, so a future change to the
// binding cannot be confused with this one. The NUL separates it from the token.
const cardAADPrefix = "pan-vault/card/1\x00"

// cardAAD is the additional data a stored card is sealed with: it binds the ciphertext to its
// token, so a ciphertext copied into another token's row fails authentication instead of
// decrypting as that token's card.
func cardAAD(token string) []byte {
	return []byte(cardAADPrefix + token)
}

// seal encrypts plaintext under dek with AES-256-GCM and a fresh random 12-byte nonce,
// authenticating aad (which is not stored in the output), and returns nonce || ciphertext || tag.
// A nil aad means no additional data.
// A DEK that is not 32 bytes is a programming error (DEKs are length-checked at load) and panics.
func seal(dek, plaintext, aad []byte) []byte {
	gcm, err := newGCM(dek)
	if err != nil {
		panic("seal: invalid DEK")
	}
	out := make([]byte, gcmNonceSize, gcmNonceSize+len(plaintext)+gcmTagSize)
	rand.Read(out) // never fails; see newToken
	return gcm.Seal(out, out, plaintext, aad)
}

// unseal reverses seal; aad must equal what the blob was sealed with. Any failure (bad key
// length, short blob, wrong aad, authentication failure) returns the same static error, never
// key or data material.
func unseal(dek, blob, aad []byte) ([]byte, error) {
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, errUnseal
	}
	if len(blob) < gcmNonceSize+gcmTagSize {
		return nil, errUnseal
	}
	pt, err := gcm.Open(nil, blob[:gcmNonceSize], blob[gcmNonceSize:], aad)
	if err != nil {
		return nil, errUnseal
	}
	return pt, nil
}

// zero overwrites b with zeros. Best effort only: Go may have copied the data
// elsewhere (string conversions, GC moves, register spills), so this narrows exposure but
// cannot guarantee the bytes are gone from memory.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ---------------------------------------------------------------------------
// CVV cache: in memory only, single use, TTL, capped, swept on a ticker and when full
// ---------------------------------------------------------------------------

const (
	cvvCacheTTL   = 15 * time.Minute
	cvvSweepEvery = 60 * time.Second
	// cvvCacheMax bounds the memory a flood of /tokenize calls can pin. A full cache refuses new
	// CVVs rather than evicting live ones: the card is still stored, and a later {{cvv}} use gets
	// the ordinary 409.
	cvvCacheMax = 50_000
)

// cvvEntry holds the CVV as bytes so it can be overwritten when the entry is removed.
type cvvEntry struct {
	cvv []byte
	exp time.Time
}

type cvvCache struct {
	mu  sync.Mutex
	m   map[string]cvvEntry
	ttl time.Duration
	now func() time.Time
}

func newCVVCache(ttl time.Duration, now func() time.Time) *cvvCache {
	return &cvvCache{m: make(map[string]cvvEntry), ttl: ttl, now: now}
}

// removeLocked zeroes token's CVV bytes and deletes the entry. The caller holds c.mu, so a
// concurrent take or drop for the same token finds it either intact or gone, never half-zeroed.
func (c *cvvCache) removeLocked(token string, e cvvEntry) {
	zero(e.cvv) // best effort
	delete(c.m, token)
}

// sweepLocked removes every entry expired at now and returns how many it removed. The caller
// holds c.mu. An entry is expired from exactly put+ttl onward.
func (c *cvvCache) sweepLocked(now time.Time) int {
	n := 0
	for k, e := range c.m {
		if !now.Before(e.exp) {
			c.removeLocked(k, e)
			n++
		}
	}
	return n
}

// put caches cvv for token until now+ttl. Only live entries count against cvvCacheMax: when the
// map is full, put first removes every expired entry. Below the cap it does not sweep, so a put
// stays cheap however many entries are pending; the ticker in run handles routine expiry. It
// returns false, caching nothing, when the cache is still full after that sweep.
func (c *cvvCache) put(token, cvv string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if e, ok := c.m[token]; ok {
		c.removeLocked(token, e)
	}
	if len(c.m) >= cvvCacheMax {
		c.sweepLocked(now)
	}
	if len(c.m) >= cvvCacheMax {
		return false
	}
	c.m[token] = cvvEntry{cvv: []byte(cvv), exp: now.Add(c.ttl)}
	return true
}

// take removes and returns token's CVV; "" if absent or expired. Single use: concurrent
// callers for the same token get it at most once. The cached bytes are zeroed on removal.
func (c *cvvCache) take(token string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[token]
	if !ok {
		return ""
	}
	cvv := ""
	if c.now().Before(e.exp) {
		cvv = string(e.cvv)
	}
	c.removeLocked(token, e)
	return cvv
}

// drop removes token's CVV, zeroing it, if one is cached; otherwise it does nothing.
func (c *cvvCache) drop(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[token]; ok {
		c.removeLocked(token, e)
	}
}

// sweep removes every expired entry, zeroing it, and returns how many it removed.
func (c *cvvCache) sweep() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sweepLocked(c.now())
}

// run calls sweep every interval until ctx is done. It is the routine expiry path: put sweeps
// only when the cache is full, so without run expired CVVs would stay until then.
func (c *cvvCache) run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.sweep()
		}
	}
}
