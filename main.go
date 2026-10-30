package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {}

// ---------------------------------------------------------------------------
// Card primitives (SPEC §5.5, §5.6, §8.1, §8.5)
// ---------------------------------------------------------------------------

// card is the encrypted record: plaintext is json.Marshal(card{...}) (§8.1).
// CVV is never part of it. Keep values of this type scoped to a single request.
type card struct {
	PAN      string `json:"pan"`
	ExpMonth string `json:"exp_month"`
	ExpYear  string `json:"exp_year"`
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
// and a passing Luhn check (§5.5). On failure it returns ("", false).
// SPEC-DECISION: only ' ' and '-' are stripped; any other separator (tab, dot, NBSP) or
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
// requires (year, month) >= the current month in UTC (§5.5).
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

// validCVV reports whether s is 3–4 ASCII digits (§5.5). Presence is the caller's concern.
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

// newToken returns "tok_" + 32 lowercase hex chars from 16 bytes of crypto/rand (§5.6).
func newToken() string {
	var b [16]byte
	// crypto/rand.Read is deliberately called without error handling: since Go 1.24 it never
	// returns an error and irrecoverably crashes the process if the OS RNG fails, which is
	// exactly §8.1's "a crypto/rand failure panics; it is not recoverable".
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
// SPEC-DECISION: only 32-byte keys are accepted (AES-256 per §8.1); aes.NewCipher would
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

// seal encrypts plaintext under dek with AES-256-GCM and a fresh random 12-byte nonce, no
// additional data, returning nonce || ciphertext || tag (§8.1).
// A DEK that is not 32 bytes is a programming error (DEKs are length-checked at load) and panics.
func seal(dek, plaintext []byte) []byte {
	gcm, err := newGCM(dek)
	if err != nil {
		panic("seal: invalid DEK")
	}
	out := make([]byte, gcmNonceSize, gcmNonceSize+len(plaintext)+gcmTagSize)
	rand.Read(out) // never fails; see newToken
	return gcm.Seal(out, out, plaintext, nil)
}

// unseal reverses seal. Any failure (bad key length, short blob, authentication failure)
// returns the same static error, never key or data material.
func unseal(dek, blob []byte) ([]byte, error) {
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, errUnseal
	}
	if len(blob) < gcmNonceSize+gcmTagSize {
		return nil, errUnseal
	}
	pt, err := gcm.Open(nil, blob[:gcmNonceSize], blob[gcmNonceSize:], nil)
	if err != nil {
		return nil, errUnseal
	}
	return pt, nil
}

// zero overwrites b with zeros. Best effort only (§8.5): Go may have copied the data
// elsewhere (string conversions, GC moves, register spills), so this narrows exposure but
// cannot guarantee the bytes are gone from memory.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
