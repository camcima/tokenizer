package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// ---------------------------------------------------------------------------
// Card receipts
// ---------------------------------------------------------------------------

// receiptPrefix names the receipt scheme and its version. The signature covers it, so a receipt
// cannot be relabelled as another version or scheme without failing verification.
const receiptPrefix = "rcpt.v1."

// receipt is the signed statement the vault returns from /tokenize: which token it issued and the
// truncated card details the platform may keep next to it. It never carries more of the card
// number than the BIN and the last four digits. The field order is the payload's key order.
// Name is omitted when the card was tokenized without one.
type receipt struct {
	Token    string `json:"token"`
	BIN      string `json:"bin"`
	Last4    string `json:"last4"`
	ExpMonth string `json:"exp_month"`
	ExpYear  string `json:"exp_year"`
	Name     string `json:"name,omitempty"`
	IAT      int64  `json:"iat"`
}

var errReceipt = errors.New("invalid receipt")

// maxReceiptLen bounds the input verifyReceipt looks at. The longest receipt the vault issues
// (a 36-character token, 8 + 4 digits, the expiry, a 100-rune name whose every rune JSON-escapes
// to six bytes, and the largest iat) is 1097 bytes, so the cap rejects nothing the vault signs
// while keeping the cost of hostile input small and fixed.
const maxReceiptLen = 2048

// receiptFields is the exact set of keys a receipt payload may contain.
var receiptFields = map[string]bool{
	"token": true, "bin": true, "last4": true, "exp_month": true, "exp_year": true, "name": true, "iat": true,
}

// receiptB64 decodes receipt parts. Strict rejects a final character with non-zero unused bits,
// so each payload and signature has exactly one accepted spelling.
var receiptB64 = base64.RawURLEncoding.Strict()

// cardBIN returns the leading digits of a normalized card number that a receipt may carry: 8 when
// the number has exactly 16 digits, otherwise 6. The PCI SSC truncation table allows the first 8
// and last 4 digits only for 16-digit numbers; other lengths need the card brand's confirmation,
// which the vault does not have, so they keep the conservative first 6. Together with the last
// four this always leaves digits hidden, even for a 13-digit card.
func cardBIN(pan string) string {
	if len(pan) == 16 {
		return pan[:8]
	}
	return pan[:6]
}

// encodeReceipt returns the payload bytes that are signed: compact JSON in field order with no
// trailing newline. HTML escaping is off so names containing &, < or > are carried verbatim and
// a verifier sees exactly the name the vault stored.
func encodeReceipt(r receipt) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// signReceipt returns receiptPrefix + base64url(payload) + "." + base64url(signature), with the
// Ed25519 signature computed over receiptPrefix + base64url(payload) and both parts unpadded.
// The payload is encoded once and signed as those bytes, so verifiers never re-serialize it.
// A missing or malformed key is a boot invariant violation, so it panics rather than issuing an
// unsigned receipt.
func signReceipt(priv ed25519.PrivateKey, r receipt) string {
	if len(priv) != ed25519.PrivateKeySize {
		panic("receipt signing key is not an Ed25519 private key")
	}
	payload, err := encodeReceipt(r)
	if err != nil {
		panic("receipt payload cannot be encoded")
	}
	signed := receiptPrefix + base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(priv, []byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// verifyReceipt reports whether s is a receipt signed by the key behind pub and returns its
// contents. Anything other than exactly what signReceipt produces is invalid: four dot-separated
// parts, the exact prefix and version, unpadded base64url with no other characters, a valid
// signature over receiptPrefix + payload part, and a payload holding a single JSON object with
// exactly the receipt's keys. The signature is checked before the payload is parsed, so
// unauthenticated bytes never reach the JSON decoder. Input longer than maxReceiptLen, or with a
// signature part of any length but 86, is rejected before any part is scanned or decoded, so the
// work done on hostile input is bounded. It never panics, whatever the input.
func verifyReceipt(pub ed25519.PublicKey, s string) (receipt, bool) {
	if len(s) > maxReceiptLen {
		return receipt{}, false
	}
	// ed25519.Verify panics on a public key of the wrong length.
	if len(pub) != ed25519.PublicKeySize {
		return receipt{}, false
	}
	// At most five parts are split off, so a hostile input with many dots costs no more than a
	// valid one; a fifth part means there were too many.
	parts := strings.SplitN(s, ".", 5)
	if len(parts) != 4 || parts[0]+"."+parts[1]+"." != receiptPrefix {
		return receipt{}, false
	}
	// 86 is the unpadded base64url length of a 64-byte signature.
	if len(parts[3]) != 86 {
		return receipt{}, false
	}
	// The base64 decoder skips CR and LF, so the alphabet is checked first: a part with CR or LF
	// inserted would otherwise decode to the same bytes as the original. Any other character
	// outside the alphabet already fails decoding.
	if !base64URLChars(parts[2]) || !base64URLChars(parts[3]) {
		return receipt{}, false
	}
	sig, err := receiptB64.DecodeString(parts[3])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return receipt{}, false
	}
	if !ed25519.Verify(pub, []byte(receiptPrefix+parts[2]), sig) {
		return receipt{}, false
	}
	payload, err := receiptB64.DecodeString(parts[2])
	if err != nil {
		return receipt{}, false
	}
	r, err := decodeReceiptPayload(payload)
	if err != nil {
		return receipt{}, false
	}
	return r, true
}

// base64URLChars reports whether s is non-empty and uses only the unpadded base64url alphabet.
func base64URLChars(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// decodeReceiptPayload parses a signed payload strictly: one JSON object, only the receipt's keys
// spelled exactly and each at most once, nothing after it, every key the vault always writes
// present with a non-empty value, and name, when present, a non-empty string. A payload that
// different JSON parsers could read differently is rejected even though it is signed.
func decodeReceiptPayload(payload []byte) (receipt, error) {
	if !exactKeys(payload, receiptFields) {
		return receipt{}, errReceipt
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var r receipt
	if err := dec.Decode(&r); err != nil {
		return receipt{}, errReceipt
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return receipt{}, errReceipt
	}
	if r.Token == "" || r.BIN == "" || r.Last4 == "" || r.ExpMonth == "" || r.ExpYear == "" || r.IAT <= 0 {
		return receipt{}, errReceipt
	}
	// The vault omits name when the card has none, so a name key holding "" or null is invalid
	// rather than read as a card without a name.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return receipt{}, errReceipt
	}
	if _, ok := raw["name"]; ok && r.Name == "" {
		return receipt{}, errReceipt
	}
	return r, nil
}
