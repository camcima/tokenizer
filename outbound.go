package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Provider responses: PAN masking, outbound client
// ---------------------------------------------------------------------------

const (
	maxProviderResponse = 4 << 20 // provider response body limit
	formContentType     = "application/x-www-form-urlencoded"
)

var errEgress = errors.New("egress invariant")

// maskPAN replaces every occurrence of pan, and of pan grouped in fours from the left with single
// spaces ("4242 4242 4242 4242", "3782 8224 6310 005") or single hyphens ("4242-4242-4242-4242"),
// with "****"+last4. found reports whether anything was replaced; if not, body is returned
// unchanged.
// The hyphen-grouped form is masked too, since hyphens are the other separator normalizePAN
// accepts. The replacement repeats until no form remains: one bytes.ReplaceAll pass over
// pan+pan[4:] leaves a full PAN when the last 4
// digits equal the first 4 ("4242…4242" + "4242…" → "****4242" + "4242…"). Each pass replaces a
// needle of >= 13 bytes with an 8-byte mask, so the body strictly shrinks and the loop ends.
func maskPAN(body []byte, pan string) ([]byte, bool) {
	if len(pan) < 13 { // never a real PAN; keeps every needle longer than the mask
		return body, false
	}
	var spaced, hyphen strings.Builder
	for i := 0; i < len(pan); i++ {
		if i > 0 && i%4 == 0 {
			spaced.WriteByte(' ')
			hyphen.WriteByte('-')
		}
		spaced.WriteByte(pan[i])
		hyphen.WriteByte(pan[i])
	}
	forms := [][]byte{[]byte(pan), []byte(spaced.String()), []byte(hyphen.String())}
	mask := []byte("****" + pan[len(pan)-4:])
	found := false
	for again := true; again; {
		again = false
		for _, form := range forms {
			if bytes.Contains(body, form) {
				body = bytes.ReplaceAll(body, form, mask)
				found, again = true, true
			}
		}
	}
	return body, found
}

// newOutboundClient returns the single shared provider client: 30s hard
// timeout, redirects never followed, no proxy from the environment, TLS >= 1.2 verified against
// roots (nil = system roots; tests pass an httptest server's CA), 16 idle conns per host.
func newOutboundClient(roots *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy:               nil, // never HTTP_PROXY/HTTPS_PROXY
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 16,
			TLSHandshakeTimeout: 10 * time.Second,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}
