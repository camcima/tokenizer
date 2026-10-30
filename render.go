package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// ---------------------------------------------------------------------------
// Rendering the provider request: placeholders, header templates, signers, account URL
// ---------------------------------------------------------------------------

var errRender = errors.New("render failed")

// signPayU is the payu signer: hex(hash(apiKey~merchantId~referenceCode~TX_VALUE.value~
// TX_VALUE.currency)), where hash is the account value "hash" (md5, sha1 or sha256), apiKey the
// account secret and merchantId the account value. The three body fields (payuSignerInputs) are read
// with readField and used exactly as written: a JSON string decoded, a JSON number as its raw text
// ("3.50" stays "3.50"); the platform owns PayU's amount formatting. Signers never take card data.
// Anything missing, an input that is not a string or number or holds "{{", or an unknown hash is
// errRender: checkProxy already refuses such bodies, and the signer fails closed on its own too.
func signPayU(p *proxyPlan) (string, error) {
	apiKey, merchantID := p.acct.secrets["apiKey"], p.acct.values["merchantId"]
	if apiKey == "" || merchantID == "" {
		return "", errRender
	}
	parts := []string{apiKey, merchantID}
	for _, addr := range payuSignerInputs {
		got, found, err := readField(p.prov.format, p.body, addr)
		if err != nil || !found || (got.kind != "string" && got.kind != "number") || strings.Contains(got.text, "{{") {
			return "", errRender
		}
		parts = append(parts, got.text)
	}
	msg := []byte(strings.Join(parts, "~"))
	defer zero(msg) // best effort: it holds the API key
	switch p.acct.values["hash"] {
	case "md5":
		sum := md5.Sum(msg)
		return hex.EncodeToString(sum[:]), nil
	case "sha1":
		sum := sha1.Sum(msg)
		return hex.EncodeToString(sum[:]), nil
	case "sha256":
		sum := sha256.Sum256(msg)
		return hex.EncodeToString(sum[:]), nil
	}
	return "", errRender
}

// accountURL is the egress invariant for an account: it builds
// https://<a.host><a.basePath><path>, where path is the validated request path with its "?query",
// if any. It returns errEgress unless the scheme is https and the host is exactly a.host, both on the
// constructed URL and on a reparse of its string form (what the transport actually dials), and the
// reparse keeps the path and query unchanged and gains no userinfo or fragment.
// Also refused: an account without a host, or whose base path is neither "" nor
// "/..." without a trailing "/"; a path not starting with "/"; any byte of path outside printable
// non-space ASCII, or a "#"; a "?" with an empty query; and, in the path part (base path included),
// any "%" or a "." or ".." segment. checkProxy (matchEndpoint) already refuses those request paths;
// this is defence in depth, so no dot-segment or percent-encoding can reach the transport and be
// resolved to a different path than the one checked.
func accountURL(a *catAccount, path string) (*url.URL, error) {
	if a == nil || a.host == "" || !strings.HasPrefix(path, "/") {
		return nil, errEgress
	}
	if a.basePath != "" && (!strings.HasPrefix(a.basePath, "/") || strings.HasSuffix(a.basePath, "/")) {
		return nil, errEgress
	}
	for i := 0; i < len(path); i++ {
		if path[i] < 0x21 || path[i] > 0x7e || path[i] == '#' {
			return nil, errEgress
		}
	}
	p, q, hasQuery := strings.Cut(path, "?")
	if hasQuery && q == "" {
		return nil, errEgress
	}
	full := a.basePath + p
	if strings.Contains(full, "%") {
		return nil, errEgress
	}
	for _, seg := range strings.Split(full, "/") {
		if seg == "." || seg == ".." {
			return nil, errEgress
		}
	}
	u := &url.URL{Scheme: "https", Host: a.host, Path: full, RawQuery: q}
	if u.Scheme != "https" || u.Host != a.host {
		return nil, errEgress
	}
	re, err := url.Parse(u.String())
	if err != nil || re.Scheme != "https" || re.Host != a.host || re.User != nil || re.Opaque != "" ||
		re.Fragment != "" || re.ForceQuery || re.Path != u.Path || re.RawQuery != q {
		return nil, errEgress
	}
	return u, nil
}

// renderRequest builds the outgoing provider request from a checked plan, the decrypted card and
// the CVV ("" if none):
//   - every occurrence span is replaced by its value encoded for the provider's format
//     (encodeValue), and no other body byte changes; the result is left in p.sent, which the caller
//     zeroes after the response has been read (best effort). A body left in p.sent by an
//     earlier render of the same plan is zeroed first, so p.sent is nil after a failed render;
//   - every header template of the endpoint is rendered ({{secret:N}}, {{basic:N}} =
//     base64(secret + ":"), {{signature}}) and set, whether or not the platform sent it;
//   - the platform's allowlisted headers (platformHeaders) are copied, and nothing else of its;
//   - Content-Type (from the format) and User-Agent: pan-vault/1 are set; Host and Content-Length
//     come from the URL and body. Accept-Encoding is deliberately not set: the transport then
//     requests gzip itself and decompresses transparently, so maskPAN always sees plain bytes.
//
// Card data and secrets go only into the occurrence spans and the header templates.
// It re-checks what it relies on and fails closed (errRender, or errEgress from
// accountURL, with no request and p.sent unset) on: an occurrence that is not, at its recorded span,
// exactly the placeholder of its rule position, or spans out of order; a cvv or name placeholder
// with no value; a card expiry that is not MM and YYYY; a missing secret, or one that is not
// printable non-space ASCII (validSecretValue, so no header injection); a {{basic:}} in a body; or a
// signer it does not know.
func renderRequest(ctx context.Context, p *proxyPlan, c card, cvv string) (*http.Request, error) {
	zero(p.sent) // best effort: a body from an earlier render of this plan
	p.sent = nil
	u, err := accountURL(p.acct, p.path)
	if err != nil {
		return nil, err
	}
	var contentType string
	switch p.prov.format {
	case "json":
		contentType = "application/json"
	case "form":
		contentType = formContentType
	default:
		return nil, errRender
	}

	secret := func(name string) (string, error) {
		s := p.acct.secrets[name]
		if !validSecretValue(s) {
			return "", errRender
		}
		return s, nil
	}
	sig := ""
	signature := func() (string, error) {
		if sig != "" {
			return sig, nil
		}
		var err error
		switch p.ep.signer {
		case "payu":
			sig, err = signPayU(p)
		default:
			return "", errRender
		}
		return sig, err
	}

	repl := make([][]byte, len(p.occs))
	defer func() {
		for _, r := range repl {
			zero(r) // best effort: the encoded card values and secrets
		}
	}()
	prev := 0
	for i, o := range p.occs {
		want := o.ph.String()
		if p.prov.format == "json" {
			want = `"` + want + `"`
		}
		if o.start < prev || o.end < o.start || o.end > len(p.body) || string(p.body[o.start:o.end]) != want ||
			p.ep.positions[o.addr] != o.ph {
			return nil, errRender
		}
		prev = o.end
		var v string
		switch o.ph.kind {
		case "pan":
			v = c.PAN
		case "cvv":
			v = cvv
		case "name":
			v = c.Name
		case "exp_month", "exp_year", "exp":
			if !expMonthRe.MatchString(c.ExpMonth) || !expYearRe.MatchString(c.ExpYear) {
				return nil, errRender
			}
			switch o.ph.kind + ":" + o.ph.mod {
			case "exp_month:", "exp_month:int":
				v = c.ExpMonth
			case "exp_year:", "exp_year:int":
				v = c.ExpYear
			case "exp_year:yy":
				v = c.ExpYear[2:]
			case "exp:yyyy/mm":
				v = c.ExpYear + "/" + c.ExpMonth
			case "exp:mm/yy":
				v = c.ExpMonth + "/" + c.ExpYear[2:]
			}
		case "secret":
			v, err = secret(o.ph.arg)
		case "signature":
			v, err = signature()
		}
		if err != nil || v == "" { // v == "" also covers {{basic:}} and any kind not handled above
			return nil, errRender
		}
		// A :int value is canonical digits in both formats (exp_month:int → 3); form has no quotes.
		repl[i] = encodeValue(p.prov.format, v, o.ph.isNumber())
	}

	h := http.Header{}
	for name, vals := range p.headers {
		if platformHeaders[name] && len(vals) == 1 {
			h[name] = []string{vals[0]}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(p.ep.headers)) {
		tmpl := p.ep.headers[name]
		ph, ok := parseHeaderTemplate(tmpl)
		if !ok || !strings.Contains(tmpl, ph.String()) || platformHeaders[name] || catReservedHeaders[name] {
			return nil, errRender
		}
		var v string
		switch ph.kind {
		case "secret":
			v, err = secret(ph.arg)
		case "basic":
			v, err = secret(ph.arg)
			v = base64.StdEncoding.EncodeToString([]byte(v + ":"))
		case "signature":
			v, err = signature()
		default:
			return nil, errRender
		}
		if err != nil || v == "" {
			return nil, errRender
		}
		h[name] = []string{strings.Replace(tmpl, ph.String(), v, 1)}
	}
	h.Set("Content-Type", contentType)
	h.Set("User-Agent", "pan-vault/1")

	body := substitute(p.body, p.occs, repl)
	req, err := http.NewRequestWithContext(ctx, p.ep.method, u.String(), bytes.NewReader(body))
	if err != nil {
		zero(body)
		return nil, errRender
	}
	req.Header = h
	p.sent = body
	return req, nil
}
