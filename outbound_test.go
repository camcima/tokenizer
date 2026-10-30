package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Provider catalog, egress invariant, PAN masking, outbound client
// ---------------------------------------------------------------------------

func TestMaskPAN(t *testing.T) {
	body := []byte(`{"n":"4242424242424242","f":"4242 4242 4242 4242"}`)
	got, found := maskPAN(body, testPAN)
	if !found || string(got) != `{"n":"****4242","f":"****4242"}` {
		t.Errorf("masked: found=%v, still has PAN=%v, len %d", found, bytes.Contains(got, []byte("4242424242")), len(got))
	}

	// Every occurrence; a 15-digit PAN groups in fours from the left.
	amex := "378282246310005"
	got, found = maskPAN([]byte(amex+" x "+amex+" y 3782 8224 6310 005"), amex)
	if !found || string(got) != "****0005 x ****0005 y ****0005" {
		t.Errorf("amex: found=%v, len %d", found, len(got))
	}

	clean := []byte(`{"id":"pm_123","last4":"4242","n":"4242 4242 4242"}`)
	got, found = maskPAN(clean, testPAN)
	if found || !bytes.Equal(got, clean) {
		t.Errorf("clean body changed or flagged (found=%v)", found)
	}

	// The hyphen-grouped form is masked too (same left-to-right grouping in fours).
	got, found = maskPAN([]byte(`{"f":"4242-4242-4242-4242","a":"3782-8224-6310-005"}`), testPAN)
	if !found || string(got) != `{"f":"****4242","a":"3782-8224-6310-005"}` {
		t.Errorf("hyphen form: found=%v, still has PAN=%v, len %d", found, bytes.Contains(got, []byte("4242-4242")), len(got))
	}
	got, found = maskPAN([]byte("x 3782-8224-6310-005 y"), amex)
	if !found || string(got) != "x ****0005 y" {
		t.Errorf("amex hyphen form: found=%v, len %d", found, len(got))
	}

	// Residue: PAN+PAN[4:] (last 4 == first 4) leaves a full PAN after one ReplaceAll pass
	// ("****4242"+"424242424242"); the replacement repeats until no form remains.
	for i, in := range []string{
		testPAN + testPAN[4:],
		testPAN + testPAN[4:] + testPAN[4:],
		"4242 4242 4242 4242 4242 4242 4242",
		"4242-4242-4242-4242-4242-4242-4242",
	} {
		got, found := maskPAN([]byte(in), testPAN)
		if !found || len(luhnWindowOffsets(joinDigitSeparators(string(got)))) != 0 || bytes.Contains(got, []byte(testPAN)) {
			t.Errorf("residue case %d: found=%v, a PAN remains (len %d)", i, found, len(got))
		}
	}
	if got, _ := maskPAN([]byte(testPAN+testPAN[4:]), testPAN); string(got) != "********4242" {
		t.Errorf("residue: masked to len %d, want ********4242", len(got))
	}

	// A PAN too short to be real masks nothing (never loops on an empty needle, or on a needle the
	// mask itself contains).
	for _, pan := range []string{"", "42", "4242", "424242424242"} {
		if got, found := maskPAN(clean, pan); found || !bytes.Equal(got, clean) {
			t.Errorf("short pan len %d: found=%v", len(pan), found)
		}
	}
}

func TestOutboundClientConfig(t *testing.T) {
	pool := x509.NewCertPool()
	for _, roots := range []*x509.CertPool{nil, pool} {
		c := newOutboundClient(roots)
		if c.Timeout != 30*time.Second {
			t.Errorf("timeout %v", c.Timeout)
		}
		if c.CheckRedirect == nil || c.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
			t.Error("CheckRedirect does not return http.ErrUseLastResponse")
		}
		tr, ok := c.Transport.(*http.Transport)
		if !ok {
			t.Fatal("transport is not *http.Transport")
		}
		if tr.Proxy != nil {
			t.Error("transport reads a proxy")
		}
		if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 ||
			tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.RootCAs != roots {
			t.Error("TLS config wrong (min version, verification, or roots)")
		}
		if tr.MaxIdleConnsPerHost != 16 {
			t.Errorf("MaxIdleConnsPerHost %d", tr.MaxIdleConnsPerHost)
		}
	}
	if maxProviderResponse != 4<<20 {
		t.Errorf("maxProviderResponse %d", maxProviderResponse)
	}
}
