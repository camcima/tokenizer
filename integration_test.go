package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Integration tests. Gated on VAULT_TEST_DB_URL; run with `make itest`.
// Tests may name tables (they check privileges and count audit rows as the owner); main.go never does.
// ---------------------------------------------------------------------------

// integrationDB connects to the test database. role "" connects as the URL's user (vault_owner);
// otherwise the URL's user is replaced with role (the test server uses trust auth).
func integrationDB(t *testing.T, role string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", integrationURL(t, role))
	if err != nil {
		t.Fatalf("open as %q: %v", role, err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// integrationURL returns VAULT_TEST_DB_URL, with the user replaced by role unless role is "", or
// skips the test when it is not set.
func integrationURL(t *testing.T, role string) string {
	t.Helper()
	raw := os.Getenv("VAULT_TEST_DB_URL")
	if raw == "" {
		t.Skip("VAULT_TEST_DB_URL not set")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal("VAULT_TEST_DB_URL does not parse")
	}
	if role != "" {
		u.User = url.User(role)
	}
	return u.String()
}

func wantPermissionDenied(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("%s: err = %v, want permission denied", what, err)
	}
}

func TestIntegrationPrivileges(t *testing.T) {
	ctx := context.Background()
	app := integrationDB(t, "vault_app")

	_, err := app.ExecContext(ctx, "SELECT * FROM vault.cards")
	wantPermissionDenied(t, "app SELECT cards", err)
	_, err = app.ExecContext(ctx, `INSERT INTO vault.cards VALUES ($1, '\x01', '4242', 1)`, newToken())
	wantPermissionDenied(t, "app INSERT cards", err)
	_, err = app.ExecContext(ctx, `SELECT vault.add_dek('\x00')`)
	wantPermissionDenied(t, "app add_dek", err)
	_, err = app.ExecContext(ctx, "SELECT * FROM vault.access_log")
	wantPermissionDenied(t, "app SELECT access_log", err)
	_, err = app.ExecContext(ctx, "SELECT * FROM vault.deks")
	wantPermissionDenied(t, "app SELECT deks", err)

	tok := newToken()
	if err := dbPutCard(ctx, app, tok, []byte{1, 2, 3}, "4242", 1); err != nil {
		t.Fatalf("app put_card: %v", err)
	}
	ct, kv, err := dbGetCard(ctx, app, tok, "0A1B2C")
	if err != nil || !bytes.Equal(ct, []byte{1, 2, 3}) || kv != 1 {
		t.Fatalf("app get_card: ct=%x kv=%d err=%v", ct, kv, err)
	}
	if _, _, err := dbGetCard(ctx, app, newToken(), "0A1B2C"); !errors.Is(err, errUnknownToken) {
		t.Errorf("app get_card unseeded: err = %v, want errUnknownToken", err)
	}
	if _, err := dbListDEKs(ctx, app); err != nil {
		t.Errorf("app list_deks: %v", err)
	}

	rot := integrationDB(t, "vault_rotator")
	// 32 bytes: the fake KMS reverses bytes and loadDEKs requires a 32-byte DEK for every row.
	wrapped := bytes.Repeat([]byte{0x07}, 32)
	v, err := dbAddDEK(ctx, rot, wrapped)
	if err != nil || v <= 0 {
		t.Fatalf("rotator add_dek: v=%d err=%v", v, err)
	}
	// 42501 = insufficient_privilege.
	if err := dbPutCard(ctx, rot, newToken(), []byte{1}, "4242", 1); err == nil || !strings.Contains(err.Error(), "42501") {
		t.Errorf("rotator put_card: err = %v, want sqlstate 42501", err)
	}
	if _, _, err := dbGetCard(ctx, rot, tok, "0A1B2C"); err == nil || !strings.Contains(err.Error(), "42501") {
		t.Errorf("rotator get_card: err = %v, want sqlstate 42501", err)
	}
	_, err = rot.ExecContext(ctx, "SELECT * FROM vault.deks")
	wantPermissionDenied(t, "rotator SELECT deks", err)
	deks, err := dbListDEKs(ctx, rot)
	if err != nil {
		t.Fatalf("rotator list_deks: %v", err)
	}
	if !bytes.Equal(deks[v], wrapped) {
		t.Errorf("list_deks[%d] = %x, want the wrapped value just added", v, deks[v])
	}
}

func countRows(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count query: %v", err)
	}
	return n
}

func TestIntegrationAccessLogCount(t *testing.T) {
	ctx := context.Background()
	owner := integrationDB(t, "")
	app := integrationDB(t, "vault_app")

	n0 := countRows(t, owner, "SELECT count(*) FROM vault.access_log")
	var toks []string
	for range 3 {
		tok := newToken()
		toks = append(toks, tok)
		if err := dbPutCard(ctx, app, tok, []byte{9}, "1111", 1); err != nil {
			t.Fatalf("put_card: %v", err)
		}
	}
	for _, tok := range toks[:2] {
		if _, _, err := dbGetCard(ctx, app, tok, "0A"); err != nil {
			t.Fatalf("get_card: %v", err)
		}
	}
	if n := countRows(t, owner, "SELECT count(*) FROM vault.access_log"); n != n0+5 {
		t.Errorf("access_log rows = %d, want %d", n, n0+5)
	}
	if n := countRows(t, owner, "SELECT count(*) FROM vault.access_log WHERE token = ANY($1) AND op = 'put' AND caller IS NULL", toks); n != 3 {
		t.Errorf("put rows = %d, want 3", n)
	}
	if n := countRows(t, owner, "SELECT count(*) FROM vault.access_log WHERE token = ANY($1) AND op = 'get' AND caller = '0A'", toks); n != 2 {
		t.Errorf("get rows = %d, want 2", n)
	}
}

func TestIntegrationSearchPathPinned(t *testing.T) {
	owner := integrationDB(t, "")
	rows, err := owner.QueryContext(context.Background(), `
		SELECT p.proname, coalesce(array_to_string(p.proconfig, E'\n'), '')
		  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		 WHERE n.nspname = 'vault'`)
	if err != nil {
		t.Fatalf("query pg_proc: %v", err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var name, config string
		if err := rows.Scan(&name, &config); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[name] = true
		if !slices.Contains(strings.Split(config, "\n"), "search_path=vault, pg_temp") {
			t.Errorf("%s proconfig = %q, want search_path=vault, pg_temp", name, config)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	want := map[string]bool{"put_card": true, "get_card": true, "list_deks": true, "add_dek": true}
	if !maps.Equal(got, want) {
		t.Errorf("vault functions = %v, want %v", slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(want)))
	}
}

func TestIntegrationVelocityPerToken(t *testing.T) {
	ctx := context.Background()
	app := integrationDB(t, "vault_app")
	tok := newToken()
	if err := dbPutCard(ctx, app, tok, []byte{5}, "4242", 1); err != nil {
		t.Fatalf("put_card: %v", err)
	}
	for i := range 20 {
		if _, _, err := dbGetCard(ctx, app, tok, "0A"); err != nil {
			t.Fatalf("get %d: %v", i+1, err)
		}
	}
	if _, _, err := dbGetCard(ctx, app, tok, "0A"); !errors.Is(err, errVelocity) {
		t.Errorf("get 21: err = %v, want errVelocity", err)
	}
}

func TestIntegrationVelocityConcurrent(t *testing.T) {
	ctx := context.Background()
	owner := integrationDB(t, "")
	app := integrationDB(t, "vault_app")
	app.SetMaxOpenConns(64)
	tok := newToken()
	if err := dbPutCard(ctx, app, tok, []byte{6}, "4242", 1); err != nil {
		t.Fatalf("put_card: %v", err)
	}

	const calls = 50
	start := make(chan struct{})
	var wg sync.WaitGroup
	var ok, velocity, other atomic.Int32
	for range calls {
		wg.Go(func() {
			<-start
			_, _, err := dbGetCard(ctx, app, tok, "0A")
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, errVelocity):
				velocity.Add(1)
			default:
				other.Add(1)
				t.Errorf("concurrent get: %v", err)
			}
		})
	}
	close(start)
	wg.Wait()
	if ok.Load() != 20 || velocity.Load() != calls-20 || other.Load() != 0 {
		t.Errorf("concurrent gets: %d ok, %d velocity, %d other; want 20, %d, 0", ok.Load(), velocity.Load(), other.Load(), calls-20)
	}
	if n := countRows(t, owner, "SELECT count(*) FROM vault.access_log WHERE token = $1 AND op = 'get'", tok); n != 20 {
		t.Errorf("get rows for token = %d, want 20", n)
	}
}

func TestIntegrationVelocityGlobal(t *testing.T) {
	ctx := context.Background()
	owner := integrationDB(t, "")
	app := integrationDB(t, "vault_app")

	var used []string
	t.Cleanup(func() {
		// Test DB only: remove this test's lookups so later tests in the same minute aren't throttled.
		if _, err := owner.ExecContext(context.Background(), "DELETE FROM vault.access_log WHERE token = ANY($1)", used); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	n := countRows(t, owner, "SELECT count(*) FROM vault.access_log WHERE op = 'get' AND at > now() - interval '1 minute'")
	if n >= 300 {
		t.Fatalf("%d recent gets already; cannot run", n)
	}
	for i := range 300 - n {
		tok := newToken()
		used = append(used, tok)
		if _, _, err := dbGetCard(ctx, app, tok, "0A"); err != nil && !errors.Is(err, errUnknownToken) {
			t.Fatalf("get %d of %d: %v", i+1, 300-n, err)
		}
	}
	tok := newToken()
	used = append(used, tok)
	if _, _, err := dbGetCard(ctx, app, tok, "0A"); !errors.Is(err, errVelocity) {
		t.Errorf("get past the global limit: err = %v, want errVelocity", err)
	}
}

// ---------------------------------------------------------------------------
// End-to-end acceptance: real listeners and TLS, real database, DEK rotation, and the
// opt-in live Stripe check. These tests replace package-level base URLs and must not call t.Parallel.
// ---------------------------------------------------------------------------

// roundTrip sends a request and returns status, headers and body; a transport error fails the test.
// header holds the request headers to set.
func roundTrip(t *testing.T, c *http.Client, method, target, body string, header map[string]string) (int, http.Header, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, target, rd)
	if err != nil {
		t.Fatal("building request failed")
	}
	for k, val := range header {
		req.Header.Set(k, val)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: transport error", method, req.URL.Path)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: reading response failed", method, req.URL.Path)
	}
	return resp.StatusCode, resp.Header, b
}

// hasLogLine reports whether one line of logged contains every part.
func hasLogLine(logged string, parts ...string) bool {
	for _, line := range strings.Split(logged, "\n") {
		all := true
		for _, p := range parts {
			all = all && strings.Contains(line, p)
		}
		if all {
			return true
		}
	}
	return false
}

// TestIntegrationEndToEnd boots the vault the way main does (dev config, real database as
// vault_app, DEK v1) behind both real TLS listeners, with the fake TLS provider standing in for
// the stripe_t account (testCatalogJSON, via pointAccount), and walks the full acceptance flow: browser
// preflight + tokenize with a cardholder name, platform /proxy with the {account, token, request}
// envelope (placeholders incl. {{name}}) and a forged Authorization header, healthz, and the mTLS
// refusal of a client without a certificate.
func TestIntegrationEndToEnd(t *testing.T) {
	ctx := context.Background()
	cfg := config{
		env:          "dev",
		publicAddr:   "127.0.0.1:0",
		internalAddr: "127.0.0.1:0",
		allowOrigin:  testOrigin,
		dbURL:        integrationURL(t, "vault_app"),
		devDEK:       bytes.Repeat([]byte{0x5e}, 32),
	}
	db, err := openDB(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("database ping: %v", err)
	}
	deks, current, err := loadDEKs(ctx, cfg, db, nil, nil)
	if err != nil || current != 1 {
		t.Fatalf("loadDEKs: current=%d err=%v", current, err)
	}

	fp := newFakeProvider(t, nil)
	// Account secrets as a dev boot loads them: every dev account secret from its dev variable.
	cat := testCatalog(t, testCatalogHost)
	devSecrets := func(k string) string {
		if strings.HasPrefix(k, "VAULT_DEV_SECRET_") {
			return testSecret
		}
		return ""
	}
	if err := loadAccountSecrets(ctx, cat, cfg, devSecrets, nil, nil); err != nil {
		t.Fatalf("loadAccountSecrets: %s", safeErr(err, testSecret))
	}
	v := newVault(cfg, db, deks, current, testHMACKey, cat, newOutboundClient(nil), log.New(&testLog, "", 0))
	pointAccount(t, v, "stripe_t", fp.ts)

	_, caPool, serverCert, clientCert := testPKI(t)
	public, internal := newServers(v, cfg, serverCert, caPool)
	serve := func(srv *http.Server) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go srv.ServeTLS(ln, "", "")
		t.Cleanup(func() { srv.Close() })
		return "https://" + ln.Addr().String()
	}
	pubURL, intURL := serve(public), serve(internal)
	n0 := testLog.Len()

	// Browser at VAULT_ALLOW_ORIGIN: preflight, then tokenize with a valid session token.
	browser := tlsClient(t, caPool)
	status, h, _ := roundTrip(t, browser, http.MethodOptions, pubURL+"/tokenize", "", map[string]string{
		"Origin":                         testOrigin,
		"Access-Control-Request-Method":  "POST",
		"Access-Control-Request-Headers": "authorization,content-type",
	})
	if status != http.StatusNoContent || h.Get("Access-Control-Allow-Origin") != testOrigin {
		t.Fatalf("preflight: status %d, want 204 with the allowed origin", status)
	}
	status, h, body := roundTrip(t, browser, http.MethodPost, pubURL+"/tokenize", tokBody(map[string]any{"name": testName}), map[string]string{
		"Origin":        testOrigin,
		"Authorization": "Bearer " + mintSession(testHMACKey, time.Now().Add(10*time.Minute)),
		"Content-Type":  "application/json",
	})
	var tr tokenizeResponse
	if status != http.StatusOK || json.Unmarshal(body, &tr) != nil {
		t.Fatalf("tokenize: status %d, want 200 with a JSON body", status)
	}
	if !tokenRe.MatchString(tr.Token) || tr.Last4 != "4242" || tr.ExpMonth != "12" || tr.ExpYear != "2030" ||
		h.Get("Access-Control-Allow-Origin") != testOrigin {
		t.Fatal("tokenize: response fields or CORS header wrong")
	}

	// Platform without a client certificate: the TLS handshake is refused, no handler runs.
	nNoCert := testLog.Len()
	req, err := http.NewRequest(http.MethodGet, intURL+"/healthz", nil)
	if err != nil {
		t.Fatal("building request failed")
	}
	if resp, err := tlsClient(t, caPool).Do(req); err == nil {
		resp.Body.Close()
		t.Fatalf("internal listener answered a client without a certificate: status %d", resp.StatusCode)
	}
	if strings.Contains(testLog.since(nNoCert), "listener=internal") {
		t.Error("a request without a client certificate reached the internal handler")
	}

	// Platform with its certificate: stripe_t POST /v1/tokens with a forged inbound Authorization
	// header (the inbound headers are never used; the envelope carries the platform's headers).
	platform := tlsClient(t, caPool, clientCert)
	e2eBody := stripeTokensBody + "&card[name]={{name}}"
	env := newEnvelope("stripe_t", "POST", "/v1/tokens", map[string]string{"Idempotency-Key": "e2e-1"}, e2eBody)
	env.Token = tr.Token
	status, _, body = roundTrip(t, platform, http.MethodPost, intURL+"/proxy", envelopeJSON(env), map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer sk_test_attacker",
	})
	if status != http.StatusOK {
		t.Fatalf("proxy: status %d, want 200", status)
	}
	if string(body) != `{"id":"pm_123"}` {
		t.Errorf("proxy: body is not the provider's body (%d bytes)", len(body))
	}
	hits, method, path, sentHeader, sent := fp.last()
	if hits != 1 || method != http.MethodPost || path != "/v1/tokens" {
		t.Fatalf("provider saw %d requests, last %s %s; want 1 POST /v1/tokens", hits, method, path)
	}
	if sentHeader.Get("Authorization") != "Bearer "+testSecret || sentHeader.Get("Idempotency-Key") != "e2e-1" {
		t.Error("provider did not receive the vault's own secret as the credential, or the platform's Idempotency-Key")
	}
	// The tokenized card (goodBody: 12/2030, CVV 9071, name testName) substituted into the platform's body.
	if want := seededValues("form", e2eBody); string(sent) != want {
		t.Errorf("provider body is not the platform body plus the tokenized card, CVV and name (len %d, want %d)", len(sent), len(want))
	}

	status, _, body = roundTrip(t, platform, http.MethodGet, intURL+"/healthz", "", nil)
	if status != http.StatusOK || string(body) != "{\"status\":\"ok\"}\n" {
		t.Errorf("healthz: status %d (%d bytes), want 200 {\"status\":\"ok\"}", status, len(body))
	}

	logged := testLog.since(n0)
	for _, parts := range [][]string{
		{"req listener=public method=OPTIONS path=/tokenize status=204"},
		{"req listener=public method=POST path=/tokenize status=200"},
		{"req listener=internal method=POST path=/proxy status=200", "caller=0A1B2C"},
		{"req listener=internal method=GET path=/healthz status=200", "caller=0A1B2C"},
	} {
		if !hasLogLine(logged, parts...) {
			t.Errorf("no access-log line with %q", parts)
		}
	}
}

// TestIntegrationRotateDEK covers DEK loading and rotation: -rotate-dek (as vault_rotator,
// KMS via the fake metadata server and fake KMS) creates a new version; after a "restart" (a
// second loadDEKs as vault_app) every version loads and a token sealed under the old DEK resolves.
// The KMS settings are what prod passes (no dev DEK). The pools are opened in dev mode because
// the test database speaks trust auth without TLS; prod openDB (verified TLS + IAM token) is
// covered by TestOpenDB.
func TestIntegrationRotateDEK(t *testing.T) {
	ctx := context.Background()
	open := func(role string) *sql.DB {
		db, err := openDB(config{env: "dev", dbURL: integrationURL(t, role)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
	rotDB, appDB := open("vault_rotator"), open("vault_app")
	newFakeMetadata(t, nil)
	k := newFakeKMS(t)
	c := newOutboundClient(nil)
	ts := &tokenSource{client: c}
	kmsCfg := config{env: "prod", kmsKey: testKMSKey}

	vOld, err := rotateDEK(ctx, kmsCfg, rotDB, c, ts)
	if err != nil || vOld <= 0 {
		t.Fatalf("first rotation: version=%d err=%v", vOld, err)
	}
	deks, cur, err := loadDEKs(ctx, kmsCfg, appDB, c, ts)
	if err != nil || cur != vOld || len(deks[vOld]) != dekSize {
		t.Fatalf("load after first rotation: current=%d (want %d) err=%v", cur, vOld, err)
	}

	// A card tokenized under the then-current DEK.
	pt, err := json.Marshal(card{PAN: testPAN, ExpMonth: "12", ExpYear: "2030"})
	if err != nil {
		t.Fatal("marshal card failed")
	}
	tok := newToken()
	if err := dbPutCard(ctx, appDB, tok, seal(deks[cur], pt, cardAAD(tok)), "4242", cur); err != nil {
		t.Fatalf("put_card: %v", err)
	}

	vNew, err := rotateDEK(ctx, kmsCfg, rotDB, c, ts)
	if err != nil || vNew != vOld+1 {
		t.Fatalf("second rotation: version=%d err=%v, want %d", vNew, err, vOld+1)
	}

	// Restart: both versions load, current is the highest.
	deks2, cur2, err := loadDEKs(ctx, kmsCfg, appDB, c, ts)
	if err != nil {
		t.Fatalf("load after second rotation: %v", err)
	}
	maxVer := 0
	for ver := range deks2 {
		maxVer = max(maxVer, ver)
	}
	if cur2 != vNew || cur2 != maxVer {
		t.Errorf("current = %d, want %d (the highest version)", cur2, vNew)
	}
	for _, ver := range []int{vOld, vNew} {
		if len(deks2[ver]) != dekSize {
			t.Errorf("version %d not loaded as a 32-byte DEK", ver)
		}
	}
	if !bytes.Equal(deks2[vOld], deks[vOld]) {
		t.Error("the old DEK changed across restarts")
	}
	if bytes.Equal(deks2[vOld], deks2[vNew]) {
		t.Error("two rotations produced the same DEK")
	}
	// Every DEK came through KMS decrypt: the fake KMS wraps by reversing the bytes.
	wrapped, err := dbListDEKs(ctx, appDB)
	if err != nil {
		t.Fatalf("list_deks: %v", err)
	}
	if len(wrapped) != len(deks2) {
		t.Errorf("loaded %d DEKs, list_deks has %d", len(deks2), len(wrapped))
	}
	for ver, d := range deks2 {
		if !bytes.Equal(reversed(wrapped[ver]), d) {
			t.Errorf("version %d was not unwrapped by KMS decrypt", ver)
		}
	}
	if k.count() == 0 {
		t.Error("fake KMS was never called")
	}

	// The old token still resolves under its own key version.
	ct, kv, err := dbGetCard(ctx, appDB, tok, "0A1B2C")
	if err != nil || kv != vOld {
		t.Fatalf("get_card: key_version=%d (want %d) err=%v", kv, vOld, err)
	}
	got, err := unseal(deks2[kv], ct, cardAAD(tok))
	var cd card
	if err != nil || json.Unmarshal(got, &cd) != nil || cd.PAN != testPAN || cd.ExpMonth != "12" || cd.ExpYear != "2030" {
		t.Error("the old token does not resolve to its card after rotation")
	}
	if _, err := unseal(deks2[vNew], ct, cardAAD(tok)); err == nil {
		t.Error("the old ciphertext opens under the new DEK")
	}
}

// TestIntegrationRotationTwoInstances runs a rolling deploy after a rotation: two vaults on one
// database and one (fake) KMS, both booted with the old key. After the rotation only A has
// refreshed. A card tokenized on A (sealed under the new key) proxies through B, which learns the
// key on demand; then a card tokenized on B proxies through A. No request fails to decrypt.
func TestIntegrationRotationTwoInstances(t *testing.T) {
	ctx := context.Background()
	open := func(role string) *sql.DB {
		db, err := openDB(config{env: "dev", dbURL: integrationURL(t, role)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
	rotDB, appDB := open("vault_rotator"), open("vault_app")
	newFakeMetadata(t, nil)
	newFakeKMS(t)
	c := newOutboundClient(nil)
	ts := &tokenSource{client: c}
	cfg := config{env: "prod", kmsKey: testKMSKey, allowOrigin: testOrigin}
	fp := newFakeProvider(t, nil)

	vOld, err := rotateDEK(ctx, cfg, rotDB, c, ts)
	if err != nil {
		t.Fatalf("first rotation: %v", err)
	}
	instance := func() *vault {
		deks, cur, err := loadDEKs(ctx, cfg, appDB, c, ts)
		if err != nil || cur != vOld {
			t.Fatalf("boot load: current=%d (want %d) err=%v", cur, vOld, err)
		}
		cat := testCatalog(t, testCatalogHost)
		for _, a := range cat.accounts {
			for name := range a.secretNames {
				a.secrets[name] = testSecret
			}
		}
		v := newVault(cfg, appDB, deks, cur, testHMACKey, cat, c, log.New(&testLog, "", 0))
		v.refreshDEKs = dekRefresher(v, cfg, appDB, c, ts)
		pointAccount(t, v, "stripe_t", fp.ts)
		return v
	}
	a, b := instance(), instance()
	n0 := testLog.Len()

	vNew, err := rotateDEK(ctx, cfg, rotDB, c, ts)
	if err != nil || vNew != vOld+1 {
		t.Fatalf("second rotation: version=%d err=%v, want %d", vNew, err, vOld+1)
	}
	if err := a.refresh(ctx); err != nil {
		t.Fatalf("A refresh: %v", err)
	}
	if cur, _ := a.currentDEK(); cur != vNew {
		t.Fatalf("A current after refresh = %d, want %d", cur, vNew)
	}
	if _, ok := b.dek(vNew); ok {
		t.Fatal("B holds the new key before any refresh")
	}

	tokenizeOn := func(v *vault) string {
		t.Helper()
		authz := "Bearer " + mintSession(testHMACKey, time.Now().Add(10*time.Minute))
		rec := serveTokenize(v, tokRequest(tokCase{authz: authz, body: tokBody(map[string]any{"cvv": nil})}))
		var tr tokenizeResponse
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &tr) != nil {
			t.Fatalf("tokenize: status %d, want 200", rec.Code)
		}
		if _, kv, err := dbGetCard(ctx, appDB, tr.Token, "0A1B2C"); err != nil || kv != vNew {
			t.Fatalf("stored key_version=%d (want %d) err=%v", kv, vNew, err)
		}
		return tr.Token
	}
	proxyOn := func(v *vault, tok string) {
		t.Helper()
		hits, _, _, _, _ := fp.last()
		if rec := serveInternal(v, tokensRequest(tok, stripeTokensNoCVV)); rec.Code != http.StatusOK {
			t.Fatalf("proxy: status %d, want 200", rec.Code)
		}
		if h, _, _, _, _ := fp.last(); h != hits+1 {
			t.Fatal("proxy did not reach the provider exactly once")
		}
	}

	proxyOn(b, tokenizeOn(a))
	if cur, _ := b.currentDEK(); cur != vNew {
		t.Fatalf("B current after its on-demand refresh = %d, want %d", cur, vNew)
	}
	proxyOn(a, tokenizeOn(b))

	if strings.Contains(testLog.since(n0), "decrypt_failed") {
		t.Fatal("a request failed to decrypt during the rotation")
	}
}

// stripeShow makes a Stripe response body printable in a failure message: PAN masked, the key,
// the test cardholder name and its form encoding redacted, at most 2 KiB.
func stripeShow(b []byte, secret string) string {
	m, _ := maskPAN(b, testPAN)
	out := strings.NewReplacer(secret, "<redacted>", testName, "<name>", url.QueryEscape(testName), "<name>").Replace(string(m))
	if len(out) > 2048 {
		out = out[:2048] + "…"
	}
	return out
}

// TestStripeLive runs tokenize (with a cardholder name) → /proxy against the real Stripe test-mode
// API through the embedded catalog's stripe_test account, with a forged inbound Authorization
// header: POST /v1/tokens with the CVV, then again without it (the CVV was used). Each returns a
// single-use tok_; the platform charges or creates a PaymentMethod from it with its own keys.
// It runs only when VAULT_TEST_STRIPE_SECRET holds a test-mode key (sk_test_…), which is never
// printed. That the objects show up in the vault's Stripe dashboard is still checked by hand.
func TestStripeLive(t *testing.T) {
	secret := os.Getenv("VAULT_TEST_STRIPE_SECRET")
	if !strings.HasPrefix(secret, "sk_test_") {
		t.Skip("set VAULT_TEST_STRIPE_SECRET to a Stripe test-mode key (sk_test_…) to run")
	}
	v, _ := embeddedStripeVault(t, secret) // in-memory store, host api.stripe.com
	v.client = newOutboundClient(nil)

	rec := serveTokenize(v, tokRequest(tokCase{body: tokBody(map[string]any{"cvv": "314", "name": testName})}))
	var tr tokenizeResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &tr) != nil {
		t.Fatalf("tokenize: status %d", rec.Code)
	}

	for _, c := range []struct {
		name, path, body string
		wantID           *regexp.Regexp
	}{
		{"tokens", "/v1/tokens", embeddedTokensBody, regexp.MustCompile(`"id":\s*"tok_`)},
		{"tokens (CVV used)", "/v1/tokens", embeddedTokensNoCVV, regexp.MustCompile(`"id":\s*"tok_`)},
	} {
		r := stripeProxyRequest(tr.Token, c.path, nil, c.body)
		r.Header.Set("Authorization", "Bearer sk_test_attacker")
		rec = serveInternal(v, r)
		if rec.Code != http.StatusOK || !c.wantID.Match(rec.Body.Bytes()) {
			t.Errorf("%s: status %d, body (PAN masked, key and name redacted): %s", c.name, rec.Code, stripeShow(rec.Body.Bytes(), secret))
		}
	}
}

// TestStripeMock checks the vault's real outbound Stripe requests, built from platform form bodies
// through the embedded catalog's stripe provider, against Stripe's published API definition by
// sending them to stripe/stripe-mock (`make stripe-mock-test`). It runs only when
// VAULT_TEST_STRIPE_MOCK_URL names stripe-mock's plain-HTTP port on a loopback address.
//
// stripe-mock's built-in HTTPS certificate is an X.509 v1 cert with CN=localhost and no SANs, which
// Go cannot hostname-verify for any ServerName, and stripe-mock takes no cert flags. So the vault
// talks TLS to a test-only relay (an httptest TLS server whose certificate is the only root in the
// vault client's pool, exactly as pointAccount does for the fake provider): the vault's client is
// the unmodified, fully verifying newOutboundClient. The relay forwards method, path, headers and
// body unchanged to stripe-mock over loopback HTTP and returns its status, headers and body.
//
// catalog.json's only Stripe endpoint is POST /v1/tokens (a single-use tok_), with customer
// forbidden. POST /v1/payment_methods (storage) and POST /v1/payment_intents are not in the catalog.
func TestStripeMock(t *testing.T) {
	raw := os.Getenv("VAULT_TEST_STRIPE_MOCK_URL")
	if raw == "" {
		t.Skip("set VAULT_TEST_STRIPE_MOCK_URL (e.g. via `make stripe-mock-test`) to run")
	}
	target, err := url.Parse(raw)
	if err != nil || target.Scheme != "http" || target.Path != "" && target.Path != "/" {
		t.Fatal("VAULT_TEST_STRIPE_MOCK_URL must be http://<loopback>:<port>")
	}
	if h := target.Hostname(); h != "localhost" && !(net.ParseIP(h) != nil && net.ParseIP(h).IsLoopback()) {
		t.Fatalf("VAULT_TEST_STRIPE_MOCK_URL host %q is not loopback", h)
	}
	const secret = "sk_test_123" // stripe-mock accepts any sk_test_ key

	// What stripe-mock received for the latest request; recorded by the relay, never printed.
	type seen struct {
		hits                      int
		method, path, idem        string
		authOK, formOK, userAgent bool
		body                      []byte
	}
	var mu sync.Mutex
	var last seen
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target) // no SetXForwarded: headers reach stripe-mock as the vault sent them
		},
		Transport:     &http.Transport{Proxy: nil},
		ErrorLog:      log.New(io.Discard, "", 0),
		FlushInterval: -1,
	}
	relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "relay read failed", http.StatusBadGateway)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		mu.Lock()
		last = seen{
			hits:      last.hits + 1,
			method:    r.Method,
			path:      r.URL.Path,
			idem:      r.Header.Get("Idempotency-Key"),
			authOK:    slices.Equal(r.Header.Values("Authorization"), []string{"Bearer " + secret}),
			formOK:    r.Header.Get("Content-Type") == "application/x-www-form-urlencoded",
			userAgent: r.Header.Get("User-Agent") == "pan-vault/1",
			body:      body,
		}
		mu.Unlock()
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(relay.Close)

	v, s := embeddedStripeVault(t, secret)
	pointAccount(t, v, "stripe_test", relay)
	hits := func() int {
		mu.Lock()
		defer mu.Unlock()
		return last.hits
	}

	// call sends one platform request and checks what reached stripe-mock: exactly one request,
	// POST path, the vault's credential only, form Content-Type, the vault's User-Agent, the
	// platform's Idempotency-Key if it sent one, and a body equal to the platform's body with the
	// seeded card (12/2030, testCVV, testName) substituted. Bodies are compared, never printed.
	call := func(name, tok, path, body string, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		before := hits()
		rec := serveInternal(v, stripeProxyRequest(tok, path, headers, body))
		mu.Lock()
		got := last
		mu.Unlock()
		if got.hits != before+1 {
			t.Fatalf("%s: stripe-mock got %d requests, want 1 (vault status %d)", name, got.hits-before, rec.Code)
		}
		if got.method != "POST" || got.path != path {
			t.Errorf("%s: outbound %s %s, want POST %s", name, got.method, got.path, path)
		}
		if !got.authOK {
			t.Errorf("%s: stripe-mock did not receive exactly the vault credential", name) // never print it
		}
		if !got.formOK || !got.userAgent {
			t.Errorf("%s: outbound Content-Type or User-Agent wrong", name)
		}
		if got.idem != headers["Idempotency-Key"] {
			t.Errorf("%s: outbound Idempotency-Key is not the platform's", name)
		}
		if want := seededValues("form", body); string(got.body) != want {
			t.Errorf("%s: outbound body is not the platform body plus the card values (len %d, want %d)", name, len(got.body), len(want))
		}
		return rec
	}
	// refused sends one platform request that the vault must refuse with status/msg before any
	// request reaches stripe-mock.
	refused := func(name, tok, path, body string, status int, msg string) {
		t.Helper()
		before := hits()
		rec := serveInternal(v, stripeProxyRequest(tok, path, nil, body))
		if rec.Code != status || rec.Body.String() != wantErrBody(msg) {
			t.Errorf("%s: status %d, want %d %q", name, rec.Code, status, msg)
		}
		if n := hits() - before; n != 0 {
			t.Errorf("%s: %d requests reached stripe-mock, want 0", name, n)
		}
	}
	ok := func(name string, rec *httptest.ResponseRecorder, id *regexp.Regexp) {
		t.Helper()
		if rec.Code != http.StatusOK || !id.Match(rec.Body.Bytes()) {
			t.Errorf("%s: status %d, body len %d (PAN masked, name redacted): %s", name, rec.Code, rec.Body.Len(), stripeShow(rec.Body.Bytes(), secret))
		}
	}
	tokID := regexp.MustCompile(`"id":\s*"tok_`)

	// 1. tokens with {{cvv}} and the platform's Idempotency-Key.
	tokA := seedCardNamed(t, v, s, testCVV, testName)
	ok("tokens", call("tokens", tokA, "/v1/tokens", embeddedTokensBody,
		map[string]string{"Idempotency-Key": "smock-tok-1"}), tokID)

	// 2. The CVV of tokA was used: {{cvv}} again is 409 with nothing sent; the platform resends
	// without card[cvc].
	refused("tokens (CVV used)", tokA, "/v1/tokens", embeddedTokensBody, http.StatusConflict, msgCVVUnavailable)
	ok("tokens without cvv", call("tokens without cvv", tokA, "/v1/tokens", embeddedTokensNoCVV, nil), tokID)

	// 3. Refused before the relay, leaving the CVV cached: a token cloned through customer, a token
	// request without {{pan}} (it would only borrow the vault's credential), and the endpoints that
	// are not in the catalog.
	tokB := seedCardNamed(t, v, s, testCVV, testName)
	refused("tokens + customer", tokB, "/v1/tokens", embeddedTokensBody+"&customer=cus_123", http.StatusBadRequest, msgForbiddenField)
	refused("tokens without {{pan}}", tokB, "/v1/tokens", "pii[id_number]=x", http.StatusBadRequest, msgPlaceholder)
	refused("payment_methods (not in the catalog)", tokB, "/v1/payment_methods",
		"type=card&card[number]={{pan}}&card[exp_month]={{exp_month}}&card[exp_year]={{exp_year}}&card[cvc]={{cvv}}",
		http.StatusBadRequest, msgEndpointNotAllowed)
	refused("payment_intents (not in the catalog)", tokB, "/v1/payment_intents",
		"amount=1000&currency=usd&confirm=true&payment_method_data[type]=card&payment_method_data[card][number]={{pan}}",
		http.StatusBadRequest, msgEndpointNotAllowed)
	ok("tokens after refusals", call("tokens after refusals", tokB, "/v1/tokens", embeddedTokensBody, nil), tokID)
}
