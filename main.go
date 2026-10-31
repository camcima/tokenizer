package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// ---------------------------------------------------------------------------
// Boot: configuration, GCP REST access, DEKs, secrets, rotation, listeners, shutdown
// ---------------------------------------------------------------------------

// config is the parsed environment. Secret values held here (dev mode only) are never logged.
type config struct {
	env, publicAddr, internalAddr, certFile, keyFile, clientCAFile, allowOrigin, dbURL string
	kmsKey, hmacSecretName                                                             string
	devDEK, devHMAC                                                                    []byte
}

// devVars are the fixed dev-mode secret variables; each is refused when VAULT_ENV=prod. Account
// secrets have one dev variable each (devSecretVar), refused in prod by devVarSet's prefix check.
var devVars = []string{"VAULT_DEV_DEK_HEX", "VAULT_DEV_SESSION_HMAC_HEX"}

// KMS key and Secret Manager names must have exactly the documented shape, with
// segments of [A-Za-z0-9_-] only. They are concatenated into request URLs, so "..", "?", "#",
// ":" or an extra "/versions/N" could otherwise redirect the call to another resource. (Domain-
// scoped project IDs like "example.com:p" are therefore not supported.)
var (
	kmsKeyRe     = regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/locations/[A-Za-z0-9_-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+$`)
	secretNameRe = regexp.MustCompile(`^projects/[A-Za-z0-9_-]+/secrets/[A-Za-z0-9_-]+$`)
)

// loadConfig parses the environment. Errors name the variable, never its value.
// rotate selects -rotate-dek mode, which needs only VAULT_ENV, VAULT_DB_URL and VAULT_KMS_KEY.
// An empty variable counts as unset. With VAULT_ENV=prod each VAULT_DEV_* variable
// refuses boot (main additionally refuses any other VAULT_DEV_* name, see devVarSet), in rotate
// mode too.
func loadConfig(getenv func(string) string, rotate bool) (config, error) {
	cfg := config{env: getenv("VAULT_ENV")}
	if cfg.env != "dev" && cfg.env != "prod" {
		return config{}, errors.New("VAULT_ENV must be dev or prod")
	}
	if cfg.env == "prod" {
		for _, k := range devVars {
			if getenv(k) != "" {
				return config{}, errors.New(k + " is refused when VAULT_ENV=prod")
			}
		}
	}
	if !rotate {
		for _, f := range []struct {
			name string
			dst  *string
		}{
			{"VAULT_CERT", &cfg.certFile},
			{"VAULT_KEY", &cfg.keyFile},
			{"VAULT_CLIENT_CA", &cfg.clientCAFile},
			{"VAULT_ALLOW_ORIGIN", &cfg.allowOrigin},
		} {
			if *f.dst = getenv(f.name); *f.dst == "" {
				return config{}, errors.New(f.name + " is required")
			}
		}
		if !validOrigin(cfg.allowOrigin, cfg.env == "prod") {
			return config{}, errors.New("VAULT_ALLOW_ORIGIN must be an exact origin (scheme://host[:port], https in prod)")
		}
	}
	if cfg.dbURL = getenv("VAULT_DB_URL"); cfg.dbURL == "" {
		return config{}, errors.New("VAULT_DB_URL is required")
	}
	cfg.kmsKey = getenv("VAULT_KMS_KEY")
	if cfg.kmsKey != "" && !kmsKeyRe.MatchString(cfg.kmsKey) {
		return config{}, errors.New("VAULT_KMS_KEY must be projects/P/locations/L/keyRings/R/cryptoKeys/K")
	}
	if rotate {
		if cfg.kmsKey == "" {
			return config{}, errors.New("VAULT_KMS_KEY is required for -rotate-dek")
		}
		return cfg, nil
	}

	cfg.publicAddr = getenv("VAULT_PUBLIC_ADDR")
	if cfg.publicAddr == "" {
		cfg.publicAddr = ":8443"
	}
	cfg.internalAddr = getenv("VAULT_INTERNAL_ADDR")
	if cfg.internalAddr == "" {
		cfg.internalAddr = ":9443"
	}

	cfg.hmacSecretName = getenv("VAULT_SESSION_HMAC_SECRET")
	if cfg.hmacSecretName != "" && !secretNameRe.MatchString(cfg.hmacSecretName) {
		return config{}, errors.New("VAULT_SESSION_HMAC_SECRET must be projects/P/secrets/S")
	}

	// In prod every secret comes from KMS / Secret Manager (dev vars were refused above); in dev
	// each comes from its VAULT_DEV_* variable when set, otherwise from KMS / Secret Manager.
	// Provider account secrets are named by the catalog, not here (loadAccountSecrets).
	if s := getenv("VAULT_DEV_DEK_HEX"); s != "" {
		b, ok := decodeKey64(s)
		if !ok {
			return config{}, errors.New("VAULT_DEV_DEK_HEX must be exactly 64 hex chars")
		}
		cfg.devDEK = b
	} else if cfg.kmsKey == "" {
		return config{}, errors.New("VAULT_KMS_KEY is required (or VAULT_DEV_DEK_HEX in dev)")
	}
	if s := getenv("VAULT_DEV_SESSION_HMAC_HEX"); s != "" {
		b, ok := decodeKey64(s)
		if !ok {
			return config{}, errors.New("VAULT_DEV_SESSION_HMAC_HEX must be exactly 64 hex chars")
		}
		cfg.devHMAC = b
	} else if cfg.hmacSecretName == "" {
		return config{}, errors.New("VAULT_SESSION_HMAC_SECRET is required (or VAULT_DEV_SESSION_HMAC_HEX in dev)")
	}
	return cfg, nil
}

// devVarSet returns the name of the first VAULT_DEV_* variable present in environ (os.Environ
// form), even if empty. main refuses prod boot if there is one, whatever its name.
func devVarSet(environ []string) (string, bool) {
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "VAULT_DEV_") {
			return name, true
		}
	}
	return "", false
}

// decodeKey64 decodes exactly 64 hex chars into 32 bytes.
func decodeKey64(s string) ([]byte, bool) {
	if len(s) != 64 {
		return nil, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

// validOrigin reports whether s is exactly a serialized origin: scheme://host[:port] with no
// userinfo, path, query or fragment, in canonical form (lowercase scheme and host).
// The browser's Origin header is compared byte-for-byte, so a value that
// could never match one (trailing slash, uppercase host, "*") refuses boot; prod requires https.
// The same goes for a port a browser never serializes: the scheme's default (https :443, http
// :80, which browsers omit), an empty port ("host:"), a leading zero, or one outside 1–65535.
func validOrigin(s string, requireHTTPS bool) bool {
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || u.Host != strings.ToLower(u.Host) || u.String() != s {
		return false
	}
	if strings.HasSuffix(u.Host, ":") {
		return false
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || p[0] == '0' || n < 1 || n > 65535 ||
			(u.Scheme == "https" && n == 443) || (u.Scheme == "http" && n == 80) {
			return false
		}
	}
	return u.Scheme == "https" || (!requireHTTPS && u.Scheme == "http")
}

// openDB opens the pool (it connects lazily). dev uses VAULT_DB_URL as is; prod authenticates
// with Cloud SQL IAM: before every new connection the password is set to a fresh metadata
// access token. The pool is capped at 16 open connections in both modes.
// Errors never contain the URL (it can hold credentials).
// In prod every connection path must use TLS with server certificate
// verification (sslmode=verify-ca or verify-full, or require with sslrootcert): the password is
// an OAuth token that also authorizes KMS decrypt, so it must not be sent in clear text or to an
// unverified server. sslmode=prefer/allow/require-without-root-cert/disable refuse boot.
//
// Configuration never comes from files, and pgx reads pg_service.conf when the
// URL sets service/servicefile and a password file when it sets passfile, during ParseConfig.
// Those keys (any letter case, percent-encoded or not) refuse boot before pgx sees the URL. To
// make that check complete, VAULT_DB_URL must be the URL form: the
// keyword/value form ("host=… dbname=…") is refused, as is a query string that does not parse
// strictly (pgx would silently drop such pairs). Accepted residue: pgx's PG* environment
// fallbacks (PGHOST, PGSERVICE, …; the deployment sets none), and its default ~/.pgpass lookup
// when the URL has no password, which in the scratch image resolves to /.pgpass (HOME=/ from
// /etc/passwd), a file that does not exist.
func openDB(cfg config, ts *tokenSource) (*sql.DB, error) {
	if !strings.HasPrefix(cfg.dbURL, "postgres://") && !strings.HasPrefix(cfg.dbURL, "postgresql://") {
		return nil, errors.New("VAULT_DB_URL must be a postgres:// or postgresql:// URL")
	}
	u, err := url.Parse(cfg.dbURL)
	if err != nil {
		return nil, errors.New("VAULT_DB_URL cannot be parsed")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("VAULT_DB_URL cannot be parsed")
	}
	for k := range query {
		if strings.EqualFold(k, "service") || strings.EqualFold(k, "servicefile") || strings.EqualFold(k, "passfile") {
			return nil, errors.New("VAULT_DB_URL must not set service, servicefile or passfile")
		}
	}
	pc, err := pgx.ParseConfig(cfg.dbURL)
	if err != nil {
		return nil, errors.New("VAULT_DB_URL cannot be parsed")
	}
	var db *sql.DB
	switch cfg.env {
	case "dev":
		db = stdlib.OpenDB(*pc)
	case "prod":
		if ts == nil {
			return nil, errors.New("prod database access needs a token source")
		}
		verified := func(tc *tls.Config) bool {
			return tc != nil && (!tc.InsecureSkipVerify || tc.VerifyPeerCertificate != nil)
		}
		ok := verified(pc.TLSConfig)
		for _, fb := range pc.Fallbacks {
			ok = ok && verified(fb.TLSConfig)
		}
		if !ok {
			return nil, errors.New("VAULT_DB_URL must use sslmode=verify-ca or verify-full in prod")
		}
		db = stdlib.OpenDB(*pc, stdlib.OptionBeforeConnect(func(ctx context.Context, cc *pgx.ConnConfig) error {
			tok, err := ts.token(ctx)
			if err != nil {
				return err
			}
			cc.Password = tok
			return nil
		}))
	default:
		return nil, errors.New("VAULT_ENV must be dev or prod")
	}
	db.SetMaxOpenConns(16)
	return db, nil
}

// errNoDEKs is the boot failure when the database holds no DEK.
var errNoDEKs = errors.New("no DEKs found; run vault -rotate-dek first")

// loadDEKs returns every DEK by version and the current (highest) version. In dev with
// VAULT_DEV_DEK_HEX the dev DEK is version 1 and neither the database nor KMS is used.
// Otherwise every vault.list_deks() row is unwrapped via KMS; any failure fails the whole load.
func loadDEKs(ctx context.Context, cfg config, db *sql.DB, c *http.Client, ts *tokenSource) (map[int][]byte, int, error) {
	if cfg.devDEK != nil {
		if cfg.env != "dev" {
			return nil, 0, errors.New("a dev DEK is refused when VAULT_ENV=prod")
		}
		if len(cfg.devDEK) != dekSize {
			return nil, 0, errors.New("VAULT_DEV_DEK_HEX must decode to 32 bytes")
		}
		return map[int][]byte{1: bytes.Clone(cfg.devDEK)}, 1, nil
	}
	if cfg.kmsKey == "" {
		return nil, 0, errors.New("VAULT_KMS_KEY is required")
	}
	wrapped, err := dbListDEKs(ctx, db)
	if err != nil {
		return nil, 0, err
	}
	if len(wrapped) == 0 {
		return nil, 0, errNoDEKs
	}
	return unwrapDEKs(ctx, cfg, c, ts, wrapped, nil)
}

// unwrapDEKs returns a new map holding every DEK of have plus the KMS-unwrapped DEK of each
// wrapped version not in have, and the highest version in it. DEKs already held are shared, not
// unwrapped again, and have itself is not modified. Any KMS failure fails the whole call; the
// DEKs this call unwrapped are zeroed, the held ones are left alone.
func unwrapDEKs(ctx context.Context, cfg config, c *http.Client, ts *tokenSource, wrapped map[int][]byte, have map[int][]byte) (map[int][]byte, int, error) {
	deks := make(map[int][]byte, len(have)+len(wrapped))
	maps.Copy(deks, have)
	var added []int
	for version, w := range wrapped {
		if _, ok := have[version]; ok {
			continue
		}
		dek, err := kmsDecrypt(ctx, c, ts, cfg.kmsKey, w)
		if err != nil {
			for _, a := range added {
				zero(deks[a])
			}
			return nil, 0, fmt.Errorf("DEK version %d: %s", version, err.Error())
		}
		deks[version] = dek
		added = append(added, version)
	}
	current := 0
	for version := range deks {
		current = max(current, version)
	}
	return deks, current, nil
}

// dekRefresher returns the refresh function main wires into v.refreshDEKs: list every wrapped
// DEK, unwrap only the versions v's snapshot lacks and publish the union as the new snapshot, so
// keys only ever accumulate. It runs only under v.refreshMu, so the load and the store cannot
// interleave with another refresh. With a dev DEK there is nothing to refresh.
func dekRefresher(v *vault, cfg config, db *sql.DB, c *http.Client, ts *tokenSource) func(ctx context.Context) error {
	if cfg.devDEK != nil {
		return func(context.Context) error { return nil }
	}
	return func(ctx context.Context) error {
		wrapped, err := dbListDEKs(ctx, db)
		if err != nil {
			return err
		}
		var have map[int][]byte
		if ks := v.keys.Load(); ks != nil {
			have = ks.deks
		}
		deks, current, err := unwrapDEKs(ctx, cfg, c, ts, wrapped, have)
		if err != nil {
			return err
		}
		v.keys.Store(&dekSet{deks: deks, current: current})
		return nil
	}
}

// dekVersions lists the map's versions in ascending order, comma-separated, for the boot log.
func dekVersions(deks map[int][]byte) string {
	vs := make([]int, 0, len(deks))
	for v := range deks {
		vs = append(vs, v)
	}
	slices.Sort(vs)
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ",")
}

// validSecretValue reports whether s is a non-empty run of printable, non-space ASCII.
// Stricter than "no whitespace or control chars": provider keys are ASCII and go
// into an HTTP header, so any non-ASCII byte refuses boot too.
func validSecretValue(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// loadSecrets returns the session HMAC key (32 bytes): from VAULT_DEV_SESSION_HMAC_HEX in
// dev when set, otherwise from Secret Manager. The payload must be exactly 64 hex chars. Errors
// name the variable, never the value. Provider account secrets are loadAccountSecrets'.
func loadSecrets(ctx context.Context, cfg config, c *http.Client, ts *tokenSource) (hmacKey []byte, err error) {
	if cfg.env != "dev" && cfg.devHMAC != nil {
		return nil, errors.New("dev secrets are refused when VAULT_ENV=prod")
	}
	if cfg.devHMAC != nil {
		hmacKey = bytes.Clone(cfg.devHMAC)
	} else {
		raw, err := accessSecret(ctx, c, ts, cfg.hmacSecretName)
		if err != nil {
			return nil, errors.New("VAULT_SESSION_HMAC_SECRET: " + err.Error())
		}
		var ok bool
		hmacKey, ok = decodeKey64(string(raw))
		zero(raw)
		if !ok {
			return nil, errors.New("VAULT_SESSION_HMAC_SECRET: payload must be exactly 64 hex chars")
		}
	}
	if len(hmacKey) != 32 {
		zero(hmacKey)
		return nil, errors.New("session HMAC key must be 32 bytes")
	}
	return hmacKey, nil
}

// devSecretVar is the dev variable of an account secret: VAULT_DEV_SECRET_<ACCOUNT>_<NAME>,
// uppercased, with every character outside [A-Z0-9] replaced by "_".
// parseCatalog refuses a catalog in which two account secrets share one.
func devSecretVar(account, name string) string {
	b := []byte(strings.ToUpper("VAULT_DEV_SECRET_" + account + "_" + name))
	for i, c := range b {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			b[i] = '_'
		}
	}
	return string(b)
}

// checkDevSecretVars runs before the database is touched, so a bad environment fails fast. In dev,
// every VAULT_DEV_* variable in environ (os.Environ form) must be one of devVars or the dev variable
// of a secret of a loaded account, and an account secret variable that is set must be a valid
// secret. In prod it does nothing: main refuses any VAULT_DEV_* there (devVarSet). Errors name the
// variable, account and secret name, never the value.
// An unknown VAULT_DEV_* name refuses a dev boot, even when empty. A misspelt
// account secret variable (or the removed VAULT_DEV_STRIPE_SECRET) would otherwise be ignored and
// the secret silently taken from Secret Manager, or reported missing only after the DEKs load.
func checkDevSecretVars(cat *catalog, env string, environ []string) error {
	if env != "dev" {
		return nil
	}
	if cat == nil {
		return errors.New("catalog not loaded")
	}
	type acctSecret struct{ account, name string }
	known := map[string]acctSecret{}
	for _, a := range cat.accounts {
		for n := range a.secretNames {
			known[devSecretVar(a.name, n)] = acctSecret{a.name, n}
		}
	}
	for _, kv := range environ {
		name, val, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, "VAULT_DEV_") || slices.Contains(devVars, name) {
			continue
		}
		as, ok := known[name]
		if !ok {
			return errors.New(name + " is not a dev variable or the dev variable of a dev catalog account secret")
		}
		if val != "" && !validSecretValue(val) {
			return errors.New("account " + as.account + " secret " + as.name + ": " + name + " must be non-empty printable ASCII without whitespace")
		}
	}
	return nil
}

// loadAccountSecrets fills the secrets of every account of cat (the accounts of cfg.env): in dev
// from the secret's dev variable (devSecretVar) when set, otherwise from Secret Manager by the
// catalog's resource name; prod never reads a dev variable. Every value must pass
// validSecretValue. Errors name the account and secret name, never the value or the resource.
// All or nothing. Every secret of every loaded account must load or boot fails, and
// on failure no account is given any secret. renderRequest's missing-secret path (which would
// already have consumed the CVV) is therefore unreachable in a booted vault.
func loadAccountSecrets(ctx context.Context, cat *catalog, cfg config, getenv func(string) string, c *http.Client, ts *tokenSource) error {
	if cat == nil {
		return errors.New("catalog not loaded")
	}
	if cfg.env != "dev" && cfg.env != "prod" {
		return errors.New("account secrets: environment must be dev or prod")
	}
	loaded := map[string]map[string]string{}
	for _, an := range slices.Sorted(maps.Keys(cat.accounts)) {
		a := cat.accounts[an]
		loaded[an] = map[string]string{}
		for _, n := range slices.Sorted(maps.Keys(a.secretNames)) {
			fail := func(reason string) error { return errors.New("account " + an + " secret " + n + ": " + reason) }
			var v string
			if dv := devSecretVar(an, n); cfg.env == "dev" && getenv(dv) != "" {
				if v = getenv(dv); !validSecretValue(v) {
					return fail(dv + " must be non-empty printable ASCII without whitespace")
				}
			} else {
				raw, err := accessSecret(ctx, c, ts, a.secretNames[n])
				if err != nil {
					return fail(err.Error())
				}
				v = string(raw)
				zero(raw)
				if !validSecretValue(v) {
					return fail("secret must be non-empty printable ASCII without whitespace")
				}
			}
			loaded[an][n] = v
		}
		if len(loaded[an]) != len(a.secretNames) {
			return errors.New("account " + an + ": not every secret loaded")
		}
	}
	for an, secrets := range loaded {
		cat.accounts[an].secrets = secrets
	}
	return nil
}

// rotateDEK generates a 32-byte DEK, wraps it via KMS encrypt, checks that KMS decrypt returns it,
// stores it via vault.add_dek and returns the new version.
// The unwrap check runs before anything is stored, so a wrapped value that boot
// could not unwrap (which would make every later boot fail) never reaches the database.
func rotateDEK(ctx context.Context, cfg config, db *sql.DB, c *http.Client, ts *tokenSource) (int, error) {
	if cfg.kmsKey == "" {
		return 0, errors.New("VAULT_KMS_KEY is required")
	}
	dek := make([]byte, dekSize)
	defer zero(dek)
	rand.Read(dek) // never fails; see newToken
	wrapped, err := kmsEncrypt(ctx, c, ts, cfg.kmsKey, dek)
	if err != nil {
		return 0, err
	}
	back, err := kmsDecrypt(ctx, c, ts, cfg.kmsKey, wrapped)
	if err != nil {
		return 0, err
	}
	same := hmac.Equal(back, dek)
	zero(back)
	if !same {
		return 0, errors.New("kms: wrapped DEK does not unwrap to the generated DEK")
	}
	return dbAddDEK(ctx, db, wrapped)
}

// loadClientCA reads the mTLS client CA: the file must contain exactly one PEM block, of
// type CERTIFICATE, holding a CA certificate.
// Any second PEM block (another certificate, a private key) refuses boot, as does
// a certificate without basicConstraints CA:TRUE.
func loadClientCA(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("client CA: cannot read file")
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return nil, errors.New("client CA: first PEM block is not a CERTIFICATE")
	}
	if extra, _ := pem.Decode(rest); extra != nil {
		return nil, errors.New("client CA: file must contain exactly one PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("client CA: certificate does not parse")
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, errors.New("client CA: certificate is not a CA")
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
}

// dbCallTimeout bounds each request's database call (waiting for a pool slot included), so a
// saturated pool (16 connections, get_card serialized by its advisory lock) or a stalled server
// fails the request with 500 instead of holding it until the listener's WriteTimeout.
const dbCallTimeout = 5 * time.Second

// newVault wires the vault to the database and the loaded key material. Each putCard/getCard
// call runs under dbCallTimeout, derived from the request context (an earlier request deadline
// or a client disconnect still wins).
func newVault(cfg config, db *sql.DB, deks map[int][]byte, current int, hmacKey []byte, cat *catalog, client *http.Client, logger *log.Logger) *vault {
	v := &vault{
		putCard: func(ctx context.Context, token string, ciphertext []byte, last4 string, keyVersion int) error {
			ctx, cancel := context.WithTimeout(ctx, dbCallTimeout)
			defer cancel()
			return dbPutCard(ctx, db, token, ciphertext, last4, keyVersion)
		},
		getCard: func(ctx context.Context, token, caller string) ([]byte, int, error) {
			ctx, cancel := context.WithTimeout(ctx, dbCallTimeout)
			defer cancel()
			return dbGetCard(ctx, db, token, caller)
		},
		ping:        db.PingContext,
		hmacKey:     hmacKey,
		allowOrigin: cfg.allowOrigin,
		cvv:         newCVVCache(cvvCacheTTL, time.Now),
		now:         time.Now,
		log:         logger,
		catalog:     cat,
		client:      client,
	}
	v.keys.Store(&dekSet{deks: deks, current: current})
	return v
}

// newServers builds both listeners. net/http's own error lines are discarded:
// they are neither boot nor ALERT lines and can quote client input.
func newServers(v *vault, cfg config, cert tls.Certificate, clientCAs *x509.CertPool) (public, internal *http.Server) {
	public = &http.Server{
		Addr:              cfg.publicAddr,
		Handler:           v.publicHandler(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	internal = &http.Server{
		Addr:    cfg.internalAddr,
		Handler: v.internalHandler(),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCAs,
		},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	return public, internal
}

const (
	bootDBTimeout   = 5 * time.Second
	bootGCPTimeout  = 60 * time.Second
	shutdownTimeout = 20 * time.Second
)

// main runs the boot sequence, or -rotate-dek. Every log line goes through logf;
// failures log "boot failed: <reason>" with reasons built only from variable names, fixed
// phrases, status codes and SQLSTATEs, and exit 1.
func main() {
	rotate := flag.Bool("rotate-dek", false, "generate, wrap and store a new DEK, print its version, and exit")
	flag.Parse()
	logger := log.New(os.Stderr, "", 0)
	boot := &vault{log: logger, now: time.Now} // logging only, until the real vault exists
	fail := func(reason string) {
		boot.logf("boot failed: %s", reason)
		os.Exit(1)
	}

	// 1. Parse env and fail fast.
	cfg, err := loadConfig(os.Getenv, *rotate)
	if err != nil {
		fail(err.Error())
	}
	if name, ok := devVarSet(os.Environ()); ok && cfg.env == "prod" {
		fail(name + " is refused when VAULT_ENV=prod")
	}
	boot.logf("config loaded env=%s", cfg.env)

	// 1b. Serve mode: load the certificate, key and client CA now, before the database, KMS or
	// Secret Manager is touched, so a bad file costs no network round trip and
	// never boots half way. -rotate-dek has no listeners and never reads them.
	var cert tls.Certificate
	var clientCAs *x509.CertPool
	if !*rotate {
		cert, err = tls.LoadX509KeyPair(cfg.certFile, cfg.keyFile)
		if err != nil {
			fail("VAULT_CERT/VAULT_KEY: cannot load key pair")
		}
		clientCAs, err = loadClientCA(cfg.clientCAFile)
		if err != nil {
			fail("VAULT_CLIENT_CA: " + err.Error())
		}
	}

	// 1c. Serve mode: parse the compiled-in catalog for this environment and check the dev account
	// secret variables, still before any network call. -rotate-dek needs no catalog.
	var cat *catalog
	if !*rotate {
		cat, err = parseCatalog(catalogJSON, cfg.env)
		if err != nil {
			fail(err.Error())
		}
		if err := checkDevSecretVars(cat, cfg.env, os.Environ()); err != nil {
			fail(err.Error())
		}
	}

	client := newOutboundClient(nil) // the single shared client: metadata, KMS, SM, providers
	ts := &tokenSource{client: client}

	// 2. Open the DB (the error never contains the URL).
	db, err := openDB(cfg, ts)
	if err != nil {
		fail(err.Error())
	}

	if *rotate {
		ctx, cancel := context.WithTimeout(context.Background(), bootGCPTimeout)
		version, err := rotateDEK(ctx, cfg, db, client, ts)
		cancel()
		if err != nil {
			fail("rotate: " + err.Error())
		}
		db.Close()
		fmt.Println(version)
		os.Exit(0)
	}

	// The ping error is not logged: pgx connect errors name the host, user and
	// database from VAULT_DB_URL.
	ctx, cancel := context.WithTimeout(context.Background(), bootDBTimeout)
	err = db.PingContext(ctx)
	cancel()
	if err != nil {
		fail("database ping failed")
	}

	// 3. Load DEKs.
	ctx, cancel = context.WithTimeout(context.Background(), bootGCPTimeout)
	deks, current, err := loadDEKs(ctx, cfg, db, client, ts)
	cancel()
	if errors.Is(err, errNoDEKs) {
		boot.logf("%s", errNoDEKs.Error())
		os.Exit(1)
	}
	if err != nil {
		fail(err.Error())
	}
	boot.logf("deks loaded versions=%s current=%d", dekVersions(deks), current)

	// 4. Load secrets: the session HMAC key, then every secret of every loaded catalog account
	// (all or nothing: a missing or invalid one fails the boot).
	ctx, cancel = context.WithTimeout(context.Background(), bootGCPTimeout)
	hmacKey, err := loadSecrets(ctx, cfg, client, ts)
	cancel()
	if err != nil {
		fail(err.Error())
	}
	ctx, cancel = context.WithTimeout(context.Background(), bootGCPTimeout)
	err = loadAccountSecrets(ctx, cat, cfg, os.Getenv, client, ts)
	cancel()
	if err != nil {
		zero(hmacKey)
		fail(err.Error())
	}
	boot.logf("catalog loaded env=%s accounts=%d", cfg.env, len(cat.accounts))

	// 5. Build the vault on the catalog parsed in step 1c.
	v := newVault(cfg, db, deks, current, hmacKey, cat, client, logger)
	v.refreshDEKs = dekRefresher(v, cfg, db, client, ts)

	// Background work runs on bgCtx, cancelled first on shutdown. newVault starts nothing itself,
	// so tests drive these loops directly.
	bgCtx, bgCancel := context.WithCancel(context.Background())
	go v.cvv.run(bgCtx, cvvSweepEvery)
	go v.refreshLoop(bgCtx, dekRefreshEvery)

	// 6. Start both listeners (certificate and client CA were loaded in step 1b).
	// Each socket is bound with net.Listen before serving (ServeTLS("", "") is what
	// ListenAndServeTLS("", "") does after binding), so a bind failure exits 1 before "ready".
	public, internal := newServers(v, cfg, cert, clientCAs)
	pubLn, err := net.Listen("tcp", cfg.publicAddr)
	if err != nil {
		fail("VAULT_PUBLIC_ADDR: cannot listen")
	}
	intLn, err := net.Listen("tcp", cfg.internalAddr)
	if err != nil {
		fail("VAULT_INTERNAL_ADDR: cannot listen")
	}
	serveErr := make(chan string, 2)
	go func() {
		if err := public.ServeTLS(pubLn, "", ""); !errors.Is(err, http.ErrServerClosed) {
			serveErr <- "public"
		}
	}()
	go func() {
		if err := internal.ServeTLS(intLn, "", ""); !errors.Is(err, http.ErrServerClosed) {
			serveErr <- "internal"
		}
	}()
	v.logf("listening public=%s internal=%s", cfg.publicAddr, cfg.internalAddr)

	// 7. Ready.
	v.logf("ready")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-sig:
		bgCancel()
		// Stop accepting and drain both listeners concurrently within one 20s budget.
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		var wg sync.WaitGroup
		for _, srv := range []*http.Server{public, internal} {
			wg.Go(func() { srv.Shutdown(ctx) })
		}
		wg.Wait()
		cancel()
		db.Close()
		os.Exit(0)
	case name := <-serveErr:
		v.logf("listener failed listener=%s", name)
		os.Exit(1)
	}
}
