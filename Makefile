.PHONY: build test lint vuln deps-check vendor-check image image-repro ci tools itest stripe-mock-test ci-all

# Tools from the module's toolchain (go.mod `toolchain go1.27.3`), not whatever is first on PATH.
GOFMT   = $(shell go env GOROOT)/bin/gofmt

# Pinned tool versions, built with the module's toolchain into the repo-local, gitignored .tools/bin
# (never the user's GOBIN or ~/go/bin). `make tools` installs each one that is missing or was built
# from another version or toolchain; lint and vuln depend on it so that `make ci` works on a clean
# checkout with nothing pre-installed.
TOOLBIN             = $(CURDIR)/.tools/bin
TOOLCHAIN           = go1.27.3
STATICCHECK_VERSION = v0.8.2
GOVULNCHECK_VERSION = v1.9.0

# unpack=false: with Docker's containerd image store, rewrite-timestamp conflicts with the
# exporter's default unpack=true. The image is unpacked on first `docker run`.
IMAGE       = pan-vault:local
IMAGE_BUILD = docker buildx build --provenance=false --build-arg SOURCE_DATE_EPOCH=0 \
              --output type=docker,name=$(IMAGE),rewrite-timestamp=true,unpack=false

PG_NAME = pan-vault-pg
PG_PORT ?= 55432

# stripe/stripe-mock v0.206.0 (index digest of :latest on 2026-10-01). Only its plain-HTTP port is
# published, on loopback: its HTTPS cert has no SANs, so TestStripeMock relays the vault's TLS
# requests through a test-only httptest TLS server (see the test's comment).
STRIPE_MOCK_IMAGE := stripe/stripe-mock@sha256:aeb96b83e87a893d2ac005e363ac01ffa6e59a5ad85b49c155dfc9129de02e78
STRIPE_MOCK_NAME  = pan-vault-stripe-mock
STRIPE_MOCK_PORT ?= 12111

build:
	CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w -buildid=" -o vault .

test:
	go test -race -count=1 ./...

# gofmt fails closed: a gofmt that cannot run, or that lists any file, fails the target
# (make runs recipes without pipefail, so `gofmt -l . | (! grep .)` would pass a failing gofmt).
lint: tools
	@out=$$($(GOFMT) -l .) || { echo "lint: gofmt failed"; exit 1; }; \
	test -z "$$out" || { echo "lint: gofmt would reformat:"; echo "$$out"; exit 1; }
	go vet ./...
	"$(TOOLBIN)/staticcheck" ./...

vuln: tools
	"$(TOOLBIN)/govulncheck" ./...

deps-check:
	go mod tidy -diff
	@# -mod=readonly, not -mod=mod: -mod=mod writes extra go.sum lines, dirtying the tree and the count below.
	@direct="$$(GOFLAGS=-mod=readonly go list -m -f '{{if and (not .Main) (not .Indirect)}}{{.Path}}{{end}}' all)"; \
	if [ "$$direct" != "github.com/jackc/pgx/v5" ]; then \
		echo "deps-check: direct requirements must be exactly github.com/jackc/pgx/v5, got:"; echo "$$direct"; exit 1; \
	fi
	@count=$$(cut -d' ' -f1 go.sum | sort -u | wc -l); baseline=$$(cat deps-baseline.txt); \
	if [ "$$count" -gt "$$baseline" ]; then \
		echo "deps-check: go.sum lists $$count modules, baseline is $$baseline"; exit 1; \
	fi; \
	echo "deps-check: ok ($$count modules in go.sum, baseline $$baseline)"

# vendor/ must be exactly what `go mod vendor` produces from go.mod/go.sum: no edited, added or
# missing file. The reference copy goes to a temp dir; the working tree is never modified.
vendor-check:
	@tmp=$$(mktemp -d) || exit 1; trap 'rm -rf "$$tmp"' EXIT; \
	go mod vendor -o "$$tmp/vendor" || { echo "vendor-check: go mod vendor failed"; exit 1; }; \
	if ! diff -r "$$tmp/vendor" vendor >/dev/null; then \
		echo "vendor-check: vendor/ differs from 'go mod vendor' output:"; \
		diff -rq "$$tmp/vendor" vendor | sed "s|$$tmp/vendor|(go mod vendor)|g"; exit 1; \
	fi; \
	echo "vendor-check: ok"

image:
	$(IMAGE_BUILD) .
	@docker image inspect --format '{{.Id}}' $(IMAGE)

image-repro:
	@set -e; \
	$(IMAGE_BUILD) --no-cache .; a=$$(docker image inspect --format '{{.Id}}' $(IMAGE)); \
	$(IMAGE_BUILD) --no-cache .; b=$$(docker image inspect --format '{{.Id}}' $(IMAGE)); \
	if [ "$$a" != "$$b" ]; then echo "image-repro: digests differ: $$a vs $$b"; exit 1; fi; \
	echo "image-repro: ok $$a"

ci: lint vuln deps-check vendor-check test build

# A tool is current when `go version -m` reports the pinned toolchain and module version; any
# other file under its name in .tools/bin (another version, a script) is removed and the pinned
# one installed. GOBIN is set only for the install command, so nothing outside the repo changes.
tools:
	@set -e; \
	current() { info=$$(go version -m "$(TOOLBIN)/$$1" 2>/dev/null) || return 1; \
		printf '%s\n' "$$info" | head -n 1 | grep -q ": $(TOOLCHAIN)\$$" && \
		printf '%s\n' "$$info" | grep -q "^[[:space:]]*mod[[:space:]]*$$2[[:space:]]*$$3[[:space:]]"; }; \
	mkdir -p "$(TOOLBIN)"; \
	if ! current staticcheck honnef.co/go/tools $(STATICCHECK_VERSION); then \
		echo "tools: installing staticcheck $(STATICCHECK_VERSION)"; \
		rm -f "$(TOOLBIN)/staticcheck"; \
		GOBIN="$(TOOLBIN)" GOTOOLCHAIN=$(TOOLCHAIN) go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION); \
		current staticcheck honnef.co/go/tools $(STATICCHECK_VERSION) || { echo "tools: staticcheck not at $(STATICCHECK_VERSION) in $(TOOLBIN)"; exit 1; }; \
	fi; \
	if ! current govulncheck golang.org/x/vuln $(GOVULNCHECK_VERSION); then \
		echo "tools: installing govulncheck $(GOVULNCHECK_VERSION)"; \
		rm -f "$(TOOLBIN)/govulncheck"; \
		GOBIN="$(TOOLBIN)" GOTOOLCHAIN=$(TOOLCHAIN) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION); \
		current govulncheck golang.org/x/vuln $(GOVULNCHECK_VERSION) || { echo "tools: govulncheck not at $(GOVULNCHECK_VERSION) in $(TOOLBIN)"; exit 1; }; \
	fi

# Integration tests against a throwaway postgres:18 with trust auth, published on loopback only
# (trust auth must never be reachable from the network); the container is always removed.
itest:
	@docker rm -f $(PG_NAME) >/dev/null 2>&1 || true
	@trap 'docker rm -f $(PG_NAME) >/dev/null 2>&1' EXIT; trap 'exit 130' INT TERM; \
	docker run -d --name $(PG_NAME) -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1:$(PG_PORT):5432 postgres:18 >/dev/null || exit 1; \
	ready=0; for i in $$(seq 1 60); do \
		if psql -q postgres://postgres@127.0.0.1:$(PG_PORT)/postgres -c 'select 1' >/dev/null 2>&1; then ready=1; break; fi; \
		sleep 1; \
	done; \
	[ $$ready -eq 1 ] || { echo "itest: postgres did not become ready"; exit 1; }; \
	psql -q -v ON_ERROR_STOP=1 postgres://postgres@127.0.0.1:$(PG_PORT)/postgres \
		-c 'CREATE ROLE vault_owner LOGIN CREATEROLE;' -c 'CREATE DATABASE vault OWNER vault_owner;' || exit 1; \
	psql -q -v ON_ERROR_STOP=1 postgres://vault_owner@127.0.0.1:$(PG_PORT)/vault -f schema.sql || exit 1; \
	VAULT_TEST_DB_URL='postgres://vault_owner@127.0.0.1:$(PG_PORT)/vault?sslmode=disable' \
		go test -race -count=1 -run Integration ./...

# Request-shape check of the catalog's Stripe endpoints against stripe-mock (Stripe's OpenAPI
# definition); the container is always removed and the test's exit status is propagated.
stripe-mock-test:
	@docker rm -f $(STRIPE_MOCK_NAME) >/dev/null 2>&1 || true
	@trap 'docker rm -f $(STRIPE_MOCK_NAME) >/dev/null 2>&1' EXIT; trap 'exit 130' INT TERM; \
	docker run -d --name $(STRIPE_MOCK_NAME) -p 127.0.0.1:$(STRIPE_MOCK_PORT):12111 $(STRIPE_MOCK_IMAGE) >/dev/null || exit 1; \
	ready=0; for i in $$(seq 1 60); do \
		if curl -s -o /dev/null http://127.0.0.1:$(STRIPE_MOCK_PORT)/; then ready=1; break; fi; \
		sleep 1; \
	done; \
	[ $$ready -eq 1 ] || { echo "stripe-mock-test: stripe-mock did not become ready"; exit 1; }; \
	VAULT_TEST_STRIPE_MOCK_URL=http://127.0.0.1:$(STRIPE_MOCK_PORT) \
		go test -race -count=1 -run StripeMock -v ./...

ci-all: ci itest stripe-mock-test image-repro
