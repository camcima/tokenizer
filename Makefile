.PHONY: build test lint vuln deps-check vendor-check image image-repro ci tools itest stripe-mock-test ci-all \
        fuzz fuzz-long gitleaks hooks docs-check docs-links mermaid-check comment-check commit-check \
        cover cover-html cover-check

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
GITLEAKS_VERSION    = v8.30.1
LEFTHOOK_VERSION    = v2.2.2

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

ci: lint vuln deps-check vendor-check docs-check mermaid-check comment-check gitleaks test build

# The three READMEs are one document in three languages. docs-check fails if any of them repeats
# a retired claim (case-insensitive), or if their heading, table-row or Mermaid-block counts
# differ, which catches a section, table row or diagram changed in one language only. It runs
# docs-links first.
READMES       = README.md README.es.md README.pt-BR.md
RETIRED_DOCS  = rewraps automatically|reenvuelve automáticamente|reencapsula automaticamente|\
                keeps the platform out of PCI scope|mantiene la plataforma fuera del alcance|\
                mantiene a la plataforma fuera del alcance|mantém a plataforma fora do escopo|\
                created daily|se crea diariamente|se crea una nueva clave de datos cada día|\
                criada diariamente
docs-check: docs-links
	@fail=0; retired='$(RETIRED_DOCS)'; \
	oldifs=$$IFS; IFS='|'; \
	for p in $$retired; do \
		p=$$(printf '%s' "$$p" | sed 's/^ *//; s/ *$$//'); \
		if grep -n -i -F -e "$$p" $(READMES); then echo "docs-check: retired claim: $$p"; fail=1; fi; \
	done; \
	IFS=$$oldifs; \
	for pat in '^#' '^|' '^```mermaid'; do \
		counts=""; for f in $(READMES); do counts="$$counts $$(grep -c -e "$$pat" $$f)"; done; \
		if [ $$(printf '%s\n' $$counts | sort -u | wc -l) -ne 1 ]; then \
			echo "docs-check: '$$pat' line counts differ across $(READMES):$$counts"; fail=1; \
		fi; \
	done; \
	[ $$fail -eq 0 ] && echo "docs-check: ok"

# Every link in the READMEs and docs/**/*.md must resolve to an existing, non-ignored file and,
# with a #fragment, to a heading of the target Markdown file (rules in scripts/check-doc-links.sh).
docs-links:
	@scripts/check-doc-links.sh

# Every ```mermaid block in the same files must render with the pinned Mermaid CLI, which fails
# on a syntax error that GitHub would show as a broken diagram. npx installs the pinned version
# on first use (Node is required; CI sets it up) and is asked once for the mmdc path, which saves
# npx's start-up on every file. mmdc renders each block of a file to SVG and writes a rewritten
# copy of the file; both go to a temp dir, never the working tree.
# --no-sandbox: Chrome's sandbox needs unprivileged user namespaces, which some hosts refuse
# (Ubuntu 23.10+ with AppArmor's default, many containers). The browser only renders this
# repository's own diagrams, as the same user that `make ci` already runs the test code as.
# A system Chrome is used when PUPPETEER_EXECUTABLE_PATH is set (puppeteer reads it).
MERMAID_CLI_VERSION = 12.0.0
NPX_MMDC = npx --yes --package @mermaid-js/mermaid-cli@$(MERMAID_CLI_VERSION)
mermaid-check:
	@files=$$(scripts/check-doc-links.sh --list) || { echo "mermaid-check: cannot list the documentation files"; exit 1; }; \
	files=$$(grep -l '^```mermaid' $$files); \
	mmdc=$$($(NPX_MMDC) -c 'command -v mmdc') && [ -x "$$mmdc" ] || { echo "mermaid-check: cannot install @mermaid-js/mermaid-cli@$(MERMAID_CLI_VERSION)"; exit 1; }; \
	tmp=$$(mktemp -d) || exit 1; trap 'rm -rf "$$tmp"' EXIT; \
	printf '{"args":["--no-sandbox"]}\n' > "$$tmp/puppeteer.json"; \
	fail=0; n=0; \
	for f in $$files; do \
		n=$$((n+1)); mkdir -p "$$tmp/$$n"; \
		if ! "$$mmdc" -q -p "$$tmp/puppeteer.json" -i "$$f" -o "$$tmp/$$n/out.md" >"$$tmp/log" 2>&1; then \
			echo "mermaid-check: $$f does not render:"; cat "$$tmp/log"; fail=1; \
		fi; \
	done; \
	[ $$fail -eq 0 ] && echo "mermaid-check: ok ($$n files)"

# The comment rule of the pre-commit hook, over every tracked Go file outside vendor/.
comment-check:
	@scripts/check-comments.sh $$(git ls-files '*.go' ':!:vendor/*') && echo "comment-check: ok"

# The commit-msg hook's rule over every commit in COMMIT_RANGE (CI passes the pull request's or
# the push's range), so a commit made without the hook still fails CI.
COMMIT_RANGE ?= origin/main..HEAD
commit-check:
	@commits=$$(git rev-list --reverse $(COMMIT_RANGE)) || { echo "commit-check: bad range $(COMMIT_RANGE)"; exit 1; }; \
	fail=0; n=0; \
	for c in $$commits; do \
		n=$$((n+1)); \
		out=$$(scripts/check-commit-msg.sh --message "$$(git log -1 --format=%B $$c)") || { echo "commit-check: $$c"; echo "$$out"; fail=1; }; \
	done; \
	[ $$fail -eq 0 ] && echo "commit-check: ok ($$n commits in $(COMMIT_RANGE))"

# Fuzzing: every Fuzz* target in the package, one after another (the engine fuzzes one target per
# run). `make fuzz` runs each for 20s (pull requests); `make fuzz-long` for FUZZTIME (nightly). The
# seeds alone also run in `make test`. A failing input is saved under testdata/fuzz/<Target>/; fix
# the code and commit that file so it stays a regression test.
FUZZTIME ?= 10m
FUZZ_RUN = set -e; \
	targets=$$(go test -list '^Fuzz' . | grep '^Fuzz'); \
	[ -n "$$targets" ] || { echo "fuzz: no Fuzz targets found"; exit 1; }; \
	for t in $$targets; do \
		echo "fuzz: $$t for $(1)"; \
		go test -run='^$$' -fuzz="^$$t\$$" -fuzztime=$(1) .; \
	done

fuzz:
	@$(call FUZZ_RUN,20s)

fuzz-long:
	@$(call FUZZ_RUN,$(FUZZTIME))

# Secret scan of the full git history (every commit, not just the tree) with the default rules plus
# the allowlist of synthetic test literals in .gitleaks.toml.
gitleaks: tools
	"$(TOOLBIN)/gitleaks" git --redact --no-banner --verbose --config .gitleaks.toml .

# Installs the lefthook git hooks (lefthook.yml) into this clone's .git/hooks. Opt-in per clone.
hooks: tools
	"$(TOOLBIN)/lefthook" install

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
	fi; \
	if ! current gitleaks github.com/zricethezav/gitleaks/v8 $(GITLEAKS_VERSION); then \
		echo "tools: installing gitleaks $(GITLEAKS_VERSION)"; \
		rm -f "$(TOOLBIN)/gitleaks"; \
		GOBIN="$(TOOLBIN)" GOTOOLCHAIN=$(TOOLCHAIN) go install github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION); \
		current gitleaks github.com/zricethezav/gitleaks/v8 $(GITLEAKS_VERSION) || { echo "tools: gitleaks not at $(GITLEAKS_VERSION) in $(TOOLBIN)"; exit 1; }; \
	fi; \
	if ! current lefthook github.com/evilmartians/lefthook/v2 $(LEFTHOOK_VERSION); then \
		echo "tools: installing lefthook $(LEFTHOOK_VERSION)"; \
		rm -f "$(TOOLBIN)/lefthook"; \
		GOBIN="$(TOOLBIN)" GOTOOLCHAIN=$(TOOLCHAIN) go install github.com/evilmartians/lefthook/v2@$(LEFTHOOK_VERSION); \
		current lefthook github.com/evilmartians/lefthook/v2 $(LEFTHOOK_VERSION) || { echo "tools: lefthook not at $(LEFTHOOK_VERSION) in $(TOOLBIN)"; exit 1; }; \
	fi

# A throwaway postgres:18 with trust auth, published on loopback only (trust auth must never be
# reachable from the network), with role vault_owner, database vault and schema.sql applied. It is a
# shell fragment, not a target, so the container lives exactly as long as the recipe line that uses
# it: the EXIT trap always removes it. itest and cover-check share this one definition.
PG_TEST_URL = postgres://vault_owner@127.0.0.1:$(PG_PORT)/vault?sslmode=disable
PG_UP = docker rm -f $(PG_NAME) >/dev/null 2>&1 || true; \
	trap 'docker rm -f $(PG_NAME) >/dev/null 2>&1' EXIT; trap 'exit 130' INT TERM; \
	docker run -d --name $(PG_NAME) -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1:$(PG_PORT):5432 postgres:18 >/dev/null || exit 1; \
	ready=0; for i in $$(seq 1 60); do \
		if psql -q postgres://postgres@127.0.0.1:$(PG_PORT)/postgres -c 'select 1' >/dev/null 2>&1; then ready=1; break; fi; \
		sleep 1; \
	done; \
	[ $$ready -eq 1 ] || { echo "$@: postgres did not become ready"; exit 1; }; \
	psql -q -v ON_ERROR_STOP=1 postgres://postgres@127.0.0.1:$(PG_PORT)/postgres \
		-c 'CREATE ROLE vault_owner LOGIN CREATEROLE;' -c 'CREATE DATABASE vault OWNER vault_owner;' || exit 1; \
	psql -q -v ON_ERROR_STOP=1 postgres://vault_owner@127.0.0.1:$(PG_PORT)/vault -f schema.sql || exit 1

# Integration tests against the throwaway database above.
itest:
	@$(PG_UP); \
	VAULT_TEST_DB_URL='$(PG_TEST_URL)' go test -race -count=1 -run Integration ./...

# Statement coverage of the package, written as Go's binary coverage data so that the unit run and
# the integration run merge per statement (adding two percentages would count a statement covered
# by both twice). The integration run happens only when VAULT_TEST_DB_URL is set; without it the
# figure is the unit tests' alone, and the last line says so. The unit run clears VAULT_TEST_DB_URL
# so the integration tests run once, in their own run. No -race: it only slows the run. The boot
# tests' main() subprocesses write their counters to the same directory (runMain passes it on).
COVER_DIR = $(CURDIR)/cover
cover:
	@rm -rf "$(COVER_DIR)" && mkdir -p "$(COVER_DIR)/unit" || exit 1; \
	VAULT_TEST_DB_URL= go test -count=1 -cover -covermode=atomic ./... -args -test.gocoverdir="$(COVER_DIR)/unit" || exit 1; \
	inputs="$(COVER_DIR)/unit"; scope=unit; \
	if [ -n "$$VAULT_TEST_DB_URL" ]; then \
		mkdir -p "$(COVER_DIR)/integration" || exit 1; \
		go test -count=1 -cover -covermode=atomic -run Integration ./... \
			-args -test.gocoverdir="$(COVER_DIR)/integration" || exit 1; \
		inputs="$$inputs,$(COVER_DIR)/integration"; scope=unit+integration; \
	else \
		echo "cover: VAULT_TEST_DB_URL is not set, so the integration tests did not run (make cover-check starts a database)"; \
	fi; \
	go tool covdata textfmt -i="$$inputs" -o "$(COVER_DIR)/cover.out" || exit 1; \
	go tool cover -func="$(COVER_DIR)/cover.out" > "$(COVER_DIR)/func.txt" || exit 1; \
	cat "$(COVER_DIR)/func.txt"; \
	total=$$(awk '/^total:/ { sub(/%/, "", $$NF); print $$NF }' "$(COVER_DIR)/func.txt"); \
	[ -n "$$total" ] || { echo "cover: no total in the coverage report"; exit 1; }; \
	echo "cover: $$total% of statements ($$scope)" | tee "$(COVER_DIR)/summary.txt"

# The HTML report of the last `make cover` (run first when there is none). It is written, not opened:
# open cover/cover.html in a browser.
cover-html:
	@[ -f "$(COVER_DIR)/cover.out" ] || $(MAKE) --no-print-directory cover || exit 1; \
	go tool cover -html="$(COVER_DIR)/cover.out" -o "$(COVER_DIR)/cover.html" && echo "cover-html: $(COVER_DIR)/cover.html"

# COVERAGE_MIN is a regression guard, not a target: the merged unit+integration figure measured when
# the gate was added (92.2%; unit alone 90.7%), rounded down to an integer, minus 1 point of slack so
# that a small, legitimate change does not fail CI. Raise it when coverage rises; never lower it to
# make a change pass. The figure is always the merged one: with VAULT_TEST_DB_URL unset, cover-check
# starts its own database (PG_UP), as CI's integration job does.
COVERAGE_MIN = 91
cover-check:
	@if [ -n "$$VAULT_TEST_DB_URL" ]; then \
		$(MAKE) --no-print-directory cover || exit 1; \
	else \
		$(PG_UP); \
		VAULT_TEST_DB_URL='$(PG_TEST_URL)' $(MAKE) --no-print-directory cover || exit 1; \
	fi; \
	grep -q '(unit+integration)$$' "$(COVER_DIR)/summary.txt" || { echo "cover-check: the integration tests did not run"; exit 1; }; \
	total=$$(awk '/^total:/ { sub(/%/, "", $$NF); print $$NF }' "$(COVER_DIR)/func.txt"); \
	if awk -v t="$$total" -v m="$(COVERAGE_MIN)" 'BEGIN { exit !(t + 0 >= m + 0) }'; then \
		echo "cover-check: ok ($$total% >= COVERAGE_MIN $(COVERAGE_MIN)%)" | tee -a "$(COVER_DIR)/summary.txt"; \
	else \
		echo "cover-check: coverage $$total% is below COVERAGE_MIN $(COVERAGE_MIN)% (unit+integration)" | tee -a "$(COVER_DIR)/summary.txt"; \
		exit 1; \
	fi

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

ci-all: ci itest stripe-mock-test cover-check image-repro
