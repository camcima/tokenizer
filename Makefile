.PHONY: build test lint vuln deps-check image image-repro ci tools itest ci-all

# Tools from the module's toolchain (go.mod `toolchain go1.27.3`), not whatever is first on PATH.
GOFMT   = $(shell go env GOROOT)/bin/gofmt
TOOLBIN = $(or $(shell go env GOBIN),$(shell go env GOPATH)/bin)

# unpack=false: with Docker's containerd image store, rewrite-timestamp conflicts with the
# exporter's default unpack=true. The image is unpacked on first `docker run`.
IMAGE       = pan-vault:local
IMAGE_BUILD = docker buildx build --provenance=false --build-arg SOURCE_DATE_EPOCH=0 \
              --output type=docker,name=$(IMAGE),rewrite-timestamp=true,unpack=false

PG_NAME = pan-vault-pg
PG_PORT ?= 55432

build:
	CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w -buildid=" -o vault .

test:
	go test -race -count=1 ./...

lint:
	$(GOFMT) -l . | (! grep .)
	go vet ./...
	$(TOOLBIN)/staticcheck ./...

vuln:
	$(TOOLBIN)/govulncheck ./...

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

image:
	$(IMAGE_BUILD) .
	@docker image inspect --format '{{.Id}}' $(IMAGE)

image-repro:
	@set -e; \
	$(IMAGE_BUILD) --no-cache .; a=$$(docker image inspect --format '{{.Id}}' $(IMAGE)); \
	$(IMAGE_BUILD) --no-cache .; b=$$(docker image inspect --format '{{.Id}}' $(IMAGE)); \
	if [ "$$a" != "$$b" ]; then echo "image-repro: digests differ: $$a vs $$b"; exit 1; fi; \
	echo "image-repro: ok $$a"

ci: lint vuln deps-check test build

tools:
	GOTOOLCHAIN=go1.27.3 go install honnef.co/go/tools/cmd/staticcheck@v0.8.2
	GOTOOLCHAIN=go1.27.3 go install golang.org/x/vuln/cmd/govulncheck@v1.9.0

# Integration tests against a throwaway postgres:18 with trust auth; the container is always removed.
itest:
	@docker rm -f $(PG_NAME) >/dev/null 2>&1 || true
	@trap 'docker rm -f $(PG_NAME) >/dev/null 2>&1' EXIT; trap 'exit 130' INT TERM; \
	docker run -d --name $(PG_NAME) -e POSTGRES_HOST_AUTH_METHOD=trust -p $(PG_PORT):5432 postgres:18 >/dev/null || exit 1; \
	ready=0; for i in $$(seq 1 60); do \
		if psql -q postgres://postgres@localhost:$(PG_PORT)/postgres -c 'select 1' >/dev/null 2>&1; then ready=1; break; fi; \
		sleep 1; \
	done; \
	[ $$ready -eq 1 ] || { echo "itest: postgres did not become ready"; exit 1; }; \
	psql -q -v ON_ERROR_STOP=1 postgres://postgres@localhost:$(PG_PORT)/postgres \
		-c 'CREATE ROLE vault_owner LOGIN CREATEROLE;' -c 'CREATE DATABASE vault OWNER vault_owner;' || exit 1; \
	psql -q -v ON_ERROR_STOP=1 postgres://vault_owner@localhost:$(PG_PORT)/vault -f schema.sql || exit 1; \
	VAULT_TEST_DB_URL='postgres://vault_owner@localhost:$(PG_PORT)/vault?sslmode=disable' \
		go test -race -count=1 -run Integration ./...

ci-all: ci itest image-repro
