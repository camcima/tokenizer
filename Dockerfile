FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS build
ARG SOURCE_DATE_EPOCH
WORKDIR /src
# Only the build inputs: no .git (no VCS stamping), no spec/, no local state.
COPY go.mod go.sum main.go catalog.json ./
COPY vendor/ vendor/
RUN printf 'nonroot:x:65532:65532::/:/sbin/nologin\n' > /passwd
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w -buildid=" -o vault .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /passwd /etc/passwd
COPY --from=build /src/vault /vault
USER 65532:65532
ENTRYPOINT ["/vault"]
