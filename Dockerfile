# syntax=docker/dockerfile:1

# ---- Stage 1: build ----
# CGO is required because go-sqlite3 compiles the bundled C SQLite engine, so we
# need a C toolchain (gcc + musl-dev) in the builder.
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /app

# Cache module downloads separately from source for faster rebuilds.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o relay .

# ---- Stage 2: run ----
# Minimal runtime: just the static-ish binary + CA certs (needed for outbound
# HTTPS to Web Push services). go-sqlite3 links musl, which Alpine provides.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/relay .

# Internal port; the host port is auto-assigned by vps-deploy and proxied by the
# shared Nginx. Keep in sync with RELAY_PORT.
EXPOSE 8080

# The SQLite volume is mounted here in production (see docker-compose.yml).
VOLUME ["/data"]

CMD ["./relay"]
