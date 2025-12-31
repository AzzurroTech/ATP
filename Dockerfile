# -------------------------------------------------------------
# Builder – compile the Go server
# -------------------------------------------------------------
FROM golang:1.22-alpine AS builder

# Install git (needed for go mod download if you have private modules)
RUN apk add --no-cache git

WORKDIR /src

# Cache module download
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build a fully static binary (no CGO, no dynamic linking)
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN go build -ldflags="-s -w" -o /out/atp-server ./server/main.go

# -------------------------------------------------------------
# Runtime – ultra‑minimal, hardened image
# -------------------------------------------------------------
FROM gcr.io/distroless/static:nonroot

WORKDIR /

# Copy the compiled binary from the builder stage
COPY --from=builder /out/atp-server /usr/local/bin/atp-server

# Expose the internal port (Caddy will proxy to this)
EXPOSE 8080

# Declare the data directory as a volume (runtime storage)
VOLUME ["/data"]

# Environment variable for HMAC secret (must be supplied at runtime)
ENV ATTP_HMAC_SECRET=change-me-to-a-long-random-string

# Healthcheck – simple HTTP GET on /health
HEALTHCHECK --interval=30s --timeout=5s \
  CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/atp-server"]