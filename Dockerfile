# -------------------------------------------------------------
# Builder stage – compile the Go server
# -------------------------------------------------------------
FROM golang:1.22-alpine AS builder

# Install git for go mod download (if needed)
RUN apk add --no-cache git

WORKDIR /src

# Cache module download
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build a fully static binary (no CGO)
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN go build -ldflags="-s -w" -o /out/atp-server ./server/main.go

# -------------------------------------------------------------
# Runtime stage – minimal hardened image
# -------------------------------------------------------------
FROM gcr.io/distroless/static:nonroot

WORKDIR /

# Copy the compiled binary
COPY --from=builder /out/atp-server /usr/local/bin/atp-server

# Expose the internal port (Caddy will proxy to this)
EXPOSE 8080

# Declare the data directory as a volume (runtime storage)
VOLUME ["/data"]

# Entry point
ENTRYPOINT ["/usr/local/bin/atp-server"]