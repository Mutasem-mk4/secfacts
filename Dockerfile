# --- Build Stage ---
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

WORKDIR /app

# Copy go mod and sum files first to leverage Docker cache
COPY axon/go.mod axon/go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY axon/ ./

# Build the binary statically
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
    -ldflags "-s -w -X main.version=1.0.0" \
    -o axon ./cmd/axon

# --- Final Stage ---
FROM gcr.io/distroless/static:latest

WORKDIR /

# Copy the binary from the builder stage
COPY --from=builder /app/axon /axon

# Use a non-root user for security
USER 65532:65532

ENTRYPOINT ["/axon"]
CMD ["--help"]

