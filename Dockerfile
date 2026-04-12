# Base image
FROM rust:alpine AS builder

# Create appuser
ENV USER=axiomguard
ENV UID=10001

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

RUN apk add --no-cache musl-dev openssl-dev

WORKDIR /app

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./

# Copy all workspace members
COPY common common
COPY engine engine
COPY proto proto
COPY service service
COPY service-cli service-cli
COPY client client
COPY client-cli client-cli
COPY benchmark benchmark
COPY proxy proxy

# Build release binary
RUN cargo build --release --package service-cli

# Precache embedding model so runtime doesn't need to download
ENV HF_HOME=/app/.cache/huggingface
ENV FASTEMBED_CACHE_PATH=/app/.cache/fastembed
RUN /app/target/release/service-cli --precache

# Final stage
FROM alpine:3.18.3

# Import user from builder
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Copy CA certificates and binary
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/target/release/service-cli /usr/local/bin/axiomguard

# Copy precached embedding models
COPY --from=builder /app/.cache /app/.cache
ENV HF_HOME=/app/.cache/huggingface
ENV FASTEMBED_CACHE_PATH=/app/.cache/fastembed

# Create configuration directory
RUN mkdir -p /etc/axiomguard && chmod -R 755 /app/.cache

# Copy production config
COPY config.production.toml /etc/axiomguard/config.toml

USER axiomguard:axiomguard

EXPOSE 50051
EXPOSE 9090

CMD ["axiomguard", "--config", "/etc/axiomguard/config.toml"]
