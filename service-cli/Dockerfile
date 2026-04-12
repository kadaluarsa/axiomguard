# Use Debian for faster builds (Alpine can be slow with Rust)
FROM rust:bookworm AS builder

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

RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY common common
COPY engine engine
COPY proto proto
COPY service service
COPY service-cli service-cli
COPY client client
COPY client-cli client-cli
COPY benchmark benchmark
COPY proxy proxy

# Build release binary (this may take 5-10 minutes)
RUN cargo build --release --package service-cli

# Final stage - use Debian for glibc compatibility
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder /app/target/release/service-cli /usr/local/bin/axiomguard

RUN mkdir -p /etc/axiomguard

COPY config.production.toml /etc/axiomguard/config.toml

USER axiomguard:axiomguard

EXPOSE 50051
EXPOSE 9090

CMD ["axiomguard", "--config", "/etc/axiomguard/config.toml"]
