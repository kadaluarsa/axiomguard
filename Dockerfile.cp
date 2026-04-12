FROM rust:1.82-bookworm AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/axiomguard

COPY Cargo.toml Cargo.lock ./

COPY common/ common/
COPY sdk/ sdk/
COPY tool-wrappers/common/ tool-wrappers/common/
COPY control-plane/ control-plane/

RUN mkdir -p proto/src && echo "" > proto/src/lib.rs \
 && mkdir -p engine/src && echo "" > engine/src/lib.rs \
 && mkdir -p service/src && echo "" > service/src/lib.rs \
 && mkdir -p client/src && echo "" > client/src/lib.rs \
 && mkdir -p benchmark/src && echo "" > benchmark/src/lib.rs \
 && mkdir -p service-cli/src && echo "" > service-cli/src/lib.rs \
 && mkdir -p client-cli/src && echo "" > client-cli/src/lib.rs \
 && mkdir -p proxy/src && echo "" > proxy/src/lib.rs \
 && mkdir -p mcp-server/src && echo "" > mcp-server/src/lib.rs \
 && mkdir -p tool-wrappers/exec/src && echo "" > tool-wrappers/exec/src/lib.rs \
 && mkdir -p tool-wrappers/file/src && echo "" > tool-wrappers/file/src/lib.rs \
 && mkdir -p tool-wrappers/http/src && echo "" > tool-wrappers/http/src/lib.rs \
 && mkdir -p security/bypass_suite/src && echo "" > security/bypass_suite/src/lib.rs

RUN cargo build --release -p axiomguard-cp 2>/dev/null || true

COPY common/ common/
COPY sdk/ sdk/
COPY tool-wrappers/common/ tool-wrappers/common/
COPY control-plane/ control-plane/

RUN cargo build --release -p axiomguard-cp

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash axiomguard

COPY --from=builder /usr/src/axiomguard/target/release/axiomguard-cp /usr/local/bin/axiomguard-cp

USER axiomguard

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8080/v1/health || exit 1

CMD ["axiomguard-cp"]
