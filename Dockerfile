FROM rust:1.82-slim AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY signatures/ signatures/

RUN cargo build --release --bin agentshield-web

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/agentshield-web /usr/local/bin/agentshield-web
COPY web/static /app/web/static

ENV HOST=0.0.0.0
ENV PORT=8080
ENV STATIC_DIR=/app/web/static
EXPOSE 8080

ENTRYPOINT ["agentshield-web"]
