FROM docker.io/library/rust:1.88-bookworm AS builder

WORKDIR /workspace
COPY Cargo.toml Cargo.lock ./
COPY apps ./apps
COPY crates ./crates

RUN cargo build --locked --release -p udp-file-tui -p udp-file-server

FROM docker.io/library/debian:bookworm-slim

ENV RUST_BACKTRACE=1

RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
        ca-certificates \
        conntrack \
        iproute2 \
        iptables \
        jq \
        netcat-openbsd \
        nftables \
        procps \
        socat \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/udp-file /usr/local/bin/udp-file
COPY --from=builder /workspace/target/release/udp-file-server /usr/local/bin/udp-file-server
COPY tests/network/entrypoint.sh /usr/local/bin/transfer-network-entrypoint
COPY tests/network/scenario-runner.sh /usr/local/bin/transfer-scenario-runner
COPY tests/scenarios/assert-path.sh /usr/local/bin/transfer-assert-path

RUN chmod 0755 \
        /usr/local/bin/transfer-network-entrypoint \
        /usr/local/bin/transfer-scenario-runner \
        /usr/local/bin/transfer-assert-path

ENTRYPOINT ["/usr/local/bin/transfer-network-entrypoint"]
