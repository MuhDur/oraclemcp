# syntax=docker/dockerfile:1
#
# oraclemcp container image — the engine-free Oracle Database MCP server with
# Oracle Instant Client bundled, so the live-db tools work out of the box.
#
# Licensing: the oraclemcp binary is Apache-2.0 OR MIT. The runtime layers come
# from Oracle's official Instant Client image (Oracle Free Use Terms), so this
# image is a mixed-license artifact that redistributes Oracle Instant Client
# under Oracle's terms. Unofficial — not affiliated with Oracle Corporation.

# ---- builder: compile the binary with the live-db (ODPI-C) feature ----
# ODPI-C is vendored + compiled by the `oracle` crate and dlopen()s the Oracle
# client at RUNTIME, so the build stage needs only a C toolchain, not the client.
FROM oraclelinux:9 AS builder
RUN dnf -y install gcc && dnf clean all && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain nightly-2026-05-11
ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /src
COPY . .
RUN cargo build --release -p oraclemcp --features live-db

# ---- runtime: Oracle's official Instant Client image (public, FUTC) ----
FROM ghcr.io/oracle/oraclelinux9-instantclient:23
COPY --from=builder /src/target/release/oraclemcp /usr/local/bin/oraclemcp

# Required by the MCP registry to verify image ownership against server.json's
# server name (io.modelcontextprotocol.server.name == the `name` field).
LABEL io.modelcontextprotocol.server.name="io.github.MuhDur/oraclemcp"
LABEL org.opencontainers.image.title="oraclemcp"
LABEL org.opencontainers.image.description="Unofficial, engine-free Oracle Database MCP server (read-only, fail-closed SQL guard). Not affiliated with Oracle Corporation."
LABEL org.opencontainers.image.source="https://github.com/MuhDur/oraclemcp"
LABEL org.opencontainers.image.licenses="Apache-2.0 OR MIT"

# MCP over stdio by default; the client pipes JSON-RPC in/out. Supply connection
# details at runtime (env/config + `serve --profile`). `--allow-no-auth` because
# the stdio peer is the trusted parent process that launched the container.
ENTRYPOINT ["oraclemcp"]
CMD ["serve", "--allow-no-auth"]
