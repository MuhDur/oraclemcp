# syntax=docker/dockerfile:1
#
# oraclemcp container image — the engine-free Oracle Database MCP server with
# the pure-Rust thin Oracle driver compiled in.
#
# Licensing: the oraclemcp binary and image are Apache-2.0 OR MIT. Unofficial —
# not affiliated with Oracle Corporation.

# ---- builder: compile the thin-driver binary ----
FROM oraclelinux:9 AS builder
RUN dnf -y install ca-certificates curl gcc && dnf clean all && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain nightly-2026-05-11
ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /src
COPY . .
RUN cargo build --release -p oraclemcp

# ---- runtime: no Oracle native client required ----
FROM oraclelinux:9
COPY --from=builder /src/target/release/oraclemcp /usr/local/bin/oraclemcp

# Required by the MCP registry to verify image ownership against server.json's
# server name (io.modelcontextprotocol.server.name == the `name` field).
LABEL io.modelcontextprotocol.server.name="io.github.MuhDur/oraclemcp"
LABEL org.opencontainers.image.title="oraclemcp"
LABEL org.opencontainers.image.description="Unofficial, engine-free, safe-by-default Oracle Database MCP server with a fail-closed SQL guard. Not affiliated with Oracle Corporation."
LABEL org.opencontainers.image.source="https://github.com/MuhDur/oraclemcp"
LABEL org.opencontainers.image.licenses="Apache-2.0 OR MIT"

# MCP over stdio by default; the client pipes JSON-RPC in/out. Supply connection
# details at runtime (env/config + `serve --profile`). `--allow-no-auth` because
# the stdio peer is the trusted parent process that launched the container.
ENTRYPOINT ["oraclemcp"]
CMD ["serve", "--allow-no-auth"]
