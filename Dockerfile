# syntax=docker/dockerfile:1
#
# oraclemcp container image — the engine-free Oracle Database MCP server with
# the pure-Rust thin Oracle driver compiled in.
#
# Licensing: the oraclemcp binary and image are Apache-2.0 OR MIT. Unofficial —
# not affiliated with Oracle Corporation.

# ---- builder base: compile the thin-driver binary ----
FROM oraclelinux:9 AS builder-base
RUN dnf -y install ca-certificates curl gcc && dnf clean all && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain nightly-2026-05-11
ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /src/oraclemcp

# ---- default builder: engine-free oraclemcp ----
FROM builder-base AS builder
COPY . .
# Optional path dependencies in crates/oraclemcp/Cargo.toml still need their
# sibling manifests during the pre-0.7.0 plsql-intelligence bridge. The default
# image does not compile those crates, but Cargo must be able to read them.
COPY --from=plsql-intelligence . /src/plsql-intelligence
RUN cargo build --release -p oraclemcp

# ---- optional builder: oraclemcp + PL/SQL intelligence engine ----
# Requires BuildKit and the same named context used by the default builder:
#   docker buildx build \
#     --build-context plsql-intelligence=../plsql-intelligence \
#     --target runtime-plsql-intelligence \
#     -f Dockerfile .
FROM builder-base AS builder-plsql-intelligence
COPY . .
COPY --from=plsql-intelligence . /src/plsql-intelligence
RUN cargo build --release -p oraclemcp --features plsql-intelligence

# ---- optional runtime: PL/SQL intelligence tools enabled, no DB required ----
FROM oraclelinux:9 AS runtime-plsql-intelligence
COPY --from=builder-plsql-intelligence /src/oraclemcp/target/release/oraclemcp /usr/local/bin/oraclemcp

LABEL io.modelcontextprotocol.server.name="io.github.MuhDur/oraclemcp"
LABEL org.opencontainers.image.title="oraclemcp-plsql-intelligence"
LABEL org.opencontainers.image.description="Unofficial, governed Oracle Database MCP server with optional offline PL/SQL intelligence tools. Not affiliated with Oracle Corporation."
LABEL org.opencontainers.image.source="https://github.com/MuhDur/oraclemcp"
LABEL org.opencontainers.image.licenses="Apache-2.0 OR MIT"
LABEL org.opencontainers.image.variant="plsql-intelligence"

ENTRYPOINT ["oraclemcp"]
CMD ["serve", "--allow-no-auth"]

# ---- runtime: no Oracle native client required ----
FROM oraclelinux:9 AS runtime
COPY --from=builder /src/oraclemcp/target/release/oraclemcp /usr/local/bin/oraclemcp

# Required by the MCP registry to verify image ownership against server.json's
# server name (io.modelcontextprotocol.server.name == the `name` field).
LABEL io.modelcontextprotocol.server.name="io.github.MuhDur/oraclemcp"
LABEL org.opencontainers.image.title="oraclemcp"
LABEL org.opencontainers.image.description="Unofficial, engine-free, governed least-privilege Oracle Database MCP server with a fail-closed SQL guard and confirmation-gated operating levels. Not affiliated with Oracle Corporation."
LABEL org.opencontainers.image.source="https://github.com/MuhDur/oraclemcp"
LABEL org.opencontainers.image.licenses="Apache-2.0 OR MIT"
LABEL org.opencontainers.image.variant="core"

# MCP over stdio by default; the client pipes JSON-RPC in/out. Supply connection
# details at runtime (env/config + `serve --profile`). `--allow-no-auth` because
# the stdio peer is the trusted parent process that launched the container.
ENTRYPOINT ["oraclemcp"]
CMD ["serve", "--allow-no-auth"]
