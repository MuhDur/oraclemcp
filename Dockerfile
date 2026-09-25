# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
#
# oraclemcp container image — the engine-enabled Oracle Database MCP server
# with the pure-Rust thin Oracle driver compiled in.
#
# Licensing: oraclemcp source is Apache-2.0 OR MIT. The image also contains
# Mozilla/CCADB root-certificate data through webpki-roots; its accompanying
# CDLA-Permissive-2.0 text is copied into /usr/share/licenses/oraclemcp.
# Unofficial — not affiliated with Oracle Corporation.

# The digest-pinned multi-arch builder image is the complete immutable build
# OS package closure. No package-manager repo is consulted during the build.
FROM rust:1.88.0-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS builder-base
RUN rustup toolchain install nightly-2026-05-11 --profile minimal && \
    rustup default nightly-2026-05-11
# Keep the cold release compile inside the hosted GHCR runner's memory envelope.
ENV CARGO_BUILD_JOBS=2
# The image build compiles inside a single-tenant container, but `COPY . .`
# below brings in the repo's .cargo/config.toml RUSTC_WRAPPER (cargo_build_guard),
# which fails closed demanding a machine-wide build lease it cannot find here.
# `CI` triggers the same single-tenant lease waiver a CI runner gets
# (scripts/check_build_lease.sh). It applies only to the throwaway builder
# stages; the runtime base starts separately from the digest-pinned Debian
# image and receives only the binary, so it never reaches the shipped image.
ENV CI=true
WORKDIR /src/oraclemcp

# ---- default builder: engine-enabled oraclemcp ----
FROM builder-base AS builder
COPY . .
RUN test -f web/dist/index.html
RUN cargo build --locked --release -p oraclemcp --features dashboard-bundle,oracledb

# ---- runtime base: fixed non-root identity and bounded writable state ----
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS runtime-base
RUN groupadd --gid 10001 oraclemcp && \
    useradd --uid 10001 --gid 10001 --no-create-home \
      --home-dir /home/oraclemcp --shell /sbin/nologin oraclemcp && \
    install -d -m 0755 -o root -g root \
      /home/oraclemcp /home/oraclemcp/.config /home/oraclemcp/.local \
      /home/oraclemcp/.local/state && \
    install -d -m 0700 -o oraclemcp -g oraclemcp \
      /home/oraclemcp/.config/oraclemcp \
      /home/oraclemcp/.local/state/oraclemcp
ENV HOME=/home/oraclemcp \
    XDG_CONFIG_HOME=/home/oraclemcp/.config \
    XDG_STATE_HOME=/home/oraclemcp/.local/state
WORKDIR /home/oraclemcp
USER 10001:10001
RUN test "$(id -u)" -eq 10001 && \
    test -w /home/oraclemcp/.config/oraclemcp && \
    test -w /home/oraclemcp/.local/state/oraclemcp && \
    test ! -w /home/oraclemcp && \
    test ! -w /home/oraclemcp/.config && \
    test ! -w /home/oraclemcp/.local/state

# ---- runtime: no Oracle native client required ----
FROM runtime-base AS runtime
COPY --from=builder /src/oraclemcp/target/release/oraclemcp /usr/local/bin/oraclemcp
COPY LICENSE-CDLA-Permissive-2.0 /usr/share/licenses/oraclemcp/LICENSE-CDLA-Permissive-2.0

# Required by the MCP registry to verify image ownership against server.json's
# server name (io.modelcontextprotocol.server.name == the `name` field).
LABEL io.modelcontextprotocol.server.name="io.github.MuhDur/oraclemcp"
LABEL org.opencontainers.image.title="oraclemcp"
LABEL org.opencontainers.image.description="Unofficial, governed Oracle Database MCP server with a fail-closed SQL guard, confirmation-gated operating levels, and offline PL/SQL intelligence tools. Not affiliated with Oracle Corporation."
LABEL org.opencontainers.image.source="https://github.com/MuhDur/oraclemcp"
LABEL org.opencontainers.image.licenses="(Apache-2.0 OR MIT) AND CDLA-Permissive-2.0"

# MCP over stdio by default; the client pipes JSON-RPC in/out. Supply connection
# details at runtime (env/config + `serve --profile`). `--allow-no-auth` because
# the stdio peer is the trusted parent process that launched the container.
ENTRYPOINT ["oraclemcp"]
CMD ["serve", "--allow-no-auth"]
