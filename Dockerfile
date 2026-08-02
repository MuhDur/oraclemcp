# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
#
# oraclemcp container image — the engine-free Oracle Database MCP server with
# the pure-Rust thin Oracle driver compiled in.
#
# Licensing: the oraclemcp binary and image are Apache-2.0 OR MIT. Unofficial —
# not affiliated with Oracle Corporation.

# ---- builder base: compile the thin-driver binary ----
FROM oraclelinux:9@sha256:fe2c9e975c93c1b8c00712e5ad40e0127c0f1982c2d76031f1e09e5307e32aeb AS builder-base
ARG TARGETARCH
ARG RUSTUP_VERSION=1.28.2
RUN dnf -y install ca-certificates curl gcc && dnf clean all && \
    case "$TARGETARCH" in \
      amd64) rustup_target=x86_64-unknown-linux-gnu; rustup_sha=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c ;; \
      arm64) rustup_target=aarch64-unknown-linux-gnu; rustup_sha=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c ;; \
      *) echo "unsupported container architecture: $TARGETARCH" >&2; exit 64 ;; \
    esac && \
    curl --proto '=https' --tlsv1.2 --fail --show-error --location \
      --retry 3 --retry-all-errors --connect-timeout 10 --max-time 120 \
      --output /tmp/rustup-init \
      "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${rustup_target}/rustup-init" && \
    echo "${rustup_sha}  /tmp/rustup-init" | sha256sum --check --strict && \
    chmod 0755 /tmp/rustup-init && \
    /tmp/rustup-init -y --profile minimal --default-toolchain nightly-2026-05-11
ENV PATH="/root/.cargo/bin:${PATH}"
# The image build compiles inside a single-tenant container, but `COPY . .`
# below brings in the repo's .cargo/config.toml RUSTC_WRAPPER (cargo_build_guard),
# which fails closed demanding a machine-wide build lease it cannot find here.
# `CI` triggers the same single-tenant lease waiver a CI runner gets
# (scripts/check_build_lease.sh). It applies only to the throwaway builder
# stages; the runtime base starts separately from the digest-pinned Oracle Linux
# image and receives only the binary, so it never reaches the shipped image.
ENV CI=true
WORKDIR /src/oraclemcp

# ---- default builder: engine-free oraclemcp ----
FROM builder-base AS builder
COPY . .
RUN test -f web/dist/index.html
RUN cargo build --locked --release -p oraclemcp --features dashboard-bundle

# ---- optional builder: oraclemcp + PL/SQL intelligence engine ----
# The feature build resolves published plsql-intelligence crates from crates.io.
# No sibling checkout or named BuildKit context is required.
FROM builder-base AS builder-plsql-intelligence
COPY . .
RUN test -f web/dist/index.html
RUN cargo build --locked --release -p oraclemcp --features dashboard-bundle,plsql-intelligence

# ---- runtime base: fixed non-root identity and bounded writable state ----
FROM oraclelinux:9@sha256:fe2c9e975c93c1b8c00712e5ad40e0127c0f1982c2d76031f1e09e5307e32aeb AS runtime-base
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

# ---- optional runtime: PL/SQL intelligence tools enabled, no DB required ----
FROM runtime-base AS runtime-plsql-intelligence
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
FROM runtime-base AS runtime
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
