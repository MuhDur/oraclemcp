#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'MSG'
The oraclemcp npm/npx release channel is retired and no npm publication inputs
are accepted. Use release.yml for crates.io, GitHub assets, GHCR, and MCP
registry publication.
MSG
exit 1
