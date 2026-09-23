# Packaging

No third-party package-manager manifests are shipped. oraclemcp is distributed
only through the channels its tag pipeline (`.github/workflows/release.yml`)
publishes:

- the one-line installers `install.sh` (Linux, macOS) and `install.ps1`
  (Windows), which verify the signed GitHub release archives;
- `cargo binstall oraclemcp` against the same archives, and crates.io;
- the GHCR image `ghcr.io/muhdur/oraclemcp`;
- the MCP registry entry from `server.json`.

There is no npm/npx channel.
