# Distribution Manifests

This directory contains release-time templates for package-manager metadata that
needs the final archive checksums.

`scripts/render_distribution_manifests.sh` reads the release archive `.sha256`
files from the GitHub release artifact directory and writes:

- `homebrew/Formula/oraclemcp.rb`
- `winget/manifests/m/MuhDur/oraclemcp/<version>/MuhDur.oraclemcp*.yaml`

The Homebrew formula targets the macOS release archives. The winget manifest
targets the Windows zip as a portable package and may be submitted after the tag
is published because community repository validation and review can lag the
release.
