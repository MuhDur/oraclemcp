# oraclemcp

Verified `npx` wrapper for the `oraclemcp` Oracle Database MCP server.

```sh
npx oraclemcp serve --allow-no-auth
```

The wrapper downloads the matching GitHub release archive for the current
platform, verifies the SHA-256 checksum, verifies the cosign blob signature,
verifies the cosign blob attestation, extracts the binary into a user cache,
then executes it over stdio with the arguments you supplied.

There are no `install` or `postinstall` scripts. Installing the npm package does
not install services, issue client credentials, or mutate MCP client config.

Useful environment variables:

- `ORACLEMCP_NPM_RELEASE`: release version to fetch. Defaults to this package
  version. Use `latest` to follow the latest GitHub release.
- `ORACLEMCP_NPM_CACHE`: override the binary cache directory.
- `ORACLEMCP_NPM_REPO`: override the GitHub repo, default
  `MuhDur/oraclemcp`.
- `ORACLEMCP_COSIGN`: cosign executable path, default `cosign`.
- `ORACLEMCP_NPM_DRY_RUN=1`: print the verification/download plan without
  network access.

Cosign is required because the checksum is only an integrity check. Authenticity
and provenance come from the release workflow's keyless signature and
attestation.
