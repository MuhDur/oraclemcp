# Golden Behavior Fixtures

These fixtures freeze current client-visible behavior for bead
`oraclemcp-w1-golden-behavior-harness-y8p` before the stdio and HTTP transport
rewrites.

Generated with the repository-pinned Rust toolchain from this checkout:

```bash
UPDATE_GOLDENS=1 cargo test -p oraclemcp-core --test golden_behavior
UPDATE_GOLDENS=1 cargo test -p oraclemcp --test golden_behavior
```

Review rule: fixture changes are protocol behavior changes. Do not regenerate
and accept them without reading the diff. Dynamic Streamable HTTP session IDs
are scrubbed to `[SESSION_ID]`; the remaining values are expected to be stable.

All inputs are synthetic. The stdio init token strings, OAuth metadata, JWT
verifier key, database user/schema names, SQL text, hostnames, and Oracle error
messages in these fixtures are test-only values and are not real secrets or PII.
