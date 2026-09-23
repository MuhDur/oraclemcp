# oraclemcp-verifier

Standalone, offline verification for evidence produced by the
[oraclemcp](https://github.com/MuhDur/oraclemcp) Oracle MCP server. It has no
dependency on the server, its dispatcher, a database connection or server
configuration. You supply the evidence and your own trusted keys, and every
disagreement is an error; it never falls back to what the server asserted.

## What it verifies

- **Verdict certificates** (ADR-0010). `verify_verdict` takes the exact SQL,
  the redacted `VerdictCertificate` the agent saw, the signed audit record the
  certificate names, and your independently trusted audit signing keys. It
  re-runs the self-contained classifier, recomputes the certificate core,
  checks the audit record's hash and keyed MAC, and checks that the audit
  record binds this certificate. It returns the re-derived verdict and
  required operating level, with no SQL, bind or object identifiers in the
  result. A verdict that depended on a server-only live purity oracle is
  rejected when the offline re-derivation differs: a false rejection is safer
  than accepting a claim that can't be checked.
- **Test attestations** (ADR-0012). `verify_test_attestation` checks a signed
  `test-attestation/v1` document against trusted keys, so a CI lane's recorded
  outcomes can be re-verified offline.

## Install

As a library:

```sh
cargo add oraclemcp-verifier
```

`cargo install oraclemcp-verifier` installs the `oraclemcp-test-attest`
binary. CI lanes use it to emit a signed `test-attestation/v1` document:

```sh
ORACLEMCP_TEST_ATTESTATION_KEY=<64+ hex chars> oraclemcp-test-attest \
  --lane coverage --repo MuhDur/oraclemcp --git-sha <sha> \
  --toolchain nightly-2026-05-11 --command 'cargo test' \
  --created-at 2026-01-01T00:00:00Z --output attestation.jsonl \
  --test my_test=PASS --artifact target/report.json
```

The key is read only from the environment. It is never accepted on argv,
written to the output or rendered in errors.

## Offline usage

```rust,ignore
use oraclemcp_verifier::{VerdictEvidence, verify_verdict};

let verified = verify_verdict(VerdictEvidence {
    sql: &exact_sql,
    certificate: &certificate,
    audit_record: &audit_record,
    audit_keys: &trusted_keys,
})?;
println!("{:?} requires {:?}", verified.danger, verified.required_level);
```

## Trust policy

The verifier is only as trustworthy as the keys you give it. Get audit and
attestation keys through a channel independent of the server that produced
the evidence. The HMAC attestation key is symmetric, so anyone who holds it
can also forge documents. Public authenticity of release artifacts comes from
the release's cosign/Sigstore provenance instead. See `docs/operations.md`
(§5.4 "Verify the audit trail", §6 "Verifying release artifacts", §6.7 "Opt in
to signed CI test attestations") in the repository.

## License

Licensed under either of Apache License 2.0 (`LICENSE-APACHE`) or MIT
(`LICENSE-MIT`), at your option.
