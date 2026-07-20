# ADR 0012 — Signed test-attestation schema (`test-attestation/v1`)

## Status

Accepted for the K1 format and K2 browser verifier (Cluster K, plan §32.3;
beads `oraclemcp-eng-program-bp8ia.12.1` and `.12.2`). K3 adds lane producers
in a follow-on commit.

## Context

The product's thesis is "don't trust claims, verify them": a fail-closed guard,
a keyed-MAC hash-chained audit log (ADR-0003), and standalone verdict
certificates with an independent verifier (ADR-0010). The one place that thesis
was not applied is the test program itself — "tests pass" was an unverifiable
assertion in a CI log. A test attestation closes that gap: a small, portable,
signed record binding **named tests** to **recorded outcomes**, emitted by the
coverage/mutation/invariant lanes and re-verifiable by a holder of the secret
MAC key. That last qualifier is a real trust boundary: HMAC has no public
verification key, and possession of the verification key also permits signing.

Honesty framing (plan §3.4): a `PASS` records that the named check ran and
passed, a `FAIL` records that it ran and failed, and an explicit `SKIP` records
that it did not run. The document is evidence of testing — never a proof of
correctness, and never a claim about checks not named. That wording is a fixed
`frame` field enforced at both production and verification time so the document
cannot be re-worded into an over-claim.

## Decision

### Wire format

A signed attestation is a JSONL document of exactly two LF-terminated lines
(no CR anywhere; a third line is a rejection):

```text
Line 1 — payload (compact JSON, fields in lexicographic order):
{
  artifacts:  [{path, sha256: "sha256:<64 lowercase hex>"}...],  // may be empty
  command:    "<exact command that produced the outcomes>",
  created_at: "YYYY-MM-DDTHH:MM:SSZ",                            // strict UTC
  frame:      "<the fixed evidence-of-testing claim>",
  git_sha:    "<40 lowercase hex>",
  lane:       "<lowercase slug, e.g. mutation-safety>",
  repo:       "<repository name>",
  schema:     "test-attestation/v1",
  tests:      [{detail?, name, outcome: "PASS"|"SKIP"|"FAIL"}...], // non-empty
  toolchain:  "<pinned toolchain, e.g. nightly-2026-05-11>"
}

Line 2 — detached signature:
{
  key_id:         "<audit SigningKey identifier>",
  payload_sha256: "sha256:<hex over the EXACT bytes of line 1>",
  schema:         "test-attestation-signature/v1",
  signature:      "hmac-sha256:<hex> = HMAC-SHA256(key, payload_sha256)"
}
```

The signed message is the **exact byte sequence of line 1**, so verification
needs no JSON canonicalization: hash the received payload bytes, compare with
`payload_sha256`, then check the keyed MAC over that digest string. Any
byte-level tamper (an edited outcome, reordered keys, injected whitespace)
breaks the digest; a forger who also recomputes the digest cannot reproduce
the MAC without the key. This is the audit chain's exact signing primitive
(`SigningKey::sign` over a `sha256:` digest string, ADR-0003), not a new one.

Outcomes reuse the repo-wide entry-trace tri-state (`PASS`/`SKIP`/`FAIL`);
there is no fourth value. A `SKIP` verifies (it is honest evidence) but is
never counted as a pass. Numeric evidence (kill rates, coverage percentages)
travels in the free-text `detail` field as strings, never as JSON floats, so
producers in different languages cannot disagree on float rendering.

### Verification (fail-closed)

`oraclemcp_verifier::verify_test_attestation` rejects, with a typed error,
any document that is not exactly two lines, fails to parse, carries an unknown
schema or unknown payload field, has an altered frame, malformed field, digest
mismatch, unknown or ambiguous `key_id`, or invalid MAC. An attestation that cannot be
verified is **rejected, never assumed valid**. The K2 browser re-verifier
(`web/src/lib/attestation.ts`) implements the same checks over the same bytes
with WebCrypto; the committed golden
`crates/oraclemcp-verifier/tests/fixtures/test-attestation-v1.golden.jsonl`
pins the wire format for both implementations.

### Key model

Signing keys are the audit crate's `SigningKey` (HMAC-SHA256, ≥32-byte
secret, rotatable `key_id`). The MAC is symmetric: verification requires the
same secret key used to sign, exactly like `oraclemcp audit verify`; there is no
separate public verification key. Producers read the secret from the environment
at signing time; no key material is ever committed or embedded in an attestation.
Third-party verification therefore follows the same disclosure tiering as the
in-browser audit-chain walkthrough (plan §10.7): structural and digest checks
need no secret, while MAC verification runs only where the secret has been
provisioned out of band (an operator or auditor) or deliberately disclosed after
retirement for a demo. A browser bundle must never embed an active MAC key.

For public release verification, the keyed-MAC document must additionally be
wrapped in the repository's existing cosign/Sigstore attestation flow. That
asymmetric, identity-bound layer—not the HMAC alone—is what permits a public
third party to verify provenance without acquiring forge capability.

## Consequences

- The coverage/mutation/invariant lanes can emit evidence that outlives the CI
  log: "green" becomes a MAC a holder of the trusted secret can re-check.
- The claim stays inside plan §3.4's wording rules by construction — the frame
  is part of the signed bytes and its exact text is enforced on both sides.
- A symmetric MAC means possession of the signing key allows forging
  attestations; the trust boundary is identical to the audit chain's and is
  acceptable for the same reasons (ADR-0003). Asymmetric signatures remain the
  upgrade path if attestations must cross trust domains without key sharing.
- The format is versioned (`test-attestation/v1`); any field change is a new
  schema version, never an in-place mutation.

## Review trigger

Revisit if attestations must be verified by parties who may not hold the MAC
key (switch to asymmetric signatures), if the release pipeline starts
cosign-signing a `test-evidence` bundle that subsumes this per-lane document,
or if HMAC-SHA256 is deprecated in the project's threat model.
