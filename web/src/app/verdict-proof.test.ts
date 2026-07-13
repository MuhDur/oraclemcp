import { describe, expect, it } from "vitest";

import { toVerdictProofViewModel } from "./presentation-model";
import {
  parseVerdictProofs,
  verdictProofChecks,
  type AuditTailData,
  type AuditTailRecord,
  type VerdictCertificateWire
} from "./operator-client";

// Arc B1 verdict-proof inspector. The console re-derives the certificate's
// binding to the audit chain; it never trusts a server-side "verified" claim.

const ENTRY_HASH = "sha256:e".padEnd(71, "1");
const CORE_HASH = "sha256:c".padEnd(71, "2");
const SQL_DIGEST = "sha256:s".padEnd(71, "3");

function certificate(overrides: Partial<VerdictCertificateWire> = {}): VerdictCertificateWire {
  return {
    stmt_digest: SQL_DIGEST,
    level: "READ_ONLY",
    verdict: "SAFE",
    derivation: [
      { rule_id: "R15", construct: "routine_purity:all_proven_read_only" },
      { rule_id: "R16", construct: "final_verdict:SAFE" }
    ],
    classifier_version: "oraclemcp-guard/0.8.0;registry=1",
    observed_scn: "10420",
    bound_audit_hash: ENTRY_HASH,
    ...overrides
  };
}

function record(overrides: Partial<AuditTailRecord> = {}): AuditTailRecord {
  return {
    schema_version: 10,
    seq: 12,
    timestamp: "2026-07-13T09:00:00Z",
    subject_id_hash: "subject-sha256:abc",
    tool: "oracle_query",
    danger_level: "SAFE",
    decision: "ALLOWED",
    outcome: "SUCCESS",
    sql_sha256: SQL_DIGEST,
    proof: { entry_hash: ENTRY_HASH, hash_valid: true },
    verdict_certificate: certificate() as unknown as Record<string, unknown>,
    verdict_certificate_core_hash: CORE_HASH,
    ...overrides
  };
}

function tail(records: AuditTailRecord[]): AuditTailData {
  return { source: "self_lane", limit: 50, filters: {}, records };
}

describe("verdict-proof inspection", () => {
  it("projects a proof-carrying record into a verified proof", () => {
    const data = parseVerdictProofs(tail([record()]));
    expect(data.source).toBe("self_lane");
    expect(data.proofs).toHaveLength(1);
    expect(data.uncertified).toBe(0);

    const proof = data.proofs[0];
    expect(proof.certHash).toBe(CORE_HASH);
    expect(proof.auditHash).toBe(ENTRY_HASH);
    expect(proof.checks.every((check) => check.ok)).toBe(true);

    const model = toVerdictProofViewModel(proof);
    expect(model.proofStatus).toBe("verified");
    expect(model.admitted).toBe(true);
    expect(model.goNoGo).toBe("GO");
    expect(model.level).toBe("READ_ONLY");
    expect(model.observedScn).toBe("10420");
    expect(model.derivation.map((step) => step.ruleId)).toEqual(["R15", "R16"]);
  });

  it("renders a FORBIDDEN certificate as a refused NO-GO with no level", () => {
    const refused = certificate({
      level: null,
      verdict: "FORBIDDEN",
      derivation: [
        { rule_id: "R15", construct: "routine_purity:unproven_present" },
        { rule_id: "R16", construct: "final_verdict:FORBIDDEN" }
      ]
    });
    const data = parseVerdictProofs(
      tail([record({ verdict_certificate: refused as unknown as Record<string, unknown> })])
    );
    const model = toVerdictProofViewModel(data.proofs[0]);
    expect(model.admitted).toBe(false);
    expect(model.goNoGo).toBe("NO-GO");
    expect(model.level).toBeNull();
    // A refused statement still carries a *verified* proof of its refusal.
    expect(model.proofStatus).toBe("verified");
  });

  it("fails the binding check when the certificate names another audit entry", () => {
    const drifted = certificate({ bound_audit_hash: "sha256:other" });
    const checks = verdictProofChecks(record(), drifted, CORE_HASH);
    const binding = checks.find((check) => check.id === "audit_binding");
    expect(binding?.ok).toBe(false);
    expect(
      toVerdictProofViewModel({
        seq: 12,
        timestamp: "2026-07-13T09:00:00Z",
        tool: "oracle_query",
        subjectIdHash: "subject-sha256:abc",
        certHash: CORE_HASH,
        auditHash: ENTRY_HASH,
        certificate: drifted,
        checks
      }).proofStatus
    ).toBe("unverified");
  });

  it("fails the digest check when the certificate describes other SQL bytes", () => {
    const checks = verdictProofChecks(
      record({ sql_sha256: "sha256:different" }),
      certificate(),
      CORE_HASH
    );
    expect(checks.find((check) => check.id === "statement_digest")?.ok).toBe(false);
  });

  it("fails the registry check on an unknown rule id or construct label", () => {
    const unknownRule = verdictProofChecks(
      record(),
      certificate({ derivation: [{ rule_id: "R99", construct: "final_verdict:SAFE" }] }),
      CORE_HASH
    );
    expect(unknownRule.find((check) => check.id === "rule_registry")?.ok).toBe(false);

    const unknownConstruct = verdictProofChecks(
      record(),
      certificate({ derivation: [{ rule_id: "R16", construct: "SELECT * FROM hr.employees" }] }),
      CORE_HASH
    );
    expect(unknownConstruct.find((check) => check.id === "rule_registry")?.ok).toBe(false);

    // An empty derivation proves nothing and must not pass as a certificate.
    const empty = verdictProofChecks(record(), certificate({ derivation: [] }), CORE_HASH);
    expect(empty.find((check) => check.id === "rule_registry")?.ok).toBe(false);
  });

  it("fails the chain check on an invalid record hash or a missing core hash", () => {
    const tampered = verdictProofChecks(
      record({ proof: { entry_hash: ENTRY_HASH, hash_valid: false } }),
      certificate(),
      CORE_HASH
    );
    expect(tampered.find((check) => check.id === "chain_hash")?.ok).toBe(false);

    const uncovered = verdictProofChecks(record(), certificate(), "");
    expect(uncovered.find((check) => check.id === "chain_hash")?.ok).toBe(false);
  });

  it("counts records without a certificate instead of synthesizing one", () => {
    const data = parseVerdictProofs(
      tail([
        record(),
        record({ seq: 13, verdict_certificate: null, verdict_certificate_core_hash: null }),
        // A malformed certificate is not a certificate.
        record({ seq: 14, verdict_certificate: { verdict: "SAFE" } })
      ])
    );
    expect(data.proofs.map((proof) => proof.seq)).toEqual([12]);
    expect(data.uncertified).toBe(2);
  });

  it("reports an unavailable audit tail instead of an empty verified list", () => {
    const data = parseVerdictProofs({
      source: "unavailable",
      reason: "audit tail provider is not configured",
      limit: 50,
      filters: {},
      records: []
    });
    expect(data.source).toBe("unavailable");
    expect(data.reason).toBe("audit tail provider is not configured");
    expect(data.proofs).toHaveLength(0);
  });
});
