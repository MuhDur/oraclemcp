import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  TestAttestationVerificationError,
  verifyTestAttestation,
  type TrustedTestAttestationMacKey
} from "./attestation";

const fixturePath = resolve(
  process.cwd(),
  "../crates/oraclemcp-verifier/tests/fixtures/test-attestation-v1.golden.jsonl"
);
const golden = readFileSync(fixturePath, "utf8");
const trustedKey: TrustedTestAttestationMacKey = {
  keyId: "test-attestation-key",
  secret: new TextEncoder().encode("0123456789abcdef0123456789abcdef")
};

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
    throw new Error(`expected ${code}`);
  } catch (error) {
    expect(error).toBeInstanceOf(TestAttestationVerificationError);
    expect((error as TestAttestationVerificationError).code).toBe(code);
  }
}

async function signPayload(payload: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(payload));
  const digestHex = [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  const payloadSha256 = `sha256:${digestHex}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode("0123456789abcdef0123456789abcdef"),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadSha256));
  const macHex = [...new Uint8Array(mac)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return `${payload}\n${JSON.stringify({
    key_id: trustedKey.keyId,
    payload_sha256: payloadSha256,
    schema: "test-attestation-signature/v1",
    signature: `hmac-sha256:${macHex}`
  })}\n`;
}

describe("test-attestation/v1 WebCrypto verifier", () => {
  it("verifies the Rust golden byte-for-byte with an independently supplied secret", async () => {
    const verified = await verifyTestAttestation(golden, [trustedKey]);
    expect(verified.keyId).toBe("test-attestation-key");
    expect(verified.payloadSha256).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(verified.attestation.schema).toBe("test-attestation/v1");
    expect(verified.attestation.lane).toBe("mutation-safety");
    expect(verified.attestation.tests.map((test) => test.outcome)).toEqual(["PASS", "PASS"]);
    expect(verified.allTestsPassed).toBe(true);
  });

  it("rejects an edited outcome before authenticating it", async () => {
    const tampered = golden.replace('"outcome":"PASS"', '"outcome":"FAIL"');
    await expectCode(verifyTestAttestation(tampered, [trustedKey]), "PAYLOAD_DIGEST_MISMATCH");
  });

  it("rejects a recomputed digest when the original MAC no longer binds it", async () => {
    const [payload, signatureText] = golden.trimEnd().split("\n");
    const forgedPayload = payload.replace('"outcome":"PASS"', '"outcome":"FAIL"');
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(forgedPayload));
    const digestHex = [...new Uint8Array(digest)]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    const signature = JSON.parse(signatureText) as Record<string, unknown>;
    signature.payload_sha256 = `sha256:${digestHex}`;
    const forged = `${forgedPayload}\n${JSON.stringify(signature)}\n`;
    await expectCode(verifyTestAttestation(forged, [trustedKey]), "SIGNATURE_INVALID");
  });

  it("rejects wrong, unknown, and ambiguous trusted keys", async () => {
    await expectCode(verifyTestAttestation(golden, []), "UNTRUSTED_KEY");
    await expectCode(
      verifyTestAttestation(golden, [
        { keyId: trustedKey.keyId, secret: new TextEncoder().encode("ffffffffffffffffffffffffffffffff") }
      ]),
      "SIGNATURE_INVALID"
    );
    await expectCode(verifyTestAttestation(golden, [trustedKey, trustedKey]), "AMBIGUOUS_KEY");
  });

  it("rejects malformed documents and unknown payload fields", async () => {
    const [payload, signature] = golden.trimEnd().split("\n");
    await expectCode(verifyTestAttestation(`${payload}\n${signature}`, [trustedKey]), "MALFORMED_DOCUMENT");
    await expectCode(verifyTestAttestation(golden.replace(/\n/g, "\r\n"), [trustedKey]), "MALFORMED_DOCUMENT");
    await expectCode(verifyTestAttestation(`${golden}third-line\n`, [trustedKey]), "MALFORMED_DOCUMENT");

    const payloadObject = JSON.parse(payload) as Record<string, unknown>;
    payloadObject.untrusted = "field";
    await expectCode(
      verifyTestAttestation(`${JSON.stringify(payloadObject)}\n${signature}\n`, [trustedKey]),
      "INVALID_PAYLOAD"
    );
  });

  it("rejects an over-claiming frame and never treats SKIP as PASS", async () => {
    const overClaiming = golden.replace(
      "Evidence of testing, not a proof of correctness",
      "Proof that this binary is correct"
    );
    await expectCode(verifyTestAttestation(overClaiming, [trustedKey]), "INVALID_PAYLOAD");

    const [payload] = golden.trimEnd().split("\n");
    const skipped = await signPayload(payload.replace('"outcome":"PASS"', '"outcome":"SKIP"'));
    const verified = await verifyTestAttestation(skipped, [trustedKey]);
    expect(verified.attestation.tests[0].outcome).toBe("SKIP");
    expect(verified.allTestsPassed).toBe(false);
  });

  it("refuses undersized key material instead of weakening the HMAC contract", async () => {
    await expectCode(
      verifyTestAttestation(golden, [
        { keyId: trustedKey.keyId, secret: new TextEncoder().encode("too-short") }
      ]),
      "INVALID_KEY_MATERIAL"
    );
  });
});
