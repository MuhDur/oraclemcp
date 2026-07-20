/**
 * Browser verifier for `test-attestation/v1` (Cluster K2, ADR-0012).
 *
 * The MAC key is a symmetric secret, not a public verification key. Callers
 * must provision it through an independently trusted channel. Never fetch an
 * active key from the attestation, embed it in the dashboard bundle, or label
 * digest-only inspection as authenticated verification: anyone holding this
 * key can also forge an attestation. Public release provenance belongs to the
 * repository's asymmetric cosign/Sigstore layer.
 */

export const TEST_ATTESTATION_SCHEMA = "test-attestation/v1";
export const TEST_ATTESTATION_SIGNATURE_SCHEMA = "test-attestation-signature/v1";
export const TEST_ATTESTATION_FRAME =
  "Signed evidence that the named checks produced the recorded PASS, FAIL, or explicit SKIP " +
  "outcomes for the recorded commit and toolchain. A PASS records that the named check ran and " +
  "passed; a SKIP records that it did not run. Evidence of testing, not a proof of correctness, " +
  "and no claim about checks not named here.";

const MAX_TESTS = 4096;
const MAX_ARTIFACTS = 256;
const MAX_NAME_LENGTH = 256;
const MAX_DETAIL_LENGTH = 1024;
const MAX_COMMAND_LENGTH = 1024;
const MAX_PATH_LENGTH = 512;
const MAX_LABEL_LENGTH = 100;

export type TestOutcome = "PASS" | "SKIP" | "FAIL";

export interface AttestedTest {
  detail?: string;
  name: string;
  outcome: TestOutcome;
}

export interface AttestedArtifact {
  path: string;
  sha256: string;
}

export interface TestAttestation {
  artifacts: AttestedArtifact[];
  command: string;
  created_at: string;
  frame: string;
  git_sha: string;
  lane: string;
  repo: string;
  schema: typeof TEST_ATTESTATION_SCHEMA;
  tests: AttestedTest[];
  toolchain: string;
}

interface TestAttestationSignature {
  key_id: string;
  payload_sha256: string;
  schema: typeof TEST_ATTESTATION_SIGNATURE_SCHEMA;
  signature: string;
}

/** A secret HMAC key obtained from a trusted channel outside the document. */
export interface TrustedTestAttestationMacKey {
  keyId: string;
  secret: Uint8Array;
}

export interface VerifiedTestAttestation {
  attestation: TestAttestation;
  /** True only when every recorded outcome is PASS; SKIP is never a pass. */
  allTestsPassed: boolean;
  keyId: string;
  payloadSha256: string;
}

export type TestAttestationErrorCode =
  | "MALFORMED_DOCUMENT"
  | "MALFORMED_PAYLOAD"
  | "INVALID_PAYLOAD"
  | "MALFORMED_SIGNATURE"
  | "UNSUPPORTED_SIGNATURE_SCHEMA"
  | "PAYLOAD_DIGEST_MISMATCH"
  | "UNTRUSTED_KEY"
  | "AMBIGUOUS_KEY"
  | "INVALID_KEY_MATERIAL"
  | "SIGNATURE_INVALID"
  | "WEBCRYPTO_UNAVAILABLE";

export class TestAttestationVerificationError extends Error {
  constructor(
    readonly code: TestAttestationErrorCode,
    message: string
  ) {
    super(message);
    this.name = "TestAttestationVerificationError";
  }
}

/**
 * Verify the byte-exact payload digest and HMAC in browser WebCrypto.
 *
 * Fail-closed: malformed input, an unknown or ambiguous key id, unavailable
 * WebCrypto, and every digest/MAC disagreement reject with a typed error.
 */
export async function verifyTestAttestation(
  document: string,
  trustedKeys: readonly TrustedTestAttestationMacKey[],
  subtle?: SubtleCrypto
): Promise<VerifiedTestAttestation> {
  const { payloadLine, signatureLine } = splitDocument(document);
  const attestation = parsePayload(payloadLine);
  const signature = parseSignature(signatureLine);

  const crypto = subtle ?? globalThis.crypto?.subtle;
  if (!crypto) {
    fail("WEBCRYPTO_UNAVAILABLE", "WebCrypto SubtleCrypto is unavailable");
  }

  const payloadSha256 = `sha256:${await sha256Hex(crypto, utf8(payloadLine))}`;
  if (signature.payload_sha256 !== payloadSha256) {
    fail("PAYLOAD_DIGEST_MISMATCH", "attestation payload digest does not match the payload line");
  }

  const matchingKeys = trustedKeys.filter((key) => key.keyId === signature.key_id);
  if (matchingKeys.length === 0) {
    fail("UNTRUSTED_KEY", "attestation signing key is not independently trusted");
  }
  if (matchingKeys.length !== 1) {
    fail("AMBIGUOUS_KEY", "attestation signing key identity is ambiguous");
  }

  const trustedKey = matchingKeys[0];
  if (!isSafeLabel(trustedKey.keyId) || trustedKey.secret.byteLength < 32) {
    fail("INVALID_KEY_MATERIAL", "trusted HMAC key id or secret material is invalid");
  }
  if (!/^hmac-sha256:[0-9a-f]{64}$/.test(signature.signature)) {
    fail("SIGNATURE_INVALID", "attestation signature is not canonical HMAC-SHA256");
  }

  let key: CryptoKey;
  try {
    key = await crypto.importKey(
      "raw",
      ownedBytes(trustedKey.secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
  } catch {
    fail("INVALID_KEY_MATERIAL", "trusted HMAC key could not be imported");
  }

  const signatureBytes = hexBytes(signature.signature.slice("hmac-sha256:".length));
  const authentic = await crypto.verify(
    "HMAC",
    key,
    signatureBytes,
    utf8(payloadSha256)
  );
  if (!authentic) {
    fail("SIGNATURE_INVALID", "attestation HMAC does not verify under the trusted secret");
  }

  return {
    attestation,
    allTestsPassed: attestation.tests.every((test) => test.outcome === "PASS"),
    keyId: signature.key_id,
    payloadSha256
  };
}

function splitDocument(document: string): { payloadLine: string; signatureLine: string } {
  if (document.includes("\r") || !document.endsWith("\n")) {
    fail("MALFORMED_DOCUMENT", "attestation must contain exactly two LF-terminated lines");
  }
  const body = document.slice(0, -1);
  const separator = body.indexOf("\n");
  if (separator <= 0 || separator !== body.lastIndexOf("\n") || separator === body.length - 1) {
    fail("MALFORMED_DOCUMENT", "attestation must contain one payload line and one signature line");
  }
  return {
    payloadLine: body.slice(0, separator),
    signatureLine: body.slice(separator + 1)
  };
}

function parsePayload(line: string): TestAttestation {
  const payload = parseRecord(line, "MALFORMED_PAYLOAD", "attestation payload is not JSON");
  expectKeys(
    payload,
    [
      "artifacts",
      "command",
      "created_at",
      "frame",
      "git_sha",
      "lane",
      "repo",
      "schema",
      "tests",
      "toolchain"
    ],
    "payload"
  );

  if (payload.schema !== TEST_ATTESTATION_SCHEMA) invalid("unsupported payload schema");
  if (payload.frame !== TEST_ATTESTATION_FRAME) invalid("payload frame is not the fixed honest claim");
  if (!isLaneSlug(payload.lane)) invalid("lane is not a lowercase slug");
  if (!isSafeLabel(payload.repo)) invalid("repo identifier is invalid");
  if (!isSafeLabel(payload.toolchain)) invalid("toolchain identifier is invalid");
  if (!isBoundedText(payload.command, MAX_COMMAND_LENGTH)) invalid("command is invalid");
  if (!isStrictUtcTimestamp(payload.created_at)) invalid("created_at is not strict UTC");
  if (typeof payload.git_sha !== "string" || !/^[0-9a-f]{40}$/.test(payload.git_sha)) {
    invalid("git_sha is not 40 lowercase hex characters");
  }

  if (!Array.isArray(payload.tests) || payload.tests.length === 0 || payload.tests.length > MAX_TESTS) {
    invalid("test list is empty or oversized");
  }
  const tests = payload.tests.map(parseTest);
  if (new Set(tests.map((test) => test.name)).size !== tests.length) {
    invalid("test names are not unique");
  }

  if (!Array.isArray(payload.artifacts) || payload.artifacts.length > MAX_ARTIFACTS) {
    invalid("artifact list is malformed or oversized");
  }
  const artifacts = payload.artifacts.map(parseArtifact);
  if (new Set(artifacts.map((artifact) => artifact.path)).size !== artifacts.length) {
    invalid("artifact paths are not unique");
  }

  return {
    artifacts,
    command: payload.command as string,
    created_at: payload.created_at as string,
    frame: payload.frame as string,
    git_sha: payload.git_sha,
    lane: payload.lane as string,
    repo: payload.repo as string,
    schema: TEST_ATTESTATION_SCHEMA,
    tests,
    toolchain: payload.toolchain as string
  };
}

function parseTest(value: unknown): AttestedTest {
  if (!isRecord(value)) invalid("test entry is not an object");
  const keys = Object.keys(value).sort();
  const hasDetail = Object.hasOwn(value, "detail");
  const expected = hasDetail ? ["detail", "name", "outcome"] : ["name", "outcome"];
  if (!sameStrings(keys, expected)) invalid("test entry has missing or unknown fields");
  if (!isBoundedText(value.name, MAX_NAME_LENGTH)) invalid("test name is invalid");
  if (hasDetail && !isOptionalBoundedText(value.detail, MAX_DETAIL_LENGTH)) {
    invalid("test detail is invalid");
  }
  if (value.outcome !== "PASS" && value.outcome !== "SKIP" && value.outcome !== "FAIL") {
    invalid("test outcome is unknown");
  }
  return {
    ...(hasDetail ? { detail: value.detail as string } : {}),
    name: value.name as string,
    outcome: value.outcome
  };
}

function parseArtifact(value: unknown): AttestedArtifact {
  if (!isRecord(value)) invalid("artifact entry is not an object");
  expectKeys(value, ["path", "sha256"], "artifact entry");
  if (!isSafeRelativePath(value.path)) invalid("artifact path is invalid");
  if (typeof value.sha256 !== "string" || !/^sha256:[0-9a-f]{64}$/.test(value.sha256)) {
    invalid("artifact digest is not canonical SHA-256");
  }
  return { path: value.path as string, sha256: value.sha256 };
}

function parseSignature(line: string): TestAttestationSignature {
  const signature = parseRecord(
    line,
    "MALFORMED_SIGNATURE",
    "attestation signature is not JSON"
  );
  const keys = Object.keys(signature).sort();
  if (!sameStrings(keys, ["key_id", "payload_sha256", "schema", "signature"])) {
    fail("MALFORMED_SIGNATURE", "attestation signature has missing or unknown fields");
  }
  if (signature.schema !== TEST_ATTESTATION_SIGNATURE_SCHEMA) {
    fail("UNSUPPORTED_SIGNATURE_SCHEMA", "attestation signature schema is unsupported");
  }
  if (!isSafeLabel(signature.key_id)) {
    fail("MALFORMED_SIGNATURE", "attestation signature key id is invalid");
  }
  if (typeof signature.payload_sha256 !== "string") {
    fail("MALFORMED_SIGNATURE", "attestation payload digest is not a string");
  }
  if (typeof signature.signature !== "string") {
    fail("MALFORMED_SIGNATURE", "attestation HMAC is not a string");
  }
  return {
    key_id: signature.key_id as string,
    payload_sha256: signature.payload_sha256,
    schema: TEST_ATTESTATION_SIGNATURE_SCHEMA,
    signature: signature.signature
  };
}

function parseRecord(
  text: string,
  code: "MALFORMED_PAYLOAD" | "MALFORMED_SIGNATURE",
  message: string
): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    fail(code, message);
  }
  if (!isRecord(parsed)) fail(code, message);
  return parsed;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function expectKeys(value: Record<string, unknown>, expected: readonly string[], context: string) {
  if (!sameStrings(Object.keys(value).sort(), expected)) {
    invalid(`${context} has missing or unknown fields`);
  }
}

function sameStrings(actual: readonly string[], expected: readonly string[]): boolean {
  return actual.length === expected.length && actual.every((value, index) => value === expected[index]);
}

function isLaneSlug(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length <= MAX_LABEL_LENGTH &&
    /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value)
  );
}

function isSafeLabel(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_LABEL_LENGTH &&
    /^[A-Za-z0-9_.-]+$/.test(value)
  );
}

function isBoundedText(value: unknown, maximum: number): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    utf8(value).byteLength <= maximum &&
    !hasControl(value)
  );
}

function isOptionalBoundedText(value: unknown, maximum: number): value is string {
  return typeof value === "string" && utf8(value).byteLength <= maximum && !hasControl(value);
}

function hasControl(value: string): boolean {
  return /[\u0000-\u001f\u007f-\u009f]/u.test(value);
}

function isSafeRelativePath(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    utf8(value).byteLength > MAX_PATH_LENGTH ||
    value.startsWith("/") ||
    value.includes("\\") ||
    hasControl(value)
  ) {
    return false;
  }
  return value.split("/").every((component) => component !== "" && component !== "." && component !== "..");
}

function isStrictUtcTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/.exec(value);
  if (!match) return false;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  if (year === 0 || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) {
    return false;
  }
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day >= 1 && day <= days[month - 1];
}

function utf8(value: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(value);
}

async function sha256Hex(subtle: SubtleCrypto, bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = await subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexBytes(hex: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function ownedBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  return owned;
}

function invalid(message: string): never {
  return fail("INVALID_PAYLOAD", message);
}

function fail(code: TestAttestationErrorCode, message: string): never {
  throw new TestAttestationVerificationError(code, message);
}
