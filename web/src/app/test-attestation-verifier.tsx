import * as React from "react";
import { AlertTriangle, FileCheck2, ShieldCheck } from "lucide-react";

import { Badge, Button, Surface } from "../components/ui/primitives";
import {
  TestAttestationVerificationError,
  verifyTestAttestation,
  type VerifiedTestAttestation
} from "../lib/attestation";

const MAX_ATTESTATION_BYTES = 1024 * 1024;

type VerificationState =
  | { kind: "idle" }
  | { kind: "verifying" }
  | { kind: "verified"; evidence: VerifiedTestAttestation }
  | { kind: "rejected"; code: string; message: string };

/**
 * Production browser surface for K2 test-attestation verification.
 *
 * The HMAC secret is always supplied by the operator, is never read from the
 * attestation, and is cleared from component state after every attempt. The
 * byte buffer passed to WebCrypto is zeroed as well. Nothing is persisted to
 * browser storage.
 */
export function TestAttestationVerifier(): React.ReactElement {
  const [document, setDocument] = React.useState("");
  const [keyId, setKeyId] = React.useState("");
  const [macSecret, setMacSecret] = React.useState("");
  const [state, setState] = React.useState<VerificationState>({ kind: "idle" });

  const invalidateResult = React.useCallback((): void => {
    setState({ kind: "idle" });
  }, []);

  const updateDocument = React.useCallback(
    (value: string): void => {
      setDocument(value);
      invalidateResult();
    },
    [invalidateResult]
  );

  const loadDocument = React.useCallback(
    async (event: React.ChangeEvent<HTMLInputElement>): Promise<void> => {
      const file = event.target.files?.[0];
      if (!file) {
        return;
      }
      if (file.size > MAX_ATTESTATION_BYTES) {
        setState({
          kind: "rejected",
          code: "DOCUMENT_TOO_LARGE",
          message: "The selected attestation exceeds the 1 MiB verification limit."
        });
        return;
      }
      try {
        updateDocument(await file.text());
      } catch {
        setState({
          kind: "rejected",
          code: "DOCUMENT_READ_FAILED",
          message: "The selected attestation could not be read."
        });
      }
    },
    [updateDocument]
  );

  const verify = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>): Promise<void> => {
      event.preventDefault();
      const trustedKeyId = keyId.trim();
      const suppliedSecret = macSecret;
      setMacSecret("");
      if (document.length === 0) {
        setState({
          kind: "rejected",
          code: "MISSING_ATTESTATION",
          message: "A signed attestation document is required."
        });
        return;
      }
      if (new TextEncoder().encode(document).byteLength > MAX_ATTESTATION_BYTES) {
        setState({
          kind: "rejected",
          code: "DOCUMENT_TOO_LARGE",
          message: "The attestation exceeds the 1 MiB verification limit."
        });
        return;
      }
      if (trustedKeyId.length === 0) {
        setState({
          kind: "rejected",
          code: "MISSING_KEY_ID",
          message: "An independently trusted key ID is required."
        });
        return;
      }
      if (suppliedSecret.length === 0) {
        setState({
          kind: "rejected",
          code: "MISSING_KEY",
          message: "The independently supplied HMAC secret is required."
        });
        return;
      }

      const secret = new TextEncoder().encode(suppliedSecret);
      setState({ kind: "verifying" });
      try {
        const evidence = await verifyTestAttestation(document, [
          { keyId: trustedKeyId, secret }
        ]);
        setState({ kind: "verified", evidence });
      } catch (error) {
        setState(rejectedState(error));
      } finally {
        secret.fill(0);
      }
    },
    [document, keyId, macSecret]
  );

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(320px,0.85fr)]">
      <Surface className="space-y-5 p-4 md:p-5" data-testid="test-attestation-verifier">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-sm font-semibold text-[var(--om-text-bright)]">
              Signed evidence input
            </p>
            <p className="mt-1 max-w-2xl text-sm leading-6 text-[var(--om-text-muted)]">
              Load or paste a two-line test-attestation/v1 document. Verification runs locally
              with browser WebCrypto; the secret is never fetched from the document.
            </p>
          </div>
          <Badge tone="info">WebCrypto · local</Badge>
        </div>

        <form className="space-y-4" aria-label="Verify signed test evidence" onSubmit={verify}>
          <label className="block">
            <span className="mb-2 block text-sm font-bold text-[var(--om-text)]">
              Attestation file
            </span>
            <input
              className="block min-h-10 w-full cursor-pointer rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] px-3 py-2 text-sm text-[var(--om-text)] file:mr-3 file:rounded file:border-0 file:bg-[var(--om-gold)] file:px-3 file:py-1 file:font-semibold file:text-[var(--om-bg)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--om-focus)]"
              type="file"
              accept=".jsonl,application/x-ndjson,text/plain"
              onChange={(event) => void loadDocument(event)}
            />
          </label>

          <label className="block">
            <span className="mb-2 block text-sm font-bold text-[var(--om-text)]">
              Signed attestation JSONL
            </span>
            <textarea
              className="min-h-52 w-full resize-y rounded-md border border-[var(--om-border)] bg-[var(--om-bg)] p-3 font-mono text-xs leading-5 text-[var(--om-text)] outline-none focus-visible:border-[var(--om-focus)] focus-visible:ring-2 focus-visible:ring-[var(--om-focus)]"
              value={document}
              maxLength={MAX_ATTESTATION_BYTES}
              spellCheck={false}
              placeholder="Paste the exact two LF-terminated lines here"
              onChange={(event) => updateDocument(event.target.value)}
            />
          </label>

          <div className="grid gap-4 md:grid-cols-2">
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-[var(--om-text)]">
                Trusted key ID
              </span>
              <input
                className="h-10 w-full rounded-md border border-[var(--om-border)] bg-[var(--om-bg)] px-3 font-mono text-sm outline-none focus-visible:border-[var(--om-focus)] focus-visible:ring-2 focus-visible:ring-[var(--om-focus)]"
                value={keyId}
                autoComplete="off"
                spellCheck={false}
                placeholder="auditor-key-id"
                onChange={(event) => {
                  setKeyId(event.target.value);
                  invalidateResult();
                }}
              />
            </label>
            <label className="block">
              <span className="mb-2 block text-sm font-bold text-[var(--om-text)]">
                Trusted HMAC secret
              </span>
              <input
                className="h-10 w-full rounded-md border border-[var(--om-border)] bg-[var(--om-bg)] px-3 font-mono text-sm outline-none focus-visible:border-[var(--om-focus)] focus-visible:ring-2 focus-visible:ring-[var(--om-focus)]"
                type="password"
                value={macSecret}
                autoComplete="off"
                spellCheck={false}
                placeholder="supplied out of band"
                onChange={(event) => {
                  setMacSecret(event.target.value);
                  invalidateResult();
                }}
              />
            </label>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[var(--om-border)] pt-4">
            <p className="max-w-2xl text-xs leading-5 text-[var(--om-text-muted)]">
              HMAC is symmetric: anyone holding this verification secret can also forge evidence.
              Use cosign/Sigstore for public provenance across trust domains.
            </p>
            <Button type="submit" variant="primary" disabled={state.kind === "verifying"}>
              <ShieldCheck className="size-4" aria-hidden="true" />
              {state.kind === "verifying" ? "Verifying…" : "Verify evidence"}
            </Button>
          </div>
        </form>
      </Surface>

      <VerificationResult state={state} />
    </div>
  );
}

function VerificationResult({ state }: { state: VerificationState }): React.ReactElement {
  if (state.kind === "idle" || state.kind === "verifying") {
    return (
      <Surface className="min-h-64 p-5" data-testid="verification-result">
        <Badge tone="off">{state.kind === "verifying" ? "verifying" : "not verified"}</Badge>
        <h3 className="mt-5 text-xl font-semibold text-[var(--om-text-bright)]">
          {state.kind === "verifying" ? "Checking signed bytes" : "No verification result"}
        </h3>
        <p className="mt-2 text-sm leading-6 text-[var(--om-text-muted)]">
          A result appears only after the exact payload digest and HMAC both verify under the
          independently supplied key.
        </p>
      </Surface>
    );
  }

  if (state.kind === "rejected") {
    return (
      <Surface
        className="min-h-64 border-[color-mix(in_srgb,var(--om-rust)_70%,var(--om-border))] p-5"
        data-testid="verification-result"
        role="alert"
      >
        <Badge tone="warn">REJECTED</Badge>
        <div className="mt-5 flex items-start gap-3">
          <AlertTriangle className="mt-1 size-5 shrink-0 text-[var(--om-rust)]" aria-hidden="true" />
          <div className="min-w-0">
            <h3 className="text-xl font-semibold text-[var(--om-text-bright)]" data-testid="verification-status">
              Evidence rejected
            </h3>
            <p className="mt-2 break-words font-mono text-xs text-[var(--om-copper)]">
              {state.code}
            </p>
            <p className="mt-3 text-sm leading-6 text-[var(--om-text)]">{state.message}</p>
            <p className="mt-4 text-xs leading-5 text-[var(--om-text-muted)]">
              No test outcome is trusted or presented as verified.
            </p>
          </div>
        </div>
      </Surface>
    );
  }

  const allPass = state.evidence.allTestsPassed;
  const attestation = state.evidence.attestation;
  return (
    <Surface
      className="min-h-64 border-[color-mix(in_srgb,var(--om-sage)_70%,var(--om-border))] p-5"
      data-testid="verification-result"
      aria-live="polite"
    >
      <Badge tone={allPass ? "ok" : "warn"}>
        {allPass ? "VERIFIED PASS" : "VERIFIED · NOT ALL PASS"}
      </Badge>
      <div className="mt-5 flex items-start gap-3">
        <FileCheck2
          className={`mt-1 size-5 shrink-0 ${
            allPass ? "text-[var(--om-sage)]" : "text-[var(--om-copper)]"
          }`}
          aria-hidden="true"
        />
        <div className="min-w-0 flex-1">
          <h3 className="text-xl font-semibold text-[var(--om-text-bright)]" data-testid="verification-status">
            {allPass ? "Signature verified; every named test passed" : "Signature verified; non-pass outcomes recorded"}
          </h3>
          <dl className="mt-4 grid gap-3 text-xs sm:grid-cols-2">
            <EvidenceField label="Lane" value={attestation.lane} />
            <EvidenceField label="Repository" value={attestation.repo} />
            <EvidenceField label="Key ID" value={state.evidence.keyId} />
            <EvidenceField label="Toolchain" value={attestation.toolchain} />
            <EvidenceField label="Commit" value={attestation.git_sha} wide />
            <EvidenceField label="Payload digest" value={state.evidence.payloadSha256} wide />
          </dl>
          <ul className="mt-5 space-y-2" aria-label="Attested test outcomes">
            {attestation.tests.map((test) => (
              <li
                key={test.name}
                className="flex items-start justify-between gap-3 rounded-md border border-[var(--om-border)] bg-[var(--om-bg)] p-3"
              >
                <div className="min-w-0">
                  <p className="break-words font-mono text-xs text-[var(--om-text-bright)]">
                    {test.name}
                  </p>
                  {test.detail ? (
                    <p className="mt-1 break-words text-xs text-[var(--om-text-muted)]">{test.detail}</p>
                  ) : null}
                </div>
                <Badge tone={test.outcome === "PASS" ? "ok" : "warn"}>{test.outcome}</Badge>
              </li>
            ))}
          </ul>
          <p className="mt-4 text-xs leading-5 text-[var(--om-text-muted)]">
            Evidence that these named checks produced these outcomes—not proof of correctness.
          </p>
        </div>
      </div>
    </Surface>
  );
}

function EvidenceField({
  label,
  value,
  wide = false
}: {
  label: string;
  value: string;
  wide?: boolean;
}): React.ReactElement {
  return (
    <div className={wide ? "min-w-0 sm:col-span-2" : "min-w-0"}>
      <dt className="font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
        {label}
      </dt>
      <dd className="mt-1 break-all font-mono text-[var(--om-text)]">{value}</dd>
    </div>
  );
}

function rejectedState(error: unknown): VerificationState {
  if (error instanceof TestAttestationVerificationError) {
    return { kind: "rejected", code: error.code, message: error.message };
  }
  return {
    kind: "rejected",
    code: "VERIFICATION_FAILED",
    message: "The attestation could not be verified."
  };
}
