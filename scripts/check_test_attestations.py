#!/usr/bin/env python3
"""E6 — consume the attestation artifacts an e2e/CI lane uploads, and REJECT bad
or missing ones.

An attestation nobody verifies is decoration. Before this, oraclemcp SIGNED
(via .github/actions/test-attestation) and VERIFIED only inside Rust unit tests;
no CI job ever consumed an emitted artifact, so nothing could tell a real
attestation from an absent one.

WHY THIS RUNS WITHOUT THE SIGNING SECRET, which matters because the repo does
not have one: the signature envelope records `payload_sha256`, and that digest
binds the payload. Tampering with a signed attestation breaks the digest whether
or not you can check the HMAC. So the whole reject path — malformed, unsigned
lookalike, tampered payload, claimed-but-absent, missing entirely — is
enforceable today. Checking the HMAC itself still needs the key and is the one
thing this cannot do; it says so rather than implying otherwise.

THE INVARIANT: a lane must produce EITHER a well-formed signed attestation OR a
typed SKIP status naming a known reason. What it may never produce is silence,
or a claim it cannot back.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

PAYLOAD_SCHEMA = "test-attestation/v1"
SIGNATURE_SCHEMA = "test-attestation-signature/v1"
STATUS_SCHEMA = "test-attestation-status/v1"
# The action emits exactly these. An unrecognised reason is a silent behaviour
# change in the signer, which is precisely what a consumer exists to notice.
KNOWN_SKIP_REASONS = {"operator-not-enabled", "untrusted-context"}
REQUIRED_PAYLOAD_FIELDS = {
    "schema", "lane", "repo", "git_sha", "toolchain", "command", "tests", "created_at",
}


class Findings:
    def __init__(self) -> None:
        self.items: list[tuple[str, str]] = []

    def error(self, code: str, message: str) -> None:
        self.items.append((code, message))

    def codes(self) -> set[str]:
        return {c for c, _ in self.items}

    def __len__(self) -> int:
        return len(self.items)


def check_attestation(path: Path, findings: Findings) -> None:
    raw = path.read_bytes()
    lines = raw.splitlines()
    if len(lines) != 2:
        findings.error(
            "E_MALFORMED",
            f"{path.name}: expected 2 JSONL lines (payload, signature), found {len(lines)}",
        )
        return
    payload_bytes, signature_bytes = lines[0], lines[1]

    try:
        payload = json.loads(payload_bytes)
        signature = json.loads(signature_bytes)
    except json.JSONDecodeError as exc:
        findings.error("E_MALFORMED", f"{path.name}: not valid JSON ({exc})")
        return

    if payload.get("schema") != PAYLOAD_SCHEMA:
        findings.error(
            "E_MALFORMED",
            f"{path.name}: payload schema is {payload.get('schema')!r}, expected {PAYLOAD_SCHEMA!r}",
        )
    missing = sorted(REQUIRED_PAYLOAD_FIELDS - set(payload))
    if missing:
        findings.error("E_MALFORMED", f"{path.name}: payload is missing {missing}")

    # An "unsigned lookalike" is the failure the E6 acceptance names by that
    # word: a file shaped like evidence that carries no signature at all.
    if signature.get("schema") != SIGNATURE_SCHEMA:
        findings.error(
            "E_UNSIGNED_LOOKALIKE",
            f"{path.name}: second line is not a {SIGNATURE_SCHEMA} envelope "
            f"(found schema {signature.get('schema')!r}) — a document shaped like an "
            f"attestation but carrying no signature is not evidence",
        )
        return
    sig_value = signature.get("signature")
    if not isinstance(sig_value, str) or not sig_value.startswith("hmac-sha256:"):
        findings.error("E_UNSIGNED_LOOKALIKE", f"{path.name}: signature field is {sig_value!r}")
    if not signature.get("key_id"):
        findings.error("E_UNSIGNED_LOOKALIKE", f"{path.name}: signature names no key_id")

    # THE CHECK THAT NEEDS NO SECRET. The digest binds the payload, so an edited
    # payload is caught here even though the HMAC cannot be recomputed.
    recorded = signature.get("payload_sha256")
    computed = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()
    if recorded != computed:
        findings.error(
            "E_PAYLOAD_DIGEST_MISMATCH",
            f"{path.name}: signature records {recorded}, payload hashes to {computed} — "
            f"the payload was altered after signing",
        )


def check_status(path: Path, findings: Findings) -> bool:
    """Returns True when this status accounts for an absent attestation."""
    try:
        status = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        findings.error("E_MALFORMED", f"{path.name}: not valid JSON ({exc})")
        return False
    if status.get("schema") != STATUS_SCHEMA:
        findings.error(
            "E_MALFORMED",
            f"{path.name}: status schema is {status.get('schema')!r}, expected {STATUS_SCHEMA!r}",
        )
        return False
    if status.get("attestation_emitted") is True:
        # Claiming emission obliges the artifact to exist; the caller checks.
        return False
    if status.get("outcome") != "SKIP":
        findings.error(
            "E_MALFORMED",
            f"{path.name}: no attestation was emitted but outcome is {status.get('outcome')!r}, expected SKIP",
        )
        return False
    reason = status.get("reason")
    if reason not in KNOWN_SKIP_REASONS:
        findings.error(
            "E_UNKNOWN_SKIP_REASON",
            f"{path.name}: skip reason {reason!r} is not one of {sorted(KNOWN_SKIP_REASONS)} — "
            f"the signer changed behaviour and nothing else would have noticed",
        )
        return False
    return True


def check_directory(directory: Path, findings: Findings) -> tuple[int, int]:
    attestations = sorted(p for p in directory.glob("*.jsonl"))
    statuses = sorted(p for p in directory.glob("*.status.json"))

    for path in attestations:
        check_attestation(path, findings)

    accounted = 0
    for path in statuses:
        stem = path.name[: -len(".status.json")]
        emitted_path = directory / f"{stem}.jsonl"
        try:
            claimed = json.loads(path.read_text(encoding="utf-8")).get("attestation_emitted")
        except json.JSONDecodeError:
            claimed = None
        if claimed is True and not emitted_path.exists():
            findings.error(
                "E_CLAIMED_NOT_EMITTED",
                f"{path.name}: claims attestation_emitted=true but {emitted_path.name} is absent",
            )
            continue
        if check_status(path, findings):
            accounted += 1

    if not attestations and not statuses:
        findings.error(
            "E_NO_EVIDENCE",
            f"{directory}: neither an attestation nor a typed SKIP status — a lane must say "
            f"which of the two happened; silence is not a result",
        )
    return len(attestations), accounted


# ---------------------------------------------------------------------------


def _write(directory: Path, name: str, payload: dict, signature: dict | None) -> None:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    out = body
    if signature is not None:
        sig = dict(signature)
        if sig.get("payload_sha256") == "@AUTO@":
            sig["payload_sha256"] = "sha256:" + hashlib.sha256(body).hexdigest()
        out = body + b"\n" + json.dumps(sig, separators=(",", ":"), sort_keys=True).encode()
    (directory / name).write_bytes(out + b"\n")


def _good_payload() -> dict:
    return {
        "schema": PAYLOAD_SCHEMA,
        "lane": "e2e",
        "repo": "oraclemcp",
        "git_sha": "0" * 40,
        "toolchain": "nightly-2026-05-11",
        "command": "bash scripts/e2e/run_all.sh",
        "created_at": "2026-07-22T00:00:00Z",
        "tests": [{"name": "e2e:ladder", "outcome": "PASS", "detail": ""}],
        "artifacts": [],
        "frame": "Signed evidence that the named checks produced the recorded outcomes.",
    }


def _good_signature() -> dict:
    return {
        "schema": SIGNATURE_SCHEMA,
        "key_id": "test-attestation-key",
        "payload_sha256": "@AUTO@",
        "signature": "hmac-sha256:" + "a" * 64,
    }


def selftest() -> int:
    import tempfile

    failures = 0

    def case(label: str, build, code: str | None) -> None:
        nonlocal failures
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            build(directory)
            findings = Findings()
            check_directory(directory, findings)
            if code is None:
                if len(findings):
                    print(f"selftest: {label}: valid evidence was REJECTED: {findings.items}", file=sys.stderr)
                    failures += 1
                return
            if code not in findings.codes():
                print(
                    f"selftest: {label}: expected {code}, got {sorted(findings.codes()) or 'no findings'}",
                    file=sys.stderr,
                )
                failures += 1

    # Accept cases first: a consumer that rejects everything is as useless as one
    # that rejects nothing, and only these tell the two apart.
    case("a well-formed signed attestation",
         lambda d: _write(d, "e2e.jsonl", _good_payload(), _good_signature()), None)

    def typed_skip(d: Path) -> None:
        (d / "e2e.status.json").write_text(json.dumps({
            "schema": STATUS_SCHEMA, "attestation_emitted": False, "blocked": True,
            "outcome": "SKIP", "reason": "operator-not-enabled", "lane": "e2e",
            "git_sha": "0" * 40, "toolchain": "n", "created_at": "2026-07-22T00:00:00Z",
        }))
    case("a typed SKIP status", typed_skip, None)

    # Rejections.
    case("an empty directory", lambda d: None, "E_NO_EVIDENCE")

    def tampered(d: Path) -> None:
        _write(d, "e2e.jsonl", _good_payload(), _good_signature())
        raw = (d / "e2e.jsonl").read_bytes().splitlines()
        payload = json.loads(raw[0])
        payload["tests"] = [{"name": "e2e:ladder", "outcome": "PASS", "detail": "edited"}]
        (d / "e2e.jsonl").write_bytes(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode() + b"\n" + raw[1] + b"\n"
        )
    case("a payload edited after signing", tampered, "E_PAYLOAD_DIGEST_MISMATCH")

    case("an unsigned lookalike",
         lambda d: _write(d, "e2e.jsonl", _good_payload(), None), "E_MALFORMED")

    def no_signature_envelope(d: Path) -> None:
        _write(d, "e2e.jsonl", _good_payload(), {"schema": "something-else/v1"})
    case("a second line that is not a signature", no_signature_envelope, "E_UNSIGNED_LOOKALIKE")

    def claimed_not_emitted(d: Path) -> None:
        (d / "e2e.status.json").write_text(json.dumps({
            "schema": STATUS_SCHEMA, "attestation_emitted": True, "blocked": False,
            "outcome": "PASS", "reason": "", "lane": "e2e",
        }))
    case("a status claiming an attestation that is absent", claimed_not_emitted, "E_CLAIMED_NOT_EMITTED")

    def unknown_reason(d: Path) -> None:
        (d / "e2e.status.json").write_text(json.dumps({
            "schema": STATUS_SCHEMA, "attestation_emitted": False, "blocked": True,
            "outcome": "SKIP", "reason": "because-i-said-so", "lane": "e2e",
        }))
    case("an unrecognised skip reason", unknown_reason, "E_UNKNOWN_SKIP_REASON")

    if failures:
        print("check_test_attestations selftest: FAIL", file=sys.stderr)
        return 1
    print("check_test_attestations selftest: OK (valid evidence and a typed SKIP are accepted; "
          "missing, tampered, unsigned, claimed-but-absent and unknown-reason are all rejected)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", type=Path)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument(
        "--require-signed",
        action="store_true",
        help="fail when every lane merely SKIPPED; use once a signing key exists",
    )
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if args.directory is None:
        parser.error("a directory is required unless --selftest is given")
    if not args.directory.is_dir():
        # AN ABSENT DIRECTORY IS A RESULT, NOT A CRASH. It is what a lane looks
        # like when the signer never ran at all — the same honest path as "every
        # lane skipped", not a filesystem error. Dying here made a run that
        # produced no attestations indistinguishable from a broken checker, and
        # hard-failed CI for the one outcome this script exists to report calmly.
        print(
            f"check_test_attestations: {args.directory} does not exist, so this lane produced "
            "NO attestations at all — not even a typed SKIP status. The signer is gated on "
            "vars.ENABLE_TEST_ATTESTATION plus the ORACLEMCP_TEST_ATTESTATION_KEY secret, and "
            "neither exists in this repository. Do not cite this run as attested."
        )
        if args.require_signed:
            print("FAIL check_test_attestations: --require-signed was given and no lane signed")
            return 1
        return 0

    findings = Findings()
    signed, skipped = check_directory(args.directory, findings)

    for code, message in findings.items:
        print(f"  {code}: {message}")
    if len(findings):
        print(f"FAIL check_test_attestations: {len(findings)} finding(s)")
        return 1

    if signed == 0 and skipped > 0:
        # THE INERT STATE, SAID OUT LOUD. The signer is gated on a repo variable
        # and a secret that this repository does not have, so every lane skips.
        # That is a legitimate operator choice, but it must never read as "we
        # have signed evidence".
        print(
            f"check_test_attestations: {skipped} lane(s) SKIPPED and NOTHING WAS SIGNED. "
            "The attestation machinery is present but inert: it is gated on "
            "vars.ENABLE_TEST_ATTESTATION plus the ORACLEMCP_TEST_ATTESTATION_KEY secret, "
            "and neither exists in this repository. Do not cite these runs as attested."
        )
        if args.require_signed:
            print("FAIL check_test_attestations: --require-signed was given and no lane signed")
            return 1
        return 0

    print(f"PASS check_test_attestations: {signed} signed attestation(s), {skipped} typed SKIP(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
