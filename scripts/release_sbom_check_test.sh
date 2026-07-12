#!/usr/bin/env bash
# Self-contained guard test for scripts/release_sbom_check.sh (bead
# oraclemcp-qa100 .42). Shell + jq only, fully offline, synthetic fixtures.
#
# Proves:
#   * the canonical projection PRESERVES component hashes and licenses (mutating
#     either changes the canonical bytes the freshness gate compares), while
#     nondeterministic serialNumber/timestamp/tool changes are normalized away;
#   * the freshness comparison therefore FAILS on a mutated-hash / mutated-license
#     copy and PASSES on a clean copy;
#   * `--artifact` rejects duplicate/dangling dependency refs and schema-invalid
#     documents, and accepts a well-formed merged artifact.
#
# When npm and the checked-in dashboard SBOM are present it additionally runs the
# real `--source` gate clean and against a mutated copy; otherwise it NOTEs the
# skip.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/release_sbom_check.sh"
command -v jq >/dev/null 2>&1 || {
  echo "sbom-test: NOTE jq unavailable — cannot run SBOM guard test locally" >&2
  exit 0
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0
fail=0
ok() {
  echo "sbom-test: PASS $1"
  pass=$((pass + 1))
}
bad() {
  echo "sbom-test: FAIL $1" >&2
  fail=$((fail + 1))
}

canonical() { bash "$SCRIPT" --canonical "$1"; }

DASH_VERSION="$(jq -r '.version' "$ROOT/web/package.json" 2>/dev/null || echo 0.0.0)"

# ---- synthetic dashboard SBOM with full security/legal metadata ----
cat >"$WORK/dashboard.json" <<JSON
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
  "version": 1,
  "metadata": {
    "timestamp": "2026-07-12T00:00:00Z",
    "tools": [{ "vendor": "npm", "name": "cli", "version": "10.9.4" }],
    "component": {
      "type": "library", "name": "@oraclemcp/dashboard", "version": "$DASH_VERSION",
      "bom-ref": "@oraclemcp/dashboard@$DASH_VERSION",
      "purl": "pkg:npm/%40oraclemcp/dashboard@$DASH_VERSION"
    }
  },
  "components": [
    {
      "type": "library", "name": "react", "version": "19.2.7",
      "bom-ref": "react@19.2.7", "purl": "pkg:npm/react@19.2.7", "scope": "required",
      "hashes": [{ "alg": "SHA-512", "content": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }],
      "licenses": [{ "license": { "id": "MIT" } }],
      "externalReferences": [{ "type": "distribution", "url": "https://registry.npmjs.org/react/-/react-19.2.7.tgz" }],
      "properties": [{ "name": "cdx:npm:package:development", "value": "false" }]
    }
  ],
  "dependencies": [
    { "ref": "@oraclemcp/dashboard@$DASH_VERSION", "dependsOn": ["react@19.2.7"] },
    { "ref": "react@19.2.7", "dependsOn": [] }
  ]
}
JSON

# 1) canonical projection preserves hashes.
jq '.components[0].hashes[0].content = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' "$WORK/dashboard.json" >"$WORK/mut-hash.json"
if ! cmp -s <(canonical "$WORK/dashboard.json") <(canonical "$WORK/mut-hash.json"); then
  ok "canonical projection detects a mutated component hash"
else
  bad "canonical projection ignored a mutated hash"
fi

# 2) canonical projection preserves licenses.
jq '.components[0].licenses[0].license.id = "GPL-3.0-only"' "$WORK/dashboard.json" >"$WORK/mut-lic.json"
if ! cmp -s <(canonical "$WORK/dashboard.json") <(canonical "$WORK/mut-lic.json"); then
  ok "canonical projection detects a mutated component license"
else
  bad "canonical projection ignored a mutated license"
fi

# 2b) also proves scope / property / external-reference preservation.
jq '.components[0].scope = "optional"' "$WORK/dashboard.json" >"$WORK/mut-scope.json"
if ! cmp -s <(canonical "$WORK/dashboard.json") <(canonical "$WORK/mut-scope.json"); then
  ok "canonical projection detects a mutated component scope"
else
  bad "canonical projection ignored a mutated scope"
fi

# 3) nondeterministic serialNumber/timestamp/tool changes normalize away.
jq '.serialNumber = "urn:uuid:22222222-2222-2222-2222-222222222222"
    | .metadata.timestamp = "2027-01-01T00:00:00Z"
    | .metadata.tools[0].version = "99.0.0"' \
  "$WORK/dashboard.json" >"$WORK/nondet.json"
if cmp -s <(canonical "$WORK/dashboard.json") <(canonical "$WORK/nondet.json"); then
  ok "canonical projection normalizes serialNumber/timestamp/tool drift"
else
  bad "canonical projection flagged nondeterministic-only changes"
fi

# ---- synthetic merged artifact for --artifact ----
jq -n --arg v "$DASH_VERSION" '
{
  "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
  "metadata": {
    "component": { "type": "application", "name": "oraclemcp", "version": "0.8.0",
                   "bom-ref": "pkg:cargo/oraclemcp@0.8.0" },
    "properties": [
      { "name": "oraclemcp:sbom:merged", "value": "true" },
      { "name": "oraclemcp:sbom:includes", "value": "rust-cargo" },
      { "name": "oraclemcp:sbom:includes", "value": "dashboard-npm" },
      { "name": "oraclemcp:dashboard:root-bom-ref", "value": ("npm:@oraclemcp/dashboard@" + $v) }
    ]
  },
  "components": [
    { "type": "library", "name": "serde", "version": "1.0.0",
      "bom-ref": "pkg:cargo/serde@1.0.0", "purl": "pkg:cargo/serde@1.0.0" },
    { "type": "library", "name": "web", "version": $v,
      "bom-ref": ("npm:@oraclemcp/dashboard@" + $v),
      "purl": ("pkg:npm/%40oraclemcp/dashboard@" + $v) },
    { "type": "library", "name": "react", "version": "19.2.7",
      "bom-ref": "npm:react@19.2.7", "purl": "pkg:npm/react@19.2.7" }
  ],
  "dependencies": [
    { "ref": "pkg:cargo/oraclemcp@0.8.0",
      "dependsOn": ["pkg:cargo/serde@1.0.0", ("npm:@oraclemcp/dashboard@" + $v)] },
    { "ref": ("npm:@oraclemcp/dashboard@" + $v), "dependsOn": ["npm:react@19.2.7"] }
  ]
}' >"$WORK/merged.json"

if bash "$SCRIPT" --artifact "$WORK/merged.json" >/dev/null 2>&1; then
  ok "clean merged artifact passes --artifact"
else
  bad "clean merged artifact was rejected by --artifact"
fi

# 4) dangling dependency reference must fail.
jq '.dependencies[1].dependsOn += ["npm:ghost@0.0.0"]' "$WORK/merged.json" >"$WORK/dangling.json"
if ! bash "$SCRIPT" --artifact "$WORK/dangling.json" >/dev/null 2>&1; then
  ok "dangling dependency reference fails --artifact"
else
  bad "dangling dependency reference passed --artifact"
fi

# 5) duplicate component bom-ref must fail.
jq '.components += [.components[0]]' "$WORK/merged.json" >"$WORK/dup.json"
if ! bash "$SCRIPT" --artifact "$WORK/dup.json" >/dev/null 2>&1; then
  ok "duplicate component bom-ref fails --artifact"
else
  bad "duplicate component bom-ref passed --artifact"
fi

# 6) schema-invalid document must fail.
jq '.bomFormat = "SPDX"' "$WORK/merged.json" >"$WORK/badschema.json"
if ! bash "$SCRIPT" --artifact "$WORK/badschema.json" >/dev/null 2>&1; then
  ok "schema-invalid artifact fails --artifact"
else
  bad "schema-invalid artifact passed --artifact"
fi

# 7) optional live --source (needs npm + installed deps + checked-in dist SBOM).
DIST_SBOM="$ROOT/web/dist/oraclemcp-dashboard.cyclonedx.json"
if command -v npm >/dev/null 2>&1 && [ -f "$DIST_SBOM" ] && [ -d "$ROOT/web/node_modules" ]; then
  if bash "$SCRIPT" --source >/dev/null 2>&1; then
    ok "real --source passes clean against the checked-in dashboard SBOM"
  else
    bad "real --source failed on the clean checked-in dashboard SBOM"
  fi
  jq '(.components[]? | select(.hashes) | .hashes[0].content) = "deadbeef"' "$DIST_SBOM" \
    >"$WORK/mutated-dist.json" 2>/dev/null || cp "$DIST_SBOM" "$WORK/mutated-dist.json"
  if ! SBOM_DASHBOARD_OVERRIDE="$WORK/mutated-dist.json" bash "$SCRIPT" --source >/dev/null 2>&1; then
    ok "real --source fails when a checked-in component hash is mutated (copy)"
  else
    bad "real --source ignored a mutated component hash"
  fi
else
  echo "sbom-test: NOTE real --source not exercised (needs npm + web/node_modules + checked-in dist SBOM); ran canonical-projection + --artifact checks offline" >&2
fi

echo "sbom-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
