#!/usr/bin/env bash
# Validate release SBOM source wiring and merged CycloneDX release artifacts.
#
# Freshness is checked against a CANONICAL CycloneDX projection that preserves
# every stable security/legal field — component hashes, licenses, scope,
# properties and external references — plus the dependency graph, dropping only
# proven-nondeterministic generator fields (serial number, build timestamp, tool
# versions). A stale or degraded SBOM that silently loses a hash or a license
# therefore FAILS the gate instead of passing as "fresh" (bead
# oraclemcp-qa100 .42).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat >&2 <<'USAGE'
usage: scripts/release_sbom_check.sh --source
       scripts/release_sbom_check.sh --artifact <oraclemcp-version.cdx.json>
       scripts/release_sbom_check.sh --canonical <sbom.cdx.json>
       scripts/release_sbom_check.sh --generate-dashboard <output.cyclonedx.json>
       scripts/release_sbom_check.sh --normalize-dashboard [input.cyclonedx.json]
USAGE
}

fail() {
  echo "release-sbom-check: $*" >&2
  exit 1
}

note() {
  echo "release-sbom-check: NOTE $*" >&2
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

require_grep() {
  local needle="$1"
  local path="$2"
  grep -F "$needle" "$path" >/dev/null || fail "$path must contain: $needle"
}

# Canonical CycloneDX projection (bead oraclemcp-qa100 .42).
#
# Preserves ALL stable content — the whole metadata.component, and every
# component field including hashes, licenses, scope, properties and
# externalReferences — plus the dependency edges. Only genuinely
# nondeterministic generator fields are removed: the random serialNumber, the
# build timestamp, and the tool list (whose versions drift between runs). Every
# array is deep-sorted so array-ordering differences between otherwise-identical
# documents do not read as drift. `jq -S` sorts object keys.
CANONICAL_JQ='
  def sort_deep: walk(if type == "array" then sort_by(tojson) else . end);
  del(.serialNumber)
  | del(.metadata.timestamp)
  | del(.metadata.tools)
  | sort_deep
'

# Dependency-closure + duplicate-ref invariants for any CycloneDX document:
# component bom-refs are unique, and every dependency ref / dependsOn target
# resolves to a component bom-ref or the root metadata component. Emits `true`.
CLOSURE_JQ='
  ([ .components[]? | .["bom-ref"] // empty ]) as $refs
  | ([ .metadata.component["bom-ref"] // empty ] + $refs) as $known
  | (($refs | length) == ($refs | unique | length))
    and all(.dependencies[]?; (.ref as $r | any($known[]; . == $r)))
    and all(.dependencies[]?; all((.dependsOn // [])[]; . as $d | any($known[]; . == $d)))
'

# npm identifies components by package name and version, so two installations
# of the same version can be emitted with the same bom-ref. CycloneDX requires
# component bom-refs to be unique. Collapse only duplicates whose security and
# legal metadata is identical after removing the installation-path property;
# preserve every distinct property and dependency edge. Conflicting duplicate
# metadata is refused rather than silently choosing one component.
NORMALIZE_DASHBOARD_JQ='
  def without_installation_path:
    .properties = ((.properties // [])
      | map(select(.name != "cdx:npm:package:path"))
      | unique
      | sort_by([.name // "", .value // ""]));
  def merge_component_group:
    . as $group
    | ([$group[] | without_installation_path] | unique) as $identities
    | if ($identities | length) != 1 then
        error("conflicting duplicate component bom-ref: \($group[0]["bom-ref"])")
      else
        $group[0]
        | .properties = ([$group[] | .properties[]?]
          | unique
          | sort_by([.name // "", .value // ""]))
      end;
  def merge_dependency_group:
    . as $group
    | ([$group[] | del(.dependsOn)] | unique) as $identities
    | if ($identities | length) != 1 then
        error("conflicting duplicate dependency ref: \($group[0].ref)")
      else
        $group[0]
        | .dependsOn = ([$group[] | .dependsOn[]?] | unique | sort)
      end;
  if any(.components[]?; has("bom-ref") | not) then
    error("dashboard component is missing bom-ref")
  else
    .components = ((.components // [])
      | sort_by(."bom-ref")
      | group_by(."bom-ref")
      | map(merge_component_group))
    | .dependencies = ((.dependencies // [])
      | sort_by(.ref)
      | group_by(.ref)
      | map(merge_dependency_group))
  end
'

canonicalize() {
  local file="$1"
  local out="$2"
  jq -S "$CANONICAL_JQ" "$file" >"$out"
}

check_closure() {
  local file="$1"
  jq -e "$CLOSURE_JQ" "$file" >/dev/null ||
    fail "$file has duplicate component bom-refs or dangling dependency references"
}

generate_dashboard() {
  local output="$1"
  local raw_dir="$ROOT/target/release-sbom-check"
  local raw
  raw="$raw_dir/$(basename "$output").raw"
  mkdir -p "$raw_dir" "$(dirname "$output")"

  echo "release-sbom-check: ensuring dashboard frontend dependencies are freshly installed"
  (cd "$ROOT/web" && npm ci --ignore-scripts --no-audit --no-fund) ||
    fail "release-sbom-check prerequisite failed: npm ci could not install web dependencies"

  # npm 10.9.4 truncates `npm sbom` at 64 KiB when its stdout is a pipe on
  # some supported runtimes. Capture the complete raw document to a file before
  # normalizing it so generation cannot silently accept a partial stream.
  (cd "$ROOT/web" && npm sbom --sbom-format cyclonedx --json >"$raw") ||
    fail "release-sbom-check failed to generate dashboard SBOM from package-lock.json and package.json"
  jq -S "$NORMALIZE_DASHBOARD_JQ" "$raw" >"$output"
  validate_schema "$output"
  check_closure "$output"
}

# Schema validation. Prefers a real CycloneDX JSON-Schema validator when one is
# available; otherwise runs structural "schema-lite" invariants and NOTEs that
# full schema validation was skipped (bead oraclemcp-qa100 .42: degrade
# gracefully, name what could not run locally).
validate_schema() {
  local file="$1"
  if command -v check-jsonschema >/dev/null 2>&1 &&
    [ -n "${CYCLONEDX_SCHEMA:-}" ] && [ -f "${CYCLONEDX_SCHEMA:-}" ]; then
    check-jsonschema --schemafile "$CYCLONEDX_SCHEMA" "$file" >/dev/null ||
      fail "$file failed CycloneDX JSON-Schema validation"
    return 0
  fi
  jq -e '
    .bomFormat == "CycloneDX"
    and (.specVersion | type) == "string"
    and (.metadata.component | type) == "object"
    and ((.components // []) | all(type == "object" and has("bom-ref") and has("name")))
    and ((.dependencies // []) | all(type == "object" and has("ref")))
  ' "$file" >/dev/null ||
    fail "$file is not a structurally valid CycloneDX document"
  note "full CycloneDX JSON-Schema validation skipped (no validator on PATH); ran structural schema-lite checks on $file"
}

check_source() {
  need jq
  need npm

  # Allow tests to point the "existing" dashboard SBOM at a copy so
  # failure-on-mutation can be exercised without editing the tracked file.
  local dashboard_sbom="${SBOM_DASHBOARD_OVERRIDE:-$ROOT/web/dist/oraclemcp-dashboard.cyclonedx.json}"
  local package_json="$ROOT/web/package.json"
  local workflow="$ROOT/.github/workflows/release.yml"

  [ -f "$ROOT/scripts/merge_release_sbom.sh" ] || fail "missing scripts/merge_release_sbom.sh"
  [ -f "$dashboard_sbom" ] || fail "missing dashboard SBOM: $dashboard_sbom"
  [ -f "$package_json" ] || fail "missing web/package.json"

  local package_name package_version
  package_name="$(jq -r '.name' "$package_json")"
  package_version="$(jq -r '.version' "$package_json")"
  jq -e '
    .bomFormat == "CycloneDX" and
    .specVersion == "1.5" and
    .metadata.component["bom-ref"] == ($name + "@" + $version) and
    .metadata.component.purl == ("pkg:npm/%40oraclemcp/dashboard@" + $version)
  ' --arg name "$package_name" --arg version "$package_version" "$dashboard_sbom" >/dev/null ||
    fail "dashboard SBOM is not current for $package_name@$package_version"

  # The checked-in dashboard SBOM must itself be integrity-complete and
  # schema-valid, and its dependency graph must close.
  validate_schema "$dashboard_sbom"
  check_closure "$dashboard_sbom"

  local check_dir="$ROOT/target/release-sbom-check"
  local current_dashboard_sbom="$check_dir/current-dashboard.cyclonedx.json"
  local existing_normalized="$check_dir/existing-dashboard.normalized.json"
  local current_normalized="$check_dir/current-dashboard.normalized.json"
  mkdir -p "$check_dir"
  generate_dashboard "$current_dashboard_sbom"

  # Compare the CANONICAL projection (hashes/licenses/scope/properties/external
  # references + dependency edges preserved) rather than a bare identity subset,
  # so a dropped or mutated hash/license makes the gate fail.
  canonicalize "$dashboard_sbom" "$existing_normalized"
  canonicalize "$current_dashboard_sbom" "$current_normalized"
  cmp -s "$existing_normalized" "$current_normalized" ||
    fail "dashboard SBOM is stale or degraded for web/package-lock.json (hash/license/metadata drift); run npm run build in web/"

  require_grep "pattern: oraclemcp-*-*-*" "$workflow"
  require_grep "name: oraclemcp-dashboard-dist" "$workflow"
  require_grep "path: web/dist" "$workflow"
  require_grep "bash scripts/merge_release_sbom.sh" "$workflow"
  require_grep "web/dist/oraclemcp-dashboard.cyclonedx.json" "$workflow"
  require_grep "bash scripts/release_sbom_check.sh --artifact" "$workflow"
  require_grep 'artifacts/oraclemcp-${{ steps.version.outputs.version }}.cdx.json' "$workflow"
  require_grep "artifacts/*.cdx.json.attestation.sigstore.json" "$workflow"

  echo "release-sbom-check: OK source"
}

check_artifact() {
  need jq

  local artifact="$1"
  [ -f "$artifact" ] || fail "missing release SBOM artifact: $artifact"
  [ -f "$ROOT/web/package.json" ] || fail "missing web/package.json"

  local dashboard_version dashboard_purl
  dashboard_version="$(jq -r '.version' "$ROOT/web/package.json")"
  dashboard_purl="pkg:npm/%40oraclemcp/dashboard@$dashboard_version"

  jq -e '
    [ .components[]? | select(has("bom-ref")) | .["bom-ref"] ] as $refs
    | ([ .metadata.properties[]? | select(.name == "oraclemcp:dashboard:root-bom-ref") | .value ][0]) as $dashboard_ref
    | (.metadata.component["bom-ref"] // .metadata.component.name) as $root_ref
    | .bomFormat == "CycloneDX" and
      .specVersion == "1.5" and
      .metadata.component.name == "oraclemcp" and
      any(.metadata.properties[]?; .name == "oraclemcp:sbom:merged" and .value == "true") and
      any(.metadata.properties[]?; .name == "oraclemcp:sbom:includes" and .value == "rust-cargo") and
      any(.metadata.properties[]?; .name == "oraclemcp:sbom:includes" and .value == "dashboard-npm") and
      ($refs | length) == ($refs | unique | length) and
      ($dashboard_ref != null) and
      any(.components[]?; .purl == $dashboard_purl and .["bom-ref"] == $dashboard_ref) and
      any(.components[]?; ((.purl? // "") | startswith("pkg:npm/"))) and
      any(.components[]?; ((.purl? // "") | startswith("pkg:cargo/"))) and
      any(.dependencies[]?; .ref == $root_ref and (((.dependsOn // []) | index($dashboard_ref)) != null))
  ' --arg dashboard_purl "$dashboard_purl" "$artifact" >/dev/null ||
    fail "release SBOM must merge Rust cargo and dashboard npm components"

  # The merged artifact must also be schema-valid and have a closed dependency
  # graph — no dangling refs, no duplicate component bom-refs.
  validate_schema "$artifact"
  check_closure "$artifact"

  echo "release-sbom-check: OK artifact=$artifact"
}

[ "$#" -ge 1 ] || {
  usage
  exit 2
}

case "$1" in
  --source)
    [ "$#" -eq 1 ] || {
      usage
      exit 2
    }
    check_source
    ;;
  --artifact)
    [ "$#" -eq 2 ] || {
      usage
      exit 2
    }
    check_artifact "$2"
    ;;
  --canonical)
    # Emit the canonical projection of an SBOM (bead oraclemcp-qa100 .42): the
    # exact bytes the freshness gate compares. Reused by the test harness to
    # prove a mutated hash/license changes the canonical output while a
    # timestamp/tool/serialNumber change does not.
    [ "$#" -eq 2 ] || {
      usage
      exit 2
    }
    need jq
    [ -f "$2" ] || fail "missing SBOM: $2"
    jq -S "$CANONICAL_JQ" "$2"
    ;;
  --normalize-dashboard)
    [ "$#" -le 2 ] || {
      usage
      exit 2
    }
    need jq
    if [ "$#" -eq 2 ]; then
      [ -f "$2" ] || fail "missing dashboard SBOM: $2"
      jq -S "$NORMALIZE_DASHBOARD_JQ" "$2"
    else
      jq -S "$NORMALIZE_DASHBOARD_JQ"
    fi
    ;;
  --generate-dashboard)
    [ "$#" -eq 2 ] || {
      usage
      exit 2
    }
    need jq
    need npm
    generate_dashboard "$2"
    ;;
  *)
    usage
    exit 2
    ;;
esac
