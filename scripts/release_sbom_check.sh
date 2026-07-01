#!/usr/bin/env bash
# Validate release SBOM source wiring and merged CycloneDX release artifacts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat >&2 <<'USAGE'
usage: scripts/release_sbom_check.sh --source
       scripts/release_sbom_check.sh --artifact <oraclemcp-version.cdx.json>
USAGE
}

fail() {
  echo "release-sbom-check: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

require_grep() {
  local needle="$1"
  local path="$2"
  grep -F "$needle" "$path" >/dev/null || fail "$path must contain: $needle"
}

check_source() {
  need jq
  need npm

  local dashboard_sbom="$ROOT/web/dist/oraclemcp-dashboard.cyclonedx.json"
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

  local check_dir="$ROOT/target/release-sbom-check"
  local current_dashboard_sbom="$check_dir/current-dashboard.cyclonedx.json"
  local existing_normalized="$check_dir/existing-dashboard.normalized.json"
  local current_normalized="$check_dir/current-dashboard.normalized.json"
  mkdir -p "$check_dir"
  (cd "$ROOT/web" && npm sbom --sbom-format cyclonedx --json >"$current_dashboard_sbom")

  jq -S '
    def normalized:
      {
        root: .metadata.component,
        components: (
          (.components // [])
          | map({
              "bom-ref": .["bom-ref"],
              name,
              version,
              purl
            })
          | sort_by(."bom-ref")
        ),
        dependencies: (
          (.dependencies // [])
          | map({
              ref,
              dependsOn: ((.dependsOn // []) | sort)
            })
          | sort_by(.ref)
        )
      };
    normalized
  ' "$dashboard_sbom" >"$existing_normalized"
  jq -S '
    def normalized:
      {
        root: .metadata.component,
        components: (
          (.components // [])
          | map({
              "bom-ref": .["bom-ref"],
              name,
              version,
              purl
            })
          | sort_by(."bom-ref")
        ),
        dependencies: (
          (.dependencies // [])
          | map({
              ref,
              dependsOn: ((.dependsOn // []) | sort)
            })
          | sort_by(.ref)
        )
      };
    normalized
  ' "$current_dashboard_sbom" >"$current_normalized"
  cmp -s "$existing_normalized" "$current_normalized" ||
    fail "dashboard SBOM is stale for web/package-lock.json; run npm run build in web/"

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
  *)
    usage
    exit 2
    ;;
esac
