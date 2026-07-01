#!/usr/bin/env bash
# Merge the Rust cargo-cyclonedx SBOM with the dashboard npm CycloneDX SBOM.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat >&2 <<'USAGE'
usage: scripts/merge_release_sbom.sh <rust-sbom.cdx.json> <dashboard-sbom.cdx.json> <output.cdx.json>
USAGE
}

fail() {
  echo "merge-release-sbom: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

[ "$#" -eq 3 ] || {
  usage
  exit 2
}

rust_sbom="$1"
dashboard_sbom="$2"
output="$3"

need jq
[ -f "$rust_sbom" ] || fail "missing Rust SBOM: $rust_sbom"
[ -f "$dashboard_sbom" ] || fail "missing dashboard SBOM: $dashboard_sbom"

output_dir="$(dirname "$output")"
mkdir -p "$output_dir"

jq -S -n --slurpfile rust "$rust_sbom" --slurpfile dashboard "$dashboard_sbom" '
  def die($message): error($message);
  def prefix_ref($ref): if $ref == null then null else "npm:" + ($ref | tostring) end;
  def prefix_component_ref:
    if has("bom-ref") then .["bom-ref"] = prefix_ref(.["bom-ref"]) else . end;
  def prefix_dependency_ref:
    .ref = prefix_ref(.ref)
    | .dependsOn = ((.dependsOn // []) | map(prefix_ref(.)));
  def component_key:
    .["bom-ref"] // ((.type // "library") + ":" + (.name // "") + ":" + (.version // ""));
  def tool_entries($tools):
    if ($tools | type) == "array" then $tools
    elif ($tools | type) == "object" and (($tools.components // null) | type) == "array" then $tools.components
    else []
    end;

  ($rust[0]) as $r
  | ($dashboard[0]) as $d
  | if ($r.bomFormat != "CycloneDX") then die("Rust SBOM is not CycloneDX")
    elif ($d.bomFormat != "CycloneDX") then die("dashboard SBOM is not CycloneDX")
    elif ($r.specVersion != "1.5") then die("Rust SBOM must use CycloneDX 1.5")
    elif ($d.specVersion != "1.5") then die("dashboard SBOM must use CycloneDX 1.5")
    elif ((($r.components // null) | type) != "array") then die("Rust SBOM has no components array")
    elif ((($d.components // null) | type) != "array") then die("dashboard SBOM has no components array")
    elif (((($d.metadata.component.purl // "") | startswith("pkg:npm/%40oraclemcp/dashboard@")) | not)) then die("dashboard SBOM root is not @oraclemcp/dashboard")
    else
      ($r.metadata.component["bom-ref"] // $r.metadata.component.name // "oraclemcp") as $root_ref
      | ($d.metadata.component["bom-ref"] // ($d.metadata.component.name + "@" + $d.metadata.component.version)) as $dashboard_ref
      | (prefix_ref($dashboard_ref)) as $dashboard_root_ref
      | ($d.metadata.component | prefix_component_ref) as $dashboard_root_component
      | (($d.components // []) | map(prefix_component_ref)) as $dashboard_components
      | (($d.dependencies // []) | map(prefix_dependency_ref)) as $dashboard_dependencies
      | ($r.dependencies // []) as $rust_dependencies
      | (
          if ($root_ref == null) then $rust_dependencies
          elif any($rust_dependencies[]?; .ref == $root_ref) then
            $rust_dependencies
            | map(
                if .ref == $root_ref then
                  .dependsOn = (((.dependsOn // []) + [$dashboard_root_ref]) | unique)
                else
                  .
                end
              )
          else
            $rust_dependencies + [{ref: $root_ref, dependsOn: [$dashboard_root_ref]}]
          end
        ) as $rust_dependencies_with_dashboard
      | $r
      | .metadata.tools = (
          (tool_entries($r.metadata.tools) + tool_entries($d.metadata.tools))
          | unique_by((.vendor // "") + "\u0000" + (.name // "") + "\u0000" + (.version // ""))
        )
      | .metadata.properties = (
          (($r.metadata.properties // []) + [
            {"name": "oraclemcp:sbom:merged", "value": "true"},
            {"name": "oraclemcp:sbom:includes", "value": "rust-cargo"},
            {"name": "oraclemcp:sbom:includes", "value": "dashboard-npm"},
            {"name": "oraclemcp:dashboard:root-bom-ref", "value": $dashboard_root_ref}
          ])
          | unique_by(.name + "\u0000" + .value)
        )
      | .components = (
          (($r.components // []) + [$dashboard_root_component] + $dashboard_components)
          | unique_by(component_key)
        )
      | .dependencies = (
          ($rust_dependencies_with_dashboard + $dashboard_dependencies)
          | unique_by(.ref)
        )
    end
' >"$output"

bash "$ROOT/scripts/release_sbom_check.sh" --artifact "$output"
echo "merge-release-sbom: OK $output"
