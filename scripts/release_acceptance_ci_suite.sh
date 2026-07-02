#!/usr/bin/env bash
# Unified release-acceptance CI suite (Appendix B.12 / HCI).
#
# This is the named machine gate that aggregates the existing release-blocking
# component gates. In PR CI, feature-powerset may be asserted by the required
# `feature-powerset` job dependency to avoid running cargo-hack twice.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="release_acceptance_ci_suite"
E2E_LANE="ci"
E2E_PROFILE="release"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

skip_feature_powerset=false

usage() {
  cat <<'USAGE'
Run the unified release-acceptance CI suite.

Options:
  --skip-feature-powerset  assert cargo-hack coverage through the surrounding CI
                           job dependency instead of running it here
USAGE
  e2e_usage_common
}

for arg in "$@"; do
  set +e
  e2e_parse_common_arg "$arg"
  parsed=$?
  set -e
  case "$parsed" in
    0) continue ;;
    3)
      usage
      exit 0
      ;;
    1)
      case "$arg" in
        --skip-feature-powerset)
          skip_feature_powerset=true
          ;;
        *)
          echo "release_acceptance_ci_suite: unknown argument: $arg" >&2
          exit 2
          ;;
      esac
      ;;
  esac
done

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "Appendix B.12 release acceptance suite"

required=(
  .github/workflows/ci.yml
  .github/workflows/release.yml
  scripts/oraclemcp_concurrency_lint.sh
  scripts/oraclemcp_ergonomics_lint.sh
  scripts/e2e/doctor_fixtures.sh
  scripts/dashboard_bundle_check.sh
  scripts/oraclemcp_feature_powerset.sh
  scripts/oraclemcp_arch_fitness_lint.sh
  scripts/e2e/release_rollback_dry_run.sh
  scripts/installer_lint_and_offline_smoke.sh
  scripts/merge_release_sbom.sh
  scripts/release_sbom_check.sh
  scripts/e2e/COVERAGE.md
  scripts/e2e/PROVENANCE.md
)
missing=0
for path in "${required[@]}"; do
  if [ ! -f "$path" ]; then
    echo "missing release-acceptance gate file: $path" >&2
    missing=$((missing + 1))
  fi
done
if [ "$missing" -ne 0 ]; then
  e2e_finish_fail "$missing release-acceptance gate file(s) missing"
fi

if ! grep -F "release acceptance suite" .github/workflows/ci.yml >/dev/null; then
  e2e_finish_fail "ci.yml must expose the release acceptance suite job"
fi
if ! grep -F "scripts/release_acceptance_ci_suite.sh" .github/workflows/ci.yml >/dev/null; then
  e2e_finish_fail "ci.yml must run the release acceptance suite script"
fi
if ! grep -F "installer lint and built-artifact smoke" .github/workflows/ci.yml >/dev/null; then
  e2e_finish_fail "ci.yml must expose the installer built-artifact smoke job"
fi
if ! grep -F "ORACLEMCP_INSTALLER_BUILT_BINARY" .github/workflows/ci.yml >/dev/null; then
  e2e_finish_fail "ci.yml must run installer smoke against a built artifact"
fi
if ! grep -F "Windows installer PSSA and dry-run" .github/workflows/ci.yml >/dev/null; then
  e2e_finish_fail "ci.yml must expose the Windows installer PSSA job"
fi
if ! grep -F "scripts/release_acceptance_ci_suite.sh" .github/workflows/release.yml >/dev/null; then
  e2e_finish_fail "release.yml must gate tags with the release acceptance suite script"
fi
if ! grep -F "Release acceptance CI suite" scripts/e2e/COVERAGE.md >/dev/null; then
  e2e_finish_fail "COVERAGE.md must account for the HCI release acceptance suite"
fi
if ! grep -F "Rollback runbook dry-run" scripts/e2e/COVERAGE.md >/dev/null; then
  e2e_finish_fail "COVERAGE.md must account for the H7 rollback runbook dry-run"
fi
if ! grep -F "scripts/release_acceptance_ci_suite.sh" scripts/e2e/PROVENANCE.md >/dev/null; then
  e2e_finish_fail "PROVENANCE.md must document the HCI release acceptance suite command"
fi

if ! e2e_run_command "assert" bash scripts/oraclemcp_concurrency_lint.sh; then
  e2e_finish_fail "DL-9 concurrency-audit lint failed"
fi
if ! e2e_run_command "assert" bash scripts/oraclemcp_ergonomics_lint.sh; then
  e2e_finish_fail "ERG-10 ergonomics drift guard failed"
fi
if ! e2e_run_command "assert" bash scripts/e2e/doctor_fixtures.sh --log; then
  e2e_finish_fail "DOC-10 doctor fixture gate failed"
fi
if ! e2e_run_command "assert" bash scripts/dashboard_bundle_check.sh; then
  e2e_finish_fail "E0 dashboard web-build artifact check failed"
fi
if ! e2e_run_command "assert" bash scripts/release_sbom_check.sh --source; then
  e2e_finish_fail "S-sbom release SBOM source gate failed"
fi
if ! e2e_run_command "assert" bash scripts/installer_lint_and_offline_smoke.sh --log; then
  e2e_finish_fail "E7 installer lint/smoke failed"
fi
if ! e2e_run_command "assert" bash scripts/e2e/release_rollback_dry_run.sh --log --dry-run; then
  e2e_finish_fail "H7 rollback runbook dry-run failed"
fi
if [ "$skip_feature_powerset" = true ]; then
  e2e_log_event "component_gate" "assert" "pass" 0 "feature-powerset asserted by required CI dependency"
else
  if ! e2e_run_command "assert" bash scripts/oraclemcp_feature_powerset.sh; then
    e2e_finish_fail "feature-powerset gate failed"
  fi
fi
if ! e2e_run_command "assert" bash scripts/oraclemcp_arch_fitness_lint.sh; then
  e2e_finish_fail "architecture fitness lint failed"
fi

e2e_log_event "suite_summary" "assert" "pass" 0 "DL-9 ERG-10 DOC-10 E0 S-sbom installer-jsonl rollback feature-powerset arch-fitness accounted"
e2e_finish_pass
