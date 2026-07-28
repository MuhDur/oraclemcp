#!/usr/bin/env bash
# Keep dashboard skins presentation-only and keep retired heavyweight renderers out.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "dashboard-skin-lint: $*" >&2
  exit 1
}

if grep -RInE 'from ["'\'']\.\/operator-client["'\'']|from ["'\'']\.\.\/operator-client["'\'']' \
    web/src/app/skin.tsx web/src/app/orrery-renderer.tsx 2>/dev/null; then
  fail "skin modules must not import operator-client/business protocol code"
fi

if grep -RInE 'from ["'\''](three|@react-three/|gsap|leva)' web/src 2>/dev/null; then
  fail "retired 3D rendering dependencies must not be imported by the dashboard"
fi

if grep -InEi 'orrery3d|orreryrenderer|requireswebgl|webgluniforms|webgl' \
    web/src/app/skin.tsx web/src/app/presentation-model.ts \
    web/src/app/conformance.test.tsx web/src/app/orrery-renderer.tsx 2>/dev/null; then
  fail "retired 3D renderer wiring must not return to the dashboard contract"
fi

if grep -InE '"(@types/three|three)"' web/package.json web/package-lock.json 2>/dev/null; then
  fail "retired 3D rendering dependencies must not remain in package metadata"
fi

skin_contract="$({
  sed -n '/^export type DashboardSkin = {/,/^};$/p' web/src/app/skin.tsx
  sed -n '/^export const OMCP_SKIN: DashboardSkin = {/,/^};$/p' web/src/app/skin.tsx
})"

if grep -Eiq \
    'bigboard|groundcontrol|costbadge|fleetmap|vectorcluster|cqnchangefeed|columnlineage|scnscrubber|undotree' \
    <<<"$skin_contract"; then
  fail "the production skin contract must not register retired dashboard experiments"
fi

for renderer in VerdictProof MaskBadge PolicyBadge EditionTimeline; do
  if ! grep -Eq "^[[:space:]]+${renderer}:" <<<"$skin_contract"; then
    fail "the production skin contract must register ${renderer}"
  fi
done

if grep -InE 'REQUIRED_BIG_BOARD_RENDERERS|defaultBigBoard|bigBoardRenderers|useDashboardCapabilities|selectBigBoardRenderer|detectDashboardCapabilities' \
    web/src/app/skin.tsx web/src/app/conformance.test.tsx 2>/dev/null; then
  fail "retired big-board registry and capability wiring must not return"
fi

if grep -InE 'from ["'\''](react|lucide-react)|className=|#[0-9a-fA-F]{3,8}' \
    web/src/app/presentation-model.ts 2>/dev/null; then
  fail "presentation-model must stay semantic: no React, DOM classes, or color literals"
fi

echo "dashboard-skin-lint: OK"
