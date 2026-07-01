#!/usr/bin/env bash
# Keep dashboard skins as presentation-only modules and quarantine heavy 3D deps.
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

if grep -RInE 'from ["'\''](three|@react-three/|gsap|leva)' web/src 2>/dev/null |
    grep -v 'web/src/app/orrery-renderer.tsx'; then
  fail "three/r3f/gsap/leva imports are only allowed inside the Orrery renderer boundary"
fi

if grep -InE 'from ["'\''](react|lucide-react)|className=|#[0-9a-fA-F]{3,8}' \
    web/src/app/presentation-model.ts 2>/dev/null; then
  fail "presentation-model must stay semantic: no React, DOM classes, or color literals"
fi

echo "dashboard-skin-lint: OK"
