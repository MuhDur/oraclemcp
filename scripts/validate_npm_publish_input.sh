#!/usr/bin/env bash
set -euo pipefail

version="${REQUESTED_VERSION:-}"
auth_mode="${REQUESTED_AUTH_MODE:-auto}"

# SemVer 2.0.0, without a leading `v`. Numeric core identifiers may not have
# leading zeroes; prerelease/build identifiers are deliberately restricted to
# the ASCII grammar that is valid in both Git tags and npm versions.
core='(0|[1-9][0-9]*)'
identifier='[0-9A-Za-z-]+'
semver="^${core}\\.${core}\\.${core}(-${identifier}(\\.${identifier})*)?(\\+${identifier}(\\.${identifier})*)?$"
if [[ ! "$version" =~ $semver ]]; then
  printf 'invalid npm publish version: expected SemVer without leading v\n' >&2
  exit 2
fi

without_build="${version%%+*}"
if [[ "$without_build" == *-* ]]; then
  prerelease="${without_build#*-}"
  IFS='.' read -r -a prerelease_identifiers <<<"$prerelease"
  for identifier_part in "${prerelease_identifiers[@]}"; do
    if [[ "$identifier_part" =~ ^[0-9]+$ && "$identifier_part" != "0" && "$identifier_part" == 0* ]]; then
      printf 'invalid npm publish version: numeric prerelease identifier has a leading zero\n' >&2
      exit 2
    fi
  done
fi

case "$auth_mode" in
  auto | token | oidc) ;;
  *)
    printf 'invalid npm publish auth mode\n' >&2
    exit 2
    ;;
esac

dist_tag=latest
if [[ "$without_build" == *-* ]]; then
  dist_tag=next
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    printf 'version=%s\n' "$version"
    printf 'tag=v%s\n' "$version"
    printf 'dist_tag=%s\n' "$dist_tag"
    printf 'auth_mode=%s\n' "$auth_mode"
  } >>"$GITHUB_OUTPUT"
else
  printf 'version=%s\ntag=v%s\ndist_tag=%s\nauth_mode=%s\n' \
    "$version" "$version" "$dist_tag" "$auth_mode"
fi
