#!/usr/bin/env bash
set -euo pipefail
echo 'check-mutation-result: validator installed'
python3 scripts/check_mutation_result.py --help >/dev/null
