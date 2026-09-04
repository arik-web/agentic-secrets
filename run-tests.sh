#!/usr/bin/env bash
# Run the whole test suite against a throwaway home.
set -euo pipefail
cd "$(dirname "$0")"
exec "${SIL_PYTHON:-python3}" -m unittest discover -s tests -t tests -p "test_*.py" "$@"
