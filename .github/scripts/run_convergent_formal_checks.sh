#!/usr/bin/env bash
set -euo pipefail

# Compatibility entrypoint retained for the Convergent Formal Checks workflow.
# The current AFT formal proof/model harness lives in run_aft_formal_checks.sh.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${SCRIPT_DIR}/run_aft_formal_checks.sh"
