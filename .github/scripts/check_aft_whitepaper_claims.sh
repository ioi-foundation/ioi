#!/usr/bin/env bash
set -euo pipefail

# AFT-CB P0.1 gate: the whitepaper's AFT section (§5.3) must carry the
# A1–A10 assumption ledger (A10 added by the P1.3 round-1 reopen), the
# interim conditional claim, and no rounded percentage tolerance claim.
# Fails the build otherwise.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WHITEPAPER="${ROOT_DIR}/docs/architecture/whitepaper.tex"

python3 - "$WHITEPAPER" <<'PY'
import re
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8").read()

start = text.find("aft-challenge-dominant-settlement-finality")
if start == -1:
    print("CLAIMS FAIL: AFT section anchor not found", file=sys.stderr)
    sys.exit(1)
# Section runs to the next \subsection at the same level (5.4/6.x) or EOF.
tail = text[start:]
next_sub = re.search(r"\\subsection\{(?!5\.3)", tail[1:])
section = tail[: next_sub.start() + 1] if next_sub else tail

errors = []

for i in range(1, 11):
    if not re.search(r"\\textbf\{A%d\}" % i, section):
        errors.append(f"assumption ledger row A{i} missing")

interim = (
    "Conditional weight-independent deterministic finality over a\n"
    "common-publication substrate, with bounded-resource liveness and\n"
    "genesis-relative succinct verification."
)
if interim not in section:
    errors.append("interim conditional claim (verbatim) missing")

for pattern, label in [
    (r"9[0-9](?:\.[0-9]+)?\s*(?:\\%|percent)", "rounded percentage tolerance figure"),
]:
    match = re.search(pattern, section)
    if match:
        errors.append(f"{label} present: {match.group(0)!r}")

if "Minimal Honesty Axiom" not in section:
    errors.append("MHA definition missing")

if errors:
    print("CLAIMS FAIL:", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    sys.exit(1)

print(f"claims OK: A1–A10 ledger + interim claim present; no rounded tolerance figures ({len(section)} chars scanned)")
PY
