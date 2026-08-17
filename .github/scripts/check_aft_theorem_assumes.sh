#!/usr/bin/env bash
# AFT-CB P1.2 gate: the theorem corpus's machine-checkable Assumes convention.
#
# Over internal-docs/architecture/protocols/aft/specs/common_boundary_theorems.md:
#   1. every theorem block (## T* / ## L*) carries exactly one `Assumes:` line;
#   2. that line's assumption tokens are only A1..A10 (or the literal `none`);
#   3. A5 appears on no Assumes line outside T4a/T4b (no safety theorem may
#      consume synchrony);
#   4. A9 appears on no Assumes line outside T5b (the A6-iv hardening) and
#      T5d; A10 (succession-medium observation) outside T5d nowhere at all;
#   5. T8 is stated as a probability, carries its adversary-budget,
#      constituency-correlation, adaptive-corruption, and standby-capture
#      model, and the token T8 appears in no other theorem block;
#   6. the lower-bound pairing table exists and every positive-theorem row is
#      either a citation or a named L-OPEN;
#   7. T1's block contains no timing vocabulary (denylist: GST, the Delta
#      symbol, synchrony).
#
# Mutation-tested per AFT-CB standing rule 3 (e.g. adding A5 to T1's Assumes
# line must turn this gate RED).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOC="$ROOT/internal-docs/architecture/protocols/aft/specs/common_boundary_theorems.md"
fail=0

err() { echo "FAIL: $1"; fail=1; }

[[ -f "$DOC" ]] || { echo "FAIL: missing $DOC"; exit 1; }

# Split the doc into blocks keyed by theorem id. A block runs from its
# "## <id> " heading to the next "## " heading. Ids: T1, T2, T3, T4a, T4b,
# T5a, T5b, T5c′, T5d, T6, T7, T8, T9, L1, L2, L9, L-E, L-H, L-LR, L-M.
mapfile -t ids < <(grep -oP '^## \K(T[0-9]+[a-z]?['"'"'′]?|L-?[A-Z0-9]+)(?= —)' "$DOC")

REQUIRED_IDS=(T1 T2 T3 T4a T4b T5a T5b "T5c′" T5d T6 T7 T8 T9 L1 L2 L9)
for want in "${REQUIRED_IDS[@]}"; do
  found=0
  for id in "${ids[@]}"; do [[ "$id" == "$want" ]] && found=1; done
  [[ $found -eq 1 ]] || err "theorem block $want missing"
done

block_of() { # $1 = id → block text
  awk -v id="$1" '
    $0 ~ "^## " { inb = ($0 ~ ("^## " id " —")) ? 1 : 0 }
    inb { print }
  ' "$DOC"
}

A5_ALLOWED=" T4a T4b "
A9_ALLOWED=" T5b T5d "
A10_ALLOWED=" T5d "

for id in "${ids[@]}"; do
  block="$(block_of "$id")"
  n_assumes=$(grep -c '^Assumes:' <<<"$block" || true)
  if [[ "$n_assumes" -ne 1 ]]; then
    err "$id: expected exactly one Assumes: line, found $n_assumes"
    continue
  fi
  line="$(grep '^Assumes:' <<<"$block")"
  # tokens: every A<digits> on the line must be A1..A10; 'none' is permitted
  while read -r tok; do
    [[ "$tok" =~ ^A([1-9]|10)$ ]] || err "$id: Assumes token '$tok' outside A1..A10"
  done < <(grep -oE 'A[0-9]+' <<<"$line" || true)
  if ! grep -qE '^Assumes: (none|A[1-9])' <<<"$line"; then
    err "$id: Assumes line must start with a ledger token or 'none'"
  fi
  if grep -qE '\bA5\b' <<<"$line" && [[ "$A5_ALLOWED" != *" $id "* ]]; then
    err "$id: cites A5 — synchrony is barred outside T4a/T4b"
  fi
  if grep -qE '\bA9\b' <<<"$line" && [[ "$A9_ALLOWED" != *" $id "* ]]; then
    err "$id: cites A9 — the physical clock is barred outside T5b (A6-iv) and T5d"
  fi
  if grep -qE '\bA10\b' <<<"$line" && [[ "$A10_ALLOWED" != *" $id "* ]]; then
    err "$id: cites A10 — the succession-medium observation bound is barred outside T5d"
  fi
  # T8 must not leak into deterministic theorem blocks
  if [[ "$id" != "T8" ]] && grep -qE '\bT8\b' <<<"$block"; then
    err "$id: references T8 — the selection probability may not appear in a deterministic theorem"
  fi
done

# T8's own obligations
t8="$(block_of T8)"
grep -qi 'probability' <<<"$t8" || err "T8: not stated as a probability"
grep -qi 'adversary budget' <<<"$t8" || err "T8: adversary-budget model missing"
grep -qi 'correlation' <<<"$t8" || err "T8: constituency-correlation model missing"
grep -qi 'adaptive' <<<"$t8" || err "T8: adaptive-corruption term missing"
grep -qi 'standby' <<<"$t8" || err "T8: standby-capture term missing"
grep -qiE 'tolerance figure|never.*deterministic|deterministic.*(never|forbidden)' <<<"$t8" \
  || err "T8: must state the no-deterministic-conversion rule"

# T1 timing denylist
t1="$(block_of T1)"
for word in GST Δ synchrony; do
  if grep -q "$word" <<<"$t1"; then err "T1: timing vocabulary '$word' present"; fi
done

# Pairing table: exists, and every positive-theorem row is cited or L-OPEN
table=$(awk '/^## Lower-bound pairing table/,0' "$DOC")
[[ -n "$table" ]] || err "lower-bound pairing table missing"
rows=$(grep -cE '^\| T[0-9]' <<<"$table" || true)
[[ "$rows" -ge 13 ]] || err "pairing table: expected >=13 positive-theorem rows, found $rows"
while IFS= read -r row; do
  if ! grep -qE 'cited|L-OPEN' <<<"$row"; then
    err "pairing row neither cites a bound nor records L-OPEN: ${row:0:60}"
  fi
done < <(grep -E '^\| T[0-9]' <<<"$table")

if [[ $fail -ne 0 ]]; then
  echo "check_aft_theorem_assumes: FAILED"
  exit 1
fi
echo "theorem convention OK: ${#ids[@]} blocks; Assumes discipline (A5->T4a/T4b only, A9->T5b/T5d only, A10->T5d only), T8 probabilistic + quarantined, T1 timing-free, pairing table complete"
