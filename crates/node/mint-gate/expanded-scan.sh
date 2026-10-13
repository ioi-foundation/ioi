#!/bin/bash
# Path: crates/node/mint-gate/expanded-scan.sh
# THE MINT GATE'S LAYER 2 (BUILD-DELTA #36; the Hypervisor Director's ruling "Batch-3 Codex r5 = FAIL" (2) and the IOI
# Director's amendment (3)): MINT FORMATS and RANDOMNESS PRIMITIVES over the EXPANDED production source. REQUIRED
# PRE-MERGE for any change touching the inventoried code or the gate, and recorded in the merge record next to the CI
# result of layer 1. For every pinned configuration (the gate's `--plan`), it runs ONE `cargo check` of the inventoried
# packages and the canary on the ALREADY-INSTALLED nightly-2026-08-08 (offline, --locked: nothing is installed or
# updated), with expand-wrapper.sh as RUSTC_WORKSPACE_WRAPPER, so every production target is expanded
# (`-Zunpretty=expanded`) under exactly the feature resolution layer 1 checks; then the gate (`--expanded`) scans the
# expansions and compares them with expanded-sites.tsv both ways, with the canary checks.
# It FAILS, never skips, when the network is not isolated, a toolchain is missing, a build or an expansion fails or is
# empty, a target is not expanded, or the subject's worktree changes. It deletes nothing.
# usage (under unshare -rn, from anywhere): expanded-scan.sh <subject worktree> <NEW out dir> [--print] [config ...]
#   (no config named = every pinned configuration; naming some makes the judge's run PARTIAL, never a pass)
#   optional: EXP_NIGHTLY_TARGET (the nightly target dir; default <worktree>/target/mint-gate-nightly, build products only)
# exit: 0 PASS; 1 FAIL (findings named); 3 CANNOT RUN.
set -u
WT=$1
OUT=$2
shift 2
PRINT=""
if [ "${1:-}" = "--print" ]; then PRINT="--print"; shift; fi
SUBSET="$*"
N=${EXP_NIGHTLY:-/home/heathledger/.rustup/toolchains/nightly-2026-08-08-x86_64-unknown-linux-gnu}
HERE="$WT/crates/node/mint-gate"
fail() { echo "EXPANDED-SCAN CANNOT RUN: $*"; echo "EXPANDED-SCAN EXIT 3"; exit 3; }
ifaces=$(tail -n +3 /proc/self/net/dev | cut -d: -f1 | tr -d ' ' | sort | tr '\n' ' ')
[ "$ifaces" = "lo " ] || fail "not network-isolated (interfaces: $ifaces): run under unshare -rn"
for b in "$N/bin/cargo" "$N/bin/rustc"; do [ -x "$b" ] || fail "missing $b (the pinned nightly must already be installed)"; done
[ -x "$HERE/expand-wrapper.sh" ] || [ -f "$HERE/expand-wrapper.sh" ] || fail "no expand-wrapper.sh in the subject"
[ -e "$OUT" ] && fail "the out dir $OUT exists: give a NEW one"
mkdir -p "$OUT/units" || fail "cannot create $OUT"
P0=$(git -C "$WT" status --porcelain | tr '\n' ' ')
echo "SUBJECT $(git -C "$WT" rev-parse HEAD) PORCELAIN [$P0]"
echo "TOOLCHAIN $("$N/bin/rustc" --version) | $("$N/bin/cargo" --version)"
echo "SHA256 $(sha256sum "$HERE/expanded-scan.sh" | cut -c1-64) expanded-scan.sh"
echo "SHA256 $(sha256sum "$HERE/expand-wrapper.sh" | cut -c1-64) expand-wrapper.sh"
# The configurations, from the gate's own pins (stable toolchain, the gate built from the subject).
( cd "$WT" && cargo run --locked -q -p ioi-node-mint-gate -- --plan ) > "$OUT/plan.txt" 2> "$OUT/plan.err" || fail "the gate's --plan failed: $(tail -3 "$OUT/plan.err" | tr '\n' ' ')"
grep -q '^PLAN ' "$OUT/plan.txt" || fail "the gate printed no plan: $(tail -5 "$OUT/plan.txt" | tr '\n' ' ')"
TARGET=${EXP_NIGHTLY_TARGET:-$WT/target/mint-gate-nightly}
configs=()
while read -r tag name args; do
  [ "$tag" = PLAN ] || continue
  if [ -n "$SUBSET" ] && ! printf ' %s ' "$SUBSET" | grep -q " $name "; then continue; fi
  configs+=("$name")
  start=$(date +%s)
  # shellcheck disable=SC2086
  ( cd "$WT" && env -i HOME="$HOME" XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}" CARGO_HOME="${CARGO_HOME:-/home/heathledger/.cargo}" \
      PATH="$N/bin:/usr/bin:/bin" RUSTC="$N/bin/rustc" RUSTC_WORKSPACE_WRAPPER="$HERE/expand-wrapper.sh" EXPAND_OUT="$OUT/units" \
      CARGO_TARGET_DIR="$TARGET" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 \
      "$N/bin/cargo" check --offline --locked --keep-going -p ioi-node -p ioi-services -p ioi-node-mint-gate-canary $args \
      --message-format=json ) > "$OUT/$name.json" 2> "$OUT/$name.err"
  rc=$?
  echo "EXPANDED $name: cargo check exit $rc in $(( $(date +%s) - start )) s; units now $(ls "$OUT/units" | grep -c '\.rs$')"
  [ "$rc" -eq 0 ] || fail "configuration $name: the expansion build failed: $(grep -v '^ *\(Checking\|Compiling\|Finished\|Blocking\)' "$OUT/$name.err" | tail -8 | tr '\n' ' ')"
done < "$OUT/plan.txt"
[ "${#configs[@]}" -gt 0 ] || fail "no configuration selected"
[ "$(git -C "$WT" status --porcelain | tr '\n' ' ')" = "$P0" ] || fail "the subject's worktree changed during the expansion"
for f in "$OUT"/units/*.rs; do echo "UNIT $(basename "$f") $(wc -l < "$f") lines sha256 $(sha256sum "$f" | cut -c1-64)"; done
judge=(--expanded "$OUT")
[ -n "$PRINT" ] && judge+=("$PRINT")
[ -n "$SUBSET" ] && judge+=(--configs "$(echo "${configs[@]}" | tr ' ' ',')")
( cd "$WT" && cargo run --locked -q -p ioi-node-mint-gate -- "${judge[@]}" )
rc=$?
echo "EXPANDED-SCAN EXIT $rc"
exit $rc
