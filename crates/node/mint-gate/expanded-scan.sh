#!/bin/bash
# Path: crates/node/mint-gate/expanded-scan.sh
# THE MINT GATE'S LAYER 2 (BUILD-DELTA #36; the Hypervisor Director's ruling "Batch-3 Codex r5 = FAIL" (2) and the IOI
# Director's amendment (3)): MINT FORMATS and RANDOMNESS PRIMITIVES over the EXPANDED production source. REQUIRED
# PRE-MERGE for any change touching the inventoried code or the gate, and recorded in the merge record next to the CI
# result of layer 1. For every pinned configuration (the gate's `--plan`), it runs ONE `cargo check` of the inventoried
# packages and the canary on the SAME pinned stable toolchain as layer 1 (1.93.1, already installed; offline, --locked:
# nothing is installed or updated), with expand-wrapper.sh as RUSTC_WORKSPACE_WRAPPER, so every production target is
# expanded
# (`-Zunpretty=expanded`) under exactly the feature resolution layer 1 checks; then the gate (`--expanded`) scans the
# NAMED EXCEPTION (HYP ruling 2026-10-13 19:58 (1), with the IOI Director's concurrence): `-Zunpretty=expanded` is an
# unstable flag, so expand-wrapper.sh sets RUSTC_BOOTSTRAP=1 on the EXPANSION invocation only (it prints source and
# compiles nothing); every build invocation, dependencies and build scripts included, runs WITHOUT it (the wrapper
# unsets it, and this script's build environment never has it). The gate does not depend on a nightly toolchain:
# one compiler serves both layers (the pinned nightly-2026-08-08 could not compile rustix: ticket b3r-t1b).
# expansions and compares them with expanded-sites.tsv both ways, with the canary checks.
# It FAILS, never skips, when the network is not isolated, a toolchain is missing, a build or an expansion fails or is
# empty, a target is not expanded, or the subject's worktree changes. It deletes nothing.
# usage (under unshare -rn, from anywhere): expanded-scan.sh <subject worktree> <NEW out dir> [--print] [config ...]
#   (no config named = every pinned configuration; naming some makes the judge's run PARTIAL, never a pass)
#        or: expanded-scan.sh --preflight <subject worktree>   (the input, argument, network, wrapper and workspace
#   checks below, then exit 0 with "EXPANDED-SCAN PREFLIGHT OK: checked: ..." naming each check it made and what it did
#   NOT check; it builds nothing and creates no out dir. It does not check that the registry holds every locked
#   dependency, the gate's build (--plan), the expansion build or the out dir, so a passing preflight does not show
#   that layer 2 runs)
#   A missing positional argument is refused BY NAME (exit 3).
#   REQUIRED, from the CALLER (no fallback; each is refused BY NAME, exit 3, when unset, empty or invalid):
#   EXP_TOOLCHAIN, the absolute directory of the pinned 1.93.1 toolchain (holding executable bin/cargo and bin/rustc,
#   its rustc 1.93.1), and CARGO_HOME, the absolute cargo home holding the offline registry (an index under
#   registry/index with a non-empty .cache, and .crate files in registry/cache). The caller resolves both from its
#   own environment or rustup BEFORE it replaces HOME, e.g.
#     EXP_TOOLCHAIN="$(rustup run 1.93.1 rustc --print sysroot)" CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
#   Every cargo and rustc this script runs is EXP_TOOLCHAIN's, so the scan needs no rustup home and runs under a fresh
#   HOME (the Hypervisor Director's ruling "BATCH 3 SHIPS THIS HOST'S HOME PATH": no host path is a fallback).
#   optional: EXP_TARGET (the expansion build's target dir; default <worktree>/target/mint-gate-expand, build products only)
# exit: 0 PASS (or PREFLIGHT OK); 1 FAIL (findings named); 3 CANNOT RUN (every refused input or argument, by name).
set -u
fail() { echo "EXPANDED-SCAN CANNOT RUN: $*"; echo "EXPANDED-SCAN EXIT 3"; exit 3; }
USAGE="usage: expanded-scan.sh <subject worktree> <NEW out dir> [--print] [config ...], or expanded-scan.sh --preflight <subject worktree>"
[ -n "${EXP_TOOLCHAIN:-}" ] || fail "EXP_TOOLCHAIN is not set: pass the pinned 1.93.1 toolchain's directory, resolved before HOME is replaced (e.g. EXP_TOOLCHAIN=\"\$(rustup run 1.93.1 rustc --print sysroot)\"); there is no fallback"
[ -n "${CARGO_HOME:-}" ] || fail "CARGO_HOME is not set: pass the cargo home holding the offline registry, resolved before HOME is replaced; there is no fallback"
PREFLIGHT=""
if [ "${1:-}" = "--preflight" ]; then PREFLIGHT=1; shift; fi
{ [ "$#" -ge 1 ] && [ -n "$1" ]; } || fail "the <subject worktree> argument is missing ($USAGE)"
WT=$1
shift
if [ -n "$PREFLIGHT" ]; then
  [ "$#" -eq 0 ] || fail "--preflight takes only the <subject worktree> argument ($USAGE)"
  OUT=""
else
  { [ "$#" -ge 1 ] && [ -n "$1" ]; } || fail "the <NEW out dir> argument is missing ($USAGE)"
  OUT=$1
  shift
fi
[ -d "$WT" ] || fail "the <subject worktree> argument is not a directory: $WT"
PRINT=""
if [ "${1:-}" = "--print" ]; then PRINT="--print"; shift; fi
SUBSET="$*"
N=$EXP_TOOLCHAIN
case "$N" in /*) ;; *) fail "EXP_TOOLCHAIN=$N is not an absolute path: pass the toolchain's absolute directory" ;; esac
[ -d "$N" ] || fail "EXP_TOOLCHAIN=$N is not a directory"
for b in cargo rustc; do
  { [ -f "$N/bin/$b" ] && [ -x "$N/bin/$b" ]; } || fail "EXP_TOOLCHAIN=$N has no executable bin/$b (EXP_TOOLCHAIN must be the pinned 1.93.1, already installed)"
done
NV=$("$N/bin/rustc" --version 2>&1 | head -1)
case "$NV" in "rustc 1.93.1 "*) ;; *) fail "EXP_TOOLCHAIN=$N is not the pinned 1.93.1: its bin/rustc --version says [$NV]" ;; esac
case "$CARGO_HOME" in /*) ;; *) fail "CARGO_HOME=$CARGO_HOME is not an absolute path: pass the cargo home's absolute directory" ;; esac
[ -d "$CARGO_HOME" ] || fail "CARGO_HOME=$CARGO_HOME is not a directory"
IDX=""
for d in "$CARGO_HOME"/registry/index/*/.cache; do
  if [ -d "$d" ] && [ -n "$(ls -A "$d" 2> /dev/null)" ]; then IDX=${d%/.cache}; break; fi
done
[ -n "$IDX" ] || fail "CARGO_HOME=$CARGO_HOME holds no offline registry: no index under registry/index has a non-empty .cache"
NCRATES=$(find "$CARGO_HOME/registry/cache" -mindepth 2 -maxdepth 2 -name '*.crate' 2> /dev/null | wc -l)
[ "$NCRATES" -ge 1 ] || fail "CARGO_HOME=$CARGO_HOME holds no offline registry: registry/cache holds no .crate file"
HERE="$WT/crates/node/mint-gate"
ifaces=$(tail -n +3 /proc/self/net/dev | cut -d: -f1 | tr -d ' ' | sort | tr '\n' ' ')
[ "$ifaces" = "lo " ] || fail "not network-isolated (interfaces: $ifaces): run under unshare -rn"
[ -x "$HERE/expand-wrapper.sh" ] || [ -f "$HERE/expand-wrapper.sh" ] || fail "no expand-wrapper.sh in the subject"
# The root of every lib and bin target of the inventoried packages (see the re-expansion note below), read by
# EXP_TOOLCHAIN's cargo, offline and locked, with only HOME, CARGO_HOME and the toolchain in its environment.
roots() {
  ( cd "$WT" && env -i HOME="$HOME" CARGO_HOME="$CARGO_HOME" PATH="$N/bin:/usr/bin:/bin" RUSTC="$N/bin/rustc" CARGO_NET_OFFLINE=true \
      "$N/bin/cargo" metadata --no-deps --offline --locked --format-version 1 ) | python3 -I -c 'import json, sys; m = json.load(sys.stdin); P = {"ioi-node", "ioi-services", "ioi-node-mint-gate-canary"}; print("\n".join(t["src_path"] for p in m["packages"] if p["name"] in P for t in p["targets"] if set(t["kind"]) & {"bin", "lib", "rlib"}))'
}
if [ -n "$PREFLIGHT" ]; then
  ROOTS=$(set -o pipefail; roots 2> /dev/null) || fail "EXP_TOOLCHAIN's cargo cannot read the subject's workspace offline under HOME=$HOME: $(roots 2>&1 > /dev/null | tail -3 | tr '\n' ' ')"
  n=$(printf '%s\n' "$ROOTS" | grep -c .)
  [ "$n" -ge 3 ] || fail "too few inventoried target roots: [$ROOTS]"
  echo "EXPANDED-SCAN PREFLIGHT OK: checked: EXP_TOOLCHAIN=$N has executable bin/cargo and bin/rustc and its rustc is the pinned 1.93.1 ($NV); CARGO_HOME=$CARGO_HOME has an index with a non-empty .cache (${IDX#"$CARGO_HOME"/}) and $NCRATES .crate files in registry/cache; the network has only lo; the subject has expand-wrapper.sh; EXP_TOOLCHAIN's cargo read the subject's workspace offline and locked (metadata only, no dependency resolved) under HOME=$HOME: $n inventoried target roots. NOT checked: that the registry holds every locked dependency, the gate's build (--plan), the expansion build, the out dir"
  exit 0
fi
[ -e "$OUT" ] && fail "the out dir $OUT exists: give a NEW one"
mkdir -p "$OUT/units" || fail "cannot create $OUT"
P0=$(git -C "$WT" status --porcelain | tr '\n' ' ')
echo "SUBJECT $(git -C "$WT" rev-parse HEAD) PORCELAIN [$P0]"
echo "TOOLCHAIN $("$N/bin/rustc" --version) | $("$N/bin/cargo" --version)"
echo "SHA256 $(sha256sum "$HERE/expanded-scan.sh" | cut -c1-64) expanded-scan.sh"
echo "SHA256 $(sha256sum "$HERE/expand-wrapper.sh" | cut -c1-64) expand-wrapper.sh"
# The configurations, from the gate's own pins (EXP_TOOLCHAIN's cargo, offline; the gate built from the subject).
gate() {
  ( cd "$WT" && env PATH="$N/bin:$PATH" RUSTC="$N/bin/rustc" CARGO_NET_OFFLINE=true "$N/bin/cargo" run --locked -q -p ioi-node-mint-gate -- "$@" )
}
gate --plan > "$OUT/plan.txt" 2> "$OUT/plan.err" || fail "the gate's --plan failed: $(tail -3 "$OUT/plan.err" | tr '\n' ' ')"
grep -q '^PLAN ' "$OUT/plan.txt" || fail "the gate printed no plan: $(tail -5 "$OUT/plan.txt" | tr '\n' ' ')"
TARGET=${EXP_TARGET:-$WT/target/mint-gate-expand}
# EVERY INVENTORIED UNIT IS RE-EXPANDED IN EVERY RUN (ticket b3r-t2: cargo does not re-run a FRESH unit, so a second
# scan over the same target dir found no expansion for it and could not run). Before each configuration's build, the
# root of every lib and bin target of the inventoried packages is touched (mtime only: the content and git status do
# not change), so cargo re-runs every inventoried unit and the wrapper re-expands it into THIS run's out dir; after
# the build, an inventoried unit cargo still reports fresh is CANNOT RUN, by name. No cached expansion is ever judged.
ROOTS=$(set -o pipefail; roots 2> "$OUT/metadata.err") || fail "cannot list the inventoried target roots: $(tail -3 "$OUT/metadata.err" | tr '\n' ' ')"
[ "$(printf '%s\n' "$ROOTS" | grep -c .)" -ge 3 ] || fail "too few inventoried target roots: [$ROOTS]"
configs=()
while read -r tag name args; do
  [ "$tag" = PLAN ] || continue
  if [ -n "$SUBSET" ] && ! printf ' %s ' "$SUBSET" | grep -q " $name "; then continue; fi
  configs+=("$name")
  printf '%s\n' "$ROOTS" | while IFS= read -r root; do touch -c -- "$root" || exit 1; done || fail "cannot touch the inventoried target roots"
  start=$(date +%s)
  # shellcheck disable=SC2086
  ( cd "$WT" && env -i HOME="$HOME" XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}" CARGO_HOME="$CARGO_HOME" \
      PATH="$N/bin:/usr/bin:/bin" RUSTC="$N/bin/rustc" RUSTC_WORKSPACE_WRAPPER="$HERE/expand-wrapper.sh" EXPAND_OUT="$OUT/units" \
      CARGO_TARGET_DIR="$TARGET" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 \
      "$N/bin/cargo" check --offline --locked --keep-going -p ioi-node -p ioi-services -p ioi-node-mint-gate-canary $args \
      --message-format=json ) > "$OUT/$name.json" 2> "$OUT/$name.err"
  rc=$?
  echo "EXPANDED $name: cargo check exit $rc in $(( $(date +%s) - start )) s; units now $(ls "$OUT/units" | grep -c '\.rs$')"
  [ "$rc" -eq 0 ] || fail "configuration $name: the expansion build failed: $(grep -v '^ *\(Checking\|Compiling\|Finished\|Blocking\)' "$OUT/$name.err" | tail -8 | tr '\n' ' ')"
  fresh=$(python3 -I -c 'import json, sys
bad = []
for line in open(sys.argv[1]):
    try:
        d = json.loads(line)
    except ValueError:
        continue
    if d.get("reason") != "compiler-artifact" or "custom-build" in d["target"]["kind"]:
        continue
    if d.get("manifest_path", "").endswith(("/crates/node/Cargo.toml", "/crates/services/Cargo.toml", "/crates/node/mint-gate/canary/Cargo.toml")) and d.get("fresh"):
        bad.append(d["target"]["name"])
print(" ".join(bad))' "$OUT/$name.json") || fail "configuration $name: cannot read its build messages"
  [ -z "$fresh" ] || fail "configuration $name: inventoried units were not re-run (fresh), so not re-expanded in this run: $fresh"
done < "$OUT/plan.txt"
[ "${#configs[@]}" -gt 0 ] || fail "no configuration selected"
[ "$(git -C "$WT" status --porcelain | tr '\n' ' ')" = "$P0" ] || fail "the subject's worktree changed during the expansion"
for f in "$OUT"/units/*.rs; do echo "UNIT $(basename "$f") $(wc -l < "$f") lines sha256 $(sha256sum "$f" | cut -c1-64)"; done
judge=(--expanded "$OUT")
[ -n "$PRINT" ] && judge+=("$PRINT")
[ -n "$SUBSET" ] && judge+=(--configs "$(echo "${configs[@]}" | tr ' ' ',')")
gate "${judge[@]}"
rc=$?
echo "EXPANDED-SCAN EXIT $rc"
exit $rc
