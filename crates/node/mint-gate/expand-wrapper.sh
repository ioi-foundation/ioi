#!/bin/bash
# Path: crates/node/mint-gate/expand-wrapper.sh
# THE MINT GATE'S EXPANSION WRAPPER (BUILD-DELTA #36, layer 2), set as RUSTC_WORKSPACE_WRAPPER by expanded-scan.sh. Cargo
# calls it as `<this> <rustc> <args...>` for every workspace unit of the build. For each unit of an inventoried package
# (ioi-node, ioi-services, the canary), build scripts excepted, it first runs the SAME rustc invocation with
# `-Zunpretty=expanded` and writes the expansion to $EXPAND_OUT/<crate><extra-filename>.rs (the unit's own hashed name,
# so a configuration that reuses a unit reuses its expansion), then runs the normal invocation. A failed or empty
# expansion fails the unit (exit 97), so the build fails and the scan cannot pass. The inventoried units are compiled with
# `--cap-lints warn` (an in-source deny cannot abort the scan). It deletes nothing.
set -u
rustc=$1
shift
case "${CARGO_PKG_NAME:-}" in
  ioi-node | ioi-services | ioi-node-mint-gate-canary)
    if [ "${CARGO_CRATE_NAME:-}" != "build_script_build" ]; then
      extra=""
      previous=""
      for arg in "$@"; do
        case "$previous|$arg" in
          "-C|extra-filename="*) extra=${arg#extra-filename=} ;;
        esac
        case "$arg" in
          -Cextra-filename=*) extra=${arg#-Cextra-filename=} ;;
        esac
        previous=$arg
      done
      [ -n "${EXPAND_OUT:-}" ] || { echo "expand-wrapper: EXPAND_OUT is not set" >&2; exit 97; }
      out="$EXPAND_OUT/${CARGO_CRATE_NAME}${extra}.rs"
      "$rustc" "$@" --cap-lints warn -Zunpretty=expanded > "$out.partial" 2> "$out.err" || {
        echo "expand-wrapper: the expansion of $CARGO_PKG_NAME/$CARGO_CRATE_NAME failed: $(tail -3 "$out.err" | tr '\n' ' ')" >&2
        exit 97
      }
      [ -s "$out.partial" ] || { echo "expand-wrapper: the expansion of $CARGO_PKG_NAME/$CARGO_CRATE_NAME is EMPTY" >&2; exit 97; }
      mv "$out.partial" "$out"
      exec "$rustc" "$@" --cap-lints warn
    fi
    ;;
esac
exec "$rustc" "$@"
