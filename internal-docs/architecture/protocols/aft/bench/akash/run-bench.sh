#!/usr/bin/env bash
# Fail-closed RES-P4.3 campaign runner. A failed or partial matrix is retained
# as evidence, but is never labeled complete and is never silently re-run.
set -euo pipefail

WARMUPS="${AFT_BENCH_WARMUPS:-1}"
REPEATS="${AFT_BENCH_REPEATS:-5}"
SCENARIO="${IOI_AFT_BENCH_SCENARIO:-}"
OUTDIR="${AFT_BENCH_OUTDIR:-/output}"
CAMPAIGN="${AFT_BENCH_CAMPAIGN_ID:?AFT_BENCH_CAMPAIGN_ID is required}"
COMMIT="${IOI_BENCH_COMMIT:?IOI_BENCH_COMMIT is required}"
IMAGE_DIGEST="${IOI_BENCH_IMAGE_DIGEST:?IOI_BENCH_IMAGE_DIGEST is required}"
PROTOCOL_VERSION="${AFT_BENCH_PROTOCOL_VERSION:?AFT_BENCH_PROTOCOL_VERSION is required}"
TOOLS="${AFT_RESULT_TOOLS:-/usr/local/bin/aft-result-tools.py}"
RESULT_TLS_CERT="${AFT_RESULT_TLS_CERT:-/etc/ioi-aft-result/tls.crt}"
RESULT_TLS_KEY="${AFT_RESULT_TLS_KEY:-/etc/ioi-aft-result/tls.key}"

case "$WARMUPS:$REPEATS" in
  *[!0-9:]*|:*|*:) echo "warmups and repeats must be integers" >&2; exit 2 ;;
esac
if (( WARMUPS < 1 || REPEATS < 2 )); then
  echo "campaign requires at least one warmup and two measured passes" >&2
  exit 2
fi

mkdir -p "$OUTDIR"
if [[ ! -r "$RESULT_TLS_CERT" || ! -r "$RESULT_TLS_KEY" ]]; then
  echo "result TLS certificate and key must be readable before the campaign starts" >&2
  exit 2
fi

set_status() {
  "$TOOLS" status --output "$OUTDIR/status.json" --campaign "$CAMPAIGN" --state "$1" --detail "$2"
}

bench_cmd() {
  cargo test --release \
    -p ioi-cli \
    --features consensus-aft,vm-wasm,state-jellyfish \
    -- --ignored --nocapture test_aft_paper_benchmark_matrix
}

run_campaign() (
  set -euo pipefail
  set_status starting "capturing environment manifest"
  "$TOOLS" environment \
    --output "$OUTDIR/environment.json" \
    --campaign "$CAMPAIGN" \
    --commit "$COMMIT" \
    --image-digest "$IMAGE_DIGEST" \
    --protocol-version "$PROTOCOL_VERSION" \
    --scenario "$SCENARIO" \
    --warmups "$WARMUPS" \
    --repeats "$REPEATS"

  for (( warmup = 1; warmup <= WARMUPS; warmup++ )); do
    set_status warmup "warmup $warmup of $WARMUPS"
    bench_cmd >"$OUTDIR/warmup-${warmup}.raw" 2>&1
  done

  for (( pass = 1; pass <= REPEATS; pass++ )); do
    set_status measuring "measured pass $pass of $REPEATS"
    bench_cmd >"$OUTDIR/run-${pass}.raw" 2>&1
    "$TOOLS" collect \
      --input "$OUTDIR/run-${pass}.raw" \
      --output "$OUTDIR/run-${pass}.json" \
      --campaign "$CAMPAIGN" \
      --pass-number "$pass" \
      --scenario "$SCENARIO"
  done

  (
    cd "$OUTDIR"
    "$TOOLS" aggregate \
      --inputs 'run-*.json' \
      --repeats "$REPEATS" \
      --campaign "$CAMPAIGN" \
      --output-json result.json \
      --output-markdown result.md
  )
  "$TOOLS" scan --directory "$OUTDIR" --canaries "${IOI_SECRET_CANARIES:-}"
  "$TOOLS" manifest --directory "$OUTDIR"
  set_status complete "all measured passes validated and aggregated"
)

set_status starting "campaign has not crossed the benchmark boundary"

# Bring the authenticated evidence channel up before the paid benchmark starts.
# `/results` remains fail-closed until status reaches `complete`, while `/status`
# and `/environment` make a slow or failed run distinguishable from an absent
# container. Keeping the same server process alive across the campaign also
# prevents a completed result from depending on a late bind to the ingress port.
"$TOOLS" serve \
  --directory "$OUTDIR" \
  --port "${AFT_RESULT_PORT:-8080}" \
  --tls-cert "$RESULT_TLS_CERT" \
  --tls-key "$RESULT_TLS_KEY" &
RESULT_SERVER_PID=$!
cleanup_result_server() {
  kill "$RESULT_SERVER_PID" 2>/dev/null || true
  wait "$RESULT_SERVER_PID" 2>/dev/null || true
}
trap cleanup_result_server EXIT INT TERM
sleep 1
if ! kill -0 "$RESULT_SERVER_PID" 2>/dev/null; then
  wait "$RESULT_SERVER_PID"
fi

set +e
run_campaign
code=$?
set -e
if (( code == 0 )); then
  echo "AFT campaign $CAMPAIGN completed and validated"
else
  set_status failed "campaign failed closed with exit code $code"
  "$TOOLS" manifest --directory "$OUTDIR" || true
  echo "AFT campaign $CAMPAIGN failed closed; evidence remains retrievable" >&2
fi

# Never exit after the paid workload starts: Akash may restart an exited
# service and accidentally repeat a spend-bearing benchmark campaign. The
# already-running server keeps both successful and failed evidence available.
wait "$RESULT_SERVER_PID"
