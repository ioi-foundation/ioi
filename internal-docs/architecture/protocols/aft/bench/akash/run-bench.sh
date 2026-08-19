#!/usr/bin/env bash
# AFT paper-benchmark runner entrypoint (RES-P4.3, Stage 1).
#
# Prints an environment manifest, runs AFT_BENCH_WARMUPS discarded warmups,
# then AFT_BENCH_REPEATS measured passes of the AFT paper-benchmark matrix.
# Each pass is wrapped in ===AFT-BENCH RUN k/N=== markers so the Markdown
# tables can be split for variance analysis. After the passes it sleeps so the
# Akash lease stays up for log retrieval — CLOSE THE LEASE MANUALLY when done.
#
# Retrieval: the results are on stdout (provider lease-logs). If /output is a
# mounted volume, each pass is also written there.
set -uo pipefail

WARMUPS="${AFT_BENCH_WARMUPS:-1}"
REPEATS="${AFT_BENCH_REPEATS:-5}"
SCENARIO="${IOI_AFT_BENCH_SCENARIO:-}"   # empty = full matrix (4v+7v, both families)
OUTDIR="${AFT_BENCH_OUTDIR:-/output}"
mkdir -p "$OUTDIR" 2>/dev/null || true

bench_cmd() {
  cargo test --release \
    -p ioi-cli \
    --features consensus-aft,vm-wasm,state-jellyfish \
    -- --ignored --nocapture test_aft_paper_benchmark_matrix
}

echo "===AFT-BENCH ENVIRONMENT MANIFEST==="
echo "source_commit: ${IOI_BENCH_COMMIT:-unknown}"
echo "scenario_filter: ${SCENARIO:-<full-matrix>}"
echo "warmups: ${WARMUPS}   repeats: ${REPEATS}"
echo "cpu_model: $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ //')"
echo "cpu_cores_online: $(nproc 2>/dev/null)"
echo "mem_total: $(awk '/MemTotal/{print $2 $3}' /proc/meminfo 2>/dev/null)"
echo "kernel: $(uname -r 2>/dev/null)   (NOTE: provider host kernel, not ours)"
echo "rustc: $(rustc --version 2>/dev/null)"
echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
echo "===END MANIFEST==="

for w in $(seq 1 "${WARMUPS}"); do
  echo "===AFT-BENCH WARMUP ${w}/${WARMUPS} (discarded)==="
  bench_cmd >/dev/null 2>&1 || echo "warmup ${w} exited non-zero (continuing)"
done

for k in $(seq 1 "${REPEATS}"); do
  echo "===AFT-BENCH RUN ${k}/${REPEATS} BEGIN==="
  if [ -w "$OUTDIR" ]; then
    bench_cmd 2>&1 | tee "${OUTDIR}/run-${k}.md"
  else
    bench_cmd 2>&1
  fi
  echo "===AFT-BENCH RUN ${k}/${REPEATS} END==="
done

echo "===AFT-BENCH ALL RUNS COMPLETE — lease idle, CLOSE IT MANUALLY==="
# Keep the container alive so `lease-logs` and any mounted /output remain
# retrievable. Akash treats an exited service as crashed and restarts it,
# which would re-run the whole matrix and bill for it — so we hold here.
sleep infinity
