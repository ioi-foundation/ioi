#!/usr/bin/env node
// Done-bar: agentgres-substrate engine v0 + bench harness.
// Proves: unit battery (determinism, conflict refusal, recovery replay, fork
// isolation, group commit), then a small fsync-honest bench run whose report
// must carry the three doctrine performance metrics with sane values.
// Doctrine: docs/architecture/components/agentgres/doctrine.md
// (Substrate Contract Doctrine — performance contract).

import { spawn, spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const repo = new URL("../../..", import.meta.url).pathname;
let pass = 0, fail = 0;
const check = (name, ok, detail = "") => {
  const mark = ok ? "PASS" : "FAIL";
  console.log(`${mark} ${name}${detail ? ` — ${detail}` : ""}`);
  ok ? pass++ : fail++;
};

// 1) Unit battery (14 tests: determinism, refusal, recovery, fork, writer,
//    mux interleaving-independence, mux recovery, mux concurrent combining,
//    mux domain fork isolation, mux domain projection, torn-tail WAL
//    truncation, writer-served projection, replicated-ack durability
//    upgrade + replica root match, durability base labels).
const test = spawnSync("cargo", ["test", "-p", "agentgres", "--release"], {
  cwd: repo, encoding: "utf8",
});
const testOut = (test.stdout || "") + (test.stderr || "");
check("unit battery runs", test.status === 0);
check("unit battery: 17 passed (adds catch-up resync, promotion fencing, quorum same-host cap)", /17 passed; 0 failed/.test(testOut));

// 2) Small fsync-honest bench run.
const dataDir = join(tmpdir(), `agentgres-substrate-verify-${process.pid}`);
rmSync(dataDir, { recursive: true, force: true });
const OPS = 10000;
const bench = spawnSync(
  "cargo",
  ["run", "--release", "-p", "agentgres", "--bin", "substrate-bench"],
  {
    cwd: repo, encoding: "utf8",
    env: { ...process.env, DATA_DIR: dataDir, OPS: String(OPS), CLIENTS: "32", DOMAINS: "1", SYNC: "1" },
    maxBuffer: 64 * 1024 * 1024,
  },
);
check("bench run exits 0", bench.status === 0);

let report = null;
try {
  report = JSON.parse(readFileSync(join(dataDir, "bench-report.json"), "utf8"));
} catch { /* fall through */ }
check("bench-report.json parses", !!report);

if (report) {
  const a = report.admission ?? {};
  check("all ops admitted", a.admitted_total === OPS, `admitted=${a.admitted_total}`);
  check("zero refusals (disjoint objects)", a.refused_total === 0);
  check("admission p99 reported > 0", a.overall_p99_ms > 0, `p99=${a.overall_p99_ms?.toFixed?.(3)}ms`);
  check("throughput reported > 0", a.aggregate_throughput_ops_s > 0, `${Math.round(a.aggregate_throughput_ops_s)} ops/s`);
  check("checkpoint median < 100ms (O(heads), not O(log))", report.checkpoint?.median_ms < 100, `${report.checkpoint?.median_ms?.toFixed?.(3)}ms`);
  check("fork median < 1000ms (contract target)", report.fork?.median_ms < 1000, `${report.fork?.median_ms?.toFixed?.(3)}ms`);
  check("recovery replay: heads and root match", report.recovery?.heads_and_root_match === true, `${report.recovery?.replay_ms?.toFixed?.(1)}ms`);
  check("projection replayed all frames", report.projection?.frames_replayed >= OPS, `${report.projection?.frames_replayed} frames`);
  check("contract targets recorded (not asserted)", report.contract?.targets?.admission_p99_ms === 5.0);
}
rmSync(dataDir, { recursive: true, force: true });

// 3) Mux combined-flush mode: many domains, one log, one fsync per batch.
const muxDir = join(tmpdir(), `agentgres-substrate-verify-mux-${process.pid}`);
rmSync(muxDir, { recursive: true, force: true });
const MUX_OPS = 4000, MUX_DOMAINS = 4;
const mux = spawnSync(
  "cargo",
  ["run", "--release", "-p", "agentgres", "--bin", "substrate-bench"],
  {
    cwd: repo, encoding: "utf8",
    env: { ...process.env, DATA_DIR: muxDir, OPS: String(MUX_OPS), CLIENTS: "8", DOMAINS: String(MUX_DOMAINS), MUX: "1", SYNC: "1" },
    maxBuffer: 64 * 1024 * 1024,
  },
);
check("mux bench run exits 0", mux.status === 0);
let muxReport = null;
try {
  muxReport = JSON.parse(readFileSync(join(muxDir, "bench-report.json"), "utf8"));
} catch { /* fall through */ }
check("mux report parses", !!muxReport);
if (muxReport) {
  const a = muxReport.admission ?? {};
  check("mux mode recorded", muxReport.mode === "mux_combined_flush");
  check("mux: all ops admitted across domains", a.admitted_total === MUX_OPS * MUX_DOMAINS, `admitted=${a.admitted_total}`);
  check("mux: per-domain results present", (a.per_domain ?? []).length === MUX_DOMAINS);
  check("mux: recovery replays all domains with matching roots",
    muxReport.recovery?.heads_and_root_match === true && muxReport.recovery?.domains_recovered === MUX_DOMAINS,
    `${muxReport.recovery?.domains_recovered} domains`);
}
rmSync(muxDir, { recursive: true, force: true });

// 4) Shadow: real daemon provider receipts through the engine (read-only).
//    Prefers the checkout-local daemon data dir; honest named skip if absent.
const localReceipts = join(repo, ".ioi/hypervisor/data/provider-receipts");
if (!existsSync(localReceipts)) {
  console.log("SKIP shadow checks — no checkout-local provider-receipts dir (run any provider verify battery to mint some); not counted as pass");
} else {
  const shadowDir = join(tmpdir(), `agentgres-substrate-verify-shadow-${process.pid}`);
  const shadow = spawnSync(
    "cargo",
    ["run", "--release", "-p", "agentgres", "--bin", "substrate-shadow"],
    {
      cwd: repo, encoding: "utf8",
      env: { ...process.env, RECEIPTS_DIR: localReceipts, DATA_DIR: shadowDir, SYNC: "1" },
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  check("shadow run exits 0", shadow.status === 0);
  let sr = null;
  try {
    sr = JSON.parse(readFileSync(join(shadowDir, "shadow-report.json"), "utf8"));
  } catch { /* fall through */ }
  check("shadow report parses", !!sr);
  if (sr) {
    check("shadow: coverage complete (every parsed receipt admitted)", sr.coverage_complete === true, `${sr.admitted}/${sr.receipts_found}`);
    check("shadow: double-run deterministic (identical final root)", sr.double_run_deterministic === true);
    check("shadow: recovery root match", sr.recovery_root_match === true);
    check("shadow: read-only (never mutates daemon state)", sr.mutates_daemon_state === false);

    // 5) Parity gate: engine payloads vs legacy JSON dir (the compare step
    //    of shadow → compare → promote). Promotion bar: faithful + complete.
    const parity = spawnSync(
      "cargo",
      ["run", "--release", "-p", "agentgres", "--bin", "substrate-parity"],
      {
        cwd: repo, encoding: "utf8",
        env: { ...process.env, LEGACY_DIR: localReceipts, ENGINE_DIR: join(shadowDir, "run1"), DOMAIN: "provider-receipts" },
        maxBuffer: 64 * 1024 * 1024,
      },
    );
    check("parity run exits 0 (payload_faithful)", parity.status === 0);
    let pr = null;
    try {
      const out = parity.stdout || "";
      pr = JSON.parse(out.slice(out.indexOf("{")));
    } catch { /* fall through */ }
    check("parity report parses", !!pr);
    if (pr) {
      check("parity: zero diverged payloads", (pr.diverged ?? [1]).length === 0);
      check("parity: zero phantom engine records", (pr.extra_in_engine ?? [1]).length === 0);
      check("parity: full coverage after shadow ingest (missing==0)", pr.missing_from_engine === 0, `${pr.matched}/${pr.legacy_records} matched`);
    }
  }
  rmSync(shadowDir, { recursive: true, force: true });
}

// 6) Replication-as-durability: two OS processes, replicate-then-ack,
//    background flush both sides; durability class honest, roots identical.
{
  const repDir = join(tmpdir(), `agentgres-verify-replica-${process.pid}`);
  const repBenchDir = join(tmpdir(), `agentgres-verify-repl-bench-${process.pid}`);
  rmSync(repDir, { recursive: true, force: true });
  rmSync(repBenchDir, { recursive: true, force: true });
  const PORT = 39400 + (process.pid % 1000);
  const replica = spawn(
    "cargo",
    ["run", "--release", "-p", "agentgres", "--bin", "substrate-replica"],
    {
      cwd: repo,
      env: { ...process.env, REPLICA_ADDR: `127.0.0.1:${PORT}`, REPLICA_DIR: repDir },
      stdio: "ignore",
    },
  );
  spawnSync("sleep", ["3"]);
  const rb = spawnSync(
    "cargo",
    ["run", "--release", "-p", "agentgres", "--bin", "substrate-bench"],
    {
      cwd: repo, encoding: "utf8",
      env: {
        ...process.env, DATA_DIR: repBenchDir, OPS: "8000", CLIENTS: "16",
        DOMAINS: "2", MUX: "1", REPLICA_ADDR: `127.0.0.1:${PORT}`, REPLICA_DIR: repDir,
      },
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  replica.kill();
  check("replicated bench run exits 0", rb.status === 0);
  let rr = null;
  try {
    rr = JSON.parse(readFileSync(join(repBenchDir, "bench-report.json"), "utf8"));
  } catch { /* fall through */ }
  check("replicated report parses", !!rr);
  if (rr) {
    check("replicated mode recorded", rr.mode === "mux_replicated_ack");
    check("durability class is replicated_same_host (honest cap, never quorum on one host)",
      rr.durability?.ack_class === "replicated_same_host");
    check("replica roots byte-identical to primary", rr.durability?.replica_root_match === true);
    check("replicated: all ops admitted", rr.admission?.admitted_total === 16000, `admitted=${rr.admission?.admitted_total}`);
  }
  rmSync(repDir, { recursive: true, force: true });
  rmSync(repBenchDir, { recursive: true, force: true });
}

console.log(`\n${fail === 0 ? "DONE-BAR PASS" : "DONE-BAR FAIL"}: ${pass}/${pass + fail} checks`);
process.exit(fail === 0 ? 0 : 1);
