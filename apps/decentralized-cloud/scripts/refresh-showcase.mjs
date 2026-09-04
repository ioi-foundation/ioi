#!/usr/bin/env node
// decentralized.cloud — showcase refresher. OPERATOR PROCESS, NOT THE FACE.
//
// Quotes carry roughly fifteen-minute validity windows and taking a fresh one is a
// write, so a strictly read-only face can only ever render evidence somebody else
// refreshed. This is that somebody. It runs beside the face, never inside it: it is
// a separate process, it is never imported by serve-face.mjs, and it is not
// reachable from any served route. The face stays writer-less and its 405 on every
// mutating method stays literally true.
//
// It is read-only with respect to PROVIDERS: it opens intents and refreshes
// candidates, which quote. It never touches provider-ops, never leases anything,
// and never spends. It is operator-only and does not become a public route.
//
// Usage:
//   node apps/decentralized-cloud/scripts/refresh-showcase.mjs            # loop
//   node apps/decentralized-cloud/scripts/refresh-showcase.mjs --once     # one cycle

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import os from "node:os";

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const STATE_DIR = process.env.IOI_DC_STATE_DIR || path.join(os.homedir(), ".ioi", "decentralized-cloud");
const STATE_FILE = path.join(STATE_DIR, "showcase.json");

// Cadence sits inside the validity window so a fresh batch always lands before the
// last one expires — ten minutes against a fifteen-minute window.
const CADENCE_S = Number(process.env.IOI_DC_REFRESH_CADENCE_S || 600);
// A sweep has been measured at 38.8s against one live adapter. Space the intents so
// two of them never hammer a provider's API back to back.
const GAP_MS = Number(process.env.IOI_DC_REFRESH_GAP_MS || 5000);
const ONCE = process.argv.includes("--once");

// At most four, declared here rather than discovered: a showcase set that grows by
// accident is a load pattern nobody agreed to.
const SHOWCASE = [
  {
    key: "gpu",
    label: "compute.gpu_runtime · any region",
    intent: {
      runtime_class: "compute.gpu_runtime",
      resource_classes: ["compute.gpu_runtime"],
      gpu: { required: true },
    },
  },
  {
    key: "default",
    label: "the daemon's own default intent",
    existing_ref: "cloud-resource-intent://cri_default",
  },
];

const log = (msg) => console.log(`${new Date().toISOString()} refresh-showcase: ${msg}`);

async function jd(method, route, body) {
  const res = await fetch(`${DAEMON}${route}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

function loadState() {
  try {
    return JSON.parse(readFileSync(STATE_FILE, "utf8"));
  } catch {
    return { intents: {} };
  }
}

function saveState(state) {
  mkdirSync(STATE_DIR, { recursive: true });
  writeFileSync(STATE_FILE, `${JSON.stringify(state, null, 2)}\n`);
}

async function resolveIntentRef(entry, state) {
  if (entry.existing_ref) return entry.existing_ref;
  const known = state.intents[entry.key];
  if (known) {
    const check = await jd("GET", `/v1/hypervisor/cloud-candidates/intents/${encodeURIComponent(known)}`);
    if (check.status === 200) return known;
    log(`intent for '${entry.key}' no longer resolves; opening a new one`);
  }
  const created = await jd("POST", "/v1/hypervisor/cloud-candidates/intents", entry.intent);
  const ref = created.body?.intent?.intent_ref;
  if (!ref) throw new Error(`could not open intent for '${entry.key}' (HTTP ${created.status})`);
  state.intents[entry.key] = ref;
  saveState(state);
  log(`opened intent for '${entry.key}': ${ref}`);
  return ref;
}

// Single flight: a cycle that runs long can never overlap the next tick. The guard is
// a plain boolean because this process is deliberately single-threaded and single-host.
let cycleRunning = false;

async function cycle() {
  if (cycleRunning) {
    log("previous cycle still running — skipping this tick rather than stacking refreshes");
    return;
  }
  cycleRunning = true;
  const state = loadState();
  try {
    for (const [index, entry] of SHOWCASE.entries()) {
      if (index > 0) await new Promise((r) => setTimeout(r, GAP_MS));
      const started = Date.now();
      try {
        const intentRef = await resolveIntentRef(entry, state);
        const refreshed = await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", {
          intent_ref: intentRef,
        });
        const candidates = refreshed.body?.candidates || [];
        const live = candidates.filter((c) => c.evidence_mode === "live_evidence");
        const venues = [...new Set(live.map((c) => c.provider_kind))].sort();
        log(
          `${entry.key}: HTTP ${refreshed.status} in ${((Date.now() - started) / 1000).toFixed(1)}s — ` +
          `${candidates.length} candidates, ${live.length} live_evidence, ` +
          `venues [${venues.join(", ") || "none"}]`
        );
      } catch (err) {
        log(`${entry.key}: FAILED — ${err.message}. The face will show expired evidence rather than a stale price.`);
      }
    }
  } finally {
    cycleRunning = false;
  }
}

async function main() {
  log(`daemon ${DAEMON} · ${SHOWCASE.length} showcase intents · cadence ${CADENCE_S}s · state ${STATE_FILE}`);
  await cycle();
  if (ONCE) return;
  const timer = setInterval(cycle, CADENCE_S * 1000);
  const stop = (signal) => { log(`${signal} — stopping`); clearInterval(timer); process.exit(0); };
  process.on("SIGTERM", () => stop("SIGTERM"));
  process.on("SIGINT", () => stop("SIGINT"));
}

main().catch((e) => {
  log(`crashed: ${e}`);
  process.exit(1);
});
