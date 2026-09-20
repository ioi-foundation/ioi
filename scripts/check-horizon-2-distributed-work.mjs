#!/usr/bin/env node
// check:horizon-2-distributed-work — M12.6: Horizon 2, one logical DAS doing useful work across nodes,
// as a gate (docs/architecture/_meta/execution-horizons.md § Horizon 2; register R-209).
//
// CANON. 2A — continuity across two failure domains: one stable system_id, constitution, owner set and
// ordering profile; provision and attest a candidate, propose membership, assign state_replica/
// hot_standby, restore a checkpoint, catch up the ordered log, verify the current state root, mark
// observed readiness; inject writer/node/link failure, promote only through operator-controlled
// policy, increment the writer epoch, fence the old writer, replay, prove no dual effects; drain and
// removal as lifecycle; unchanged authority (INV-22..24). 2B-core — useful same-system distributed work:
// typed role→membership runtime assignments, allocation leases, shared-state watermarks, coordination
// epochs, partition/rejoin/rebalance, fenced reassignment, duplicate/ambiguous-effect reconciliation,
// backpressure. "Replication is not consensus"; the storage epoch never substitutes for the System
// writer epoch (agentgres/doctrine.md § Bounded-DAS deployment binding).
//
// WHAT THIS RUNNER IS. The demands are CLAUSES. Each is EXECUTED by the gate or pinned population that
// already proves it, or NAMED with its owner — and one leg is this runner's own, the only genuinely
// two-process evidence the estate can produce today, labelled exactly as what it is: STORAGE-LAYER
// continuity. Two isolated daemons and one Agentgres log shipped to a `substrate-replica` peer on its
// own directory: admitted batches arrive byte-identical; a peer that fell behind catches up by offset at
// the primary's next handshake; the operator promotes the replica to epoch+1 with a durable record; a
// second daemon opened on the promoted directory serves the same domain roots; the deposed primary is
// FENCED at its next handshake and continues loudly without its replica, and its later writes never
// reach the peer. That is `replicated_same_host`, never `quorum_replicated`, never a System writer
// epoch. Everything at the System layer (a peer-produced catch-up receipt and verified root consumed
// by admission, one system_id read from two processes, a deposed System writer refused a consequential
// effect, RPO/RTO) and everything in 2B beyond placement is named with its owner. Nothing is read back
// and called verified: a clause counts as executed only from its gate's own exit status AND the evidence
// it wrote; an absence counts only with an owner; the verdict is a pure function of the clause rows.
//
//   --drills      CI-bound, seconds: the binding of every clause to a real script, pinned floor or
//                 population; the structural claims each source must carry (the replica binary's
//                 promote mode, the handshake fence, the daemon's replica env, the membership seam
//                 that reads catch-up evidence from its own data dir — the named gap, anchored);
//                 the verdict rules; canon's binding.
//   --storage     the storage-continuity leg, run directly (needs the daemon and substrate-replica
//                 binaries; builds the replica outside a harness, never inside one). Minutes.
//   --mutation    planted defects against the drills' oracles — each must go red.
//   (default)     the full gate: drills, then every executed gate and the storage leg INSIDE the
//                 isolated-egress harness, each ledger classified here; then the verdict.
//                 Exit 0 = pass, 2 = named failure, 1 = fail.
//   --only <a,b>  (full) run only these clause numbers of the executed set.
//   --evidence <path>  also write the evidence there (default .artifacts/mvp-finish-line/).

import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { emitVerifierCensus } from "../apps/hypervisor/scripts/lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv, startIsolatedPlane } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { classifyLedger, probeIsolation, runIsolated } from "./lib/egress-harness.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP = "@ioi/hypervisor-app";
const APP_SCRIPTS = path.join(ROOT, "apps", "hypervisor", "scripts");
const FLOORS = path.join(ROOT, "apps", "hypervisor", "verifier-floors.v1.json");
const CANON = path.join(ROOT, "docs", "architecture", "_meta", "execution-horizons.md");
const AGENTGRES_DOCTRINE = path.join(ROOT, "docs", "architecture", "components", "agentgres", "doctrine.md");
const REPLICA_BIN = path.join(ROOT, "target", "debug", "substrate-replica");
const SELF = fileURLToPath(import.meta.url);
const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const flagValue = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const MODE = flag("--mutation") ? "mutation" : flag("--storage") ? "storage" : flag("--drills") ? "drills" : "full";
const ONLY = flagValue("--only") ? new Set(flagValue("--only").split(",").map((n) => Number(n))) : null;

// ---- what executes: app verifiers (floored), root populations (pinned tests), this runner's leg ---------
const gate = (script, floor, source, minutes) => ({ kind: "app", script, workspace: APP, floor, source, minutes });
const population = (script, file, minutes) => ({ kind: "population", script, workspace: null, population: file, minutes });
const STORAGE = { kind: "storage", script: "check:horizon-2-distributed-work -- --storage", minutes: 20 };
const BACKUP = gate("check:backup-restore", "backup-restore", "verify-hypervisor-backup-restore.mjs", 45);
const ATTEST = gate("check:custody-proven-private-routes", "custody-proven-private-routes", "verify-hypervisor-custody-proven-private-routes.mjs", 30);
const RESERVE = gate("check:work-lifecycle-reservations", "work-lifecycle-reservations", "verify-hypervisor-work-lifecycle-reservations.mjs", 15);
const MEMBERSHIP = population("check:system-deployment-membership-plane", "scripts/test-populations/system-deployment-membership-plane.v1.json", 60);
const RECOVERY = population("check:ordering-finality-recovery", "scripts/test-populations/ordering-finality-recovery.v1.json", 60);
const EFFECTS = population("check:recognized-effect-publication-order", "scripts/test-populations/recognized-effect-publication-order.v1.json", 60);
const REPLAY = { kind: "root", script: "check:portable-evidence-replay", workspace: null, minutes: 40 };
const S6_6 = "M12.6-S6-6 (the daemon slice: a peer-produced catch-up receipt and verified root consumed by admission; one system_id read from two processes; a deposed System writer refused a consequential effect; RPO/RTO on a second node)";
const H2B = "the H2B-core module (canon owner doc for the digital coordination epoch and allocation lease, contracts, daemon, verifier — M12.6 follow-on with M04)";

export const CLAUSES = [
  { n: 1, demand: "one stable system_id, constitution, owner set and ordering profile across both domains", executed_by: [], absence: { what: "no gate reads one system_id from two processes; the genesis gates prove it on one node", owner: S6_6 } },
  { n: 2, demand: "provision and attest a candidate node", executed_by: [ATTEST], absence: { what: "the attested node (HypervisorOS node plane: temporal profile, boot profile, sealed receipt, derived readiness) is never joined to a System — attestation is not membership", owner: S6_6 } },
  { n: 3, demand: "propose membership, assign state_replica / hot_standby, admit the node", executed_by: [MEMBERSHIP], absence: { what: "the membership plane's six operations are pinned unit tests over records; never driven over HTTP with a real peer", owner: S6_6 } },
  { n: 4, demand: "restore a checkpoint on the second domain", executed_by: [BACKUP], absence: { what: "restore across two real daemons is custody evidence (W3.3), not a System's membership-bound restore", owner: S6_6 } },
  { n: 5, demand: "catch up the ordered log", executed_by: [STORAGE, MEMBERSHIP], absence: { what: "catch-up is proven at the storage layer (a replica that fell behind resyncs by offset at the next handshake); the System-layer advance_catchup resolves its receipt from the same daemon's own evidence directory — no peer produces one", owner: S6_6 } },
  { n: 6, demand: "verify the current state root on the second domain", executed_by: [STORAGE], absence: { what: "the promoted replica's engine serves the same domain roots as the primary (storage layer); a peer-verified root consumed by attest_readiness does not exist", owner: S6_6 } },
  { n: 7, demand: "mark observed readiness", executed_by: [MEMBERSHIP], absence: { what: "readiness evidence is record-shaped and pinned by contract invariant; never attested by a second process", owner: S6_6 } },
  { n: 8, demand: "promote only through operator policy, increment the writer epoch, fence the old writer", executed_by: [STORAGE, RECOVERY], absence: { what: "operator promotion at epoch+1 with a durable record and the deposed primary fenced at its next handshake are proven at the STORAGE layer (replicated_same_host); the System writer-epoch transition and a deposed System writer refused a consequential effect are contracts with pinned tests, never demonstrated live", owner: S6_6 } },
  { n: 9, demand: "replay converges on both domains", executed_by: [REPLAY], absence: { what: "portable evidence replays to its root on one domain; replay on a SECOND domain is not driven", owner: S6_6 } },
  { n: 10, demand: "drain and removal as lifecycle (two-step)", executed_by: [MEMBERSHIP], absence: { what: "drain_node and remove_node are pinned unit tests over records; a node's work is never drained live", owner: S6_6 } },
  { n: 11, demand: "no dual effects; duplicate/ambiguous-effect custody and reconciliation", executed_by: [STORAGE, EFFECTS], absence: { what: "the deposed primary's later writes never reach the peer (storage); recognized-effect publication order is pinned in-process across 42 crash edges; reconciliation ACROSS two domains is not driven", owner: `${S6_6} · ${H2B}` } },
  { n: 12, demand: "typed role→membership runtime assignments without granting authority by placement", executed_by: [], absence: { what: "runtime-assignment.v1 carries placement only — no system_placement, no node_membership_ref; canon's RuntimeAssignmentEnvelope is planned", owner: H2B } },
  { n: 13, demand: "allocation leases and fenced reassignment", executed_by: [RESERVE], absence: { what: "per-dimension reservations transfer atomically on reassignment in the kernel seam — not fenced, not across nodes; no digital allocation-lease contract is registered", owner: H2B } },
  { n: 14, demand: "shared-state watermarks and coordination epochs", executed_by: [], absence: { what: "watermarks exist only as policy refs and a fence-context member; a coordination epoch is defined only in the embodied plane", owner: H2B } },
  { n: 15, demand: "partition / rejoin / rebalance and backpressure during useful work", executed_by: [], absence: { what: "no daemon seam, no policy object, no gate", owner: H2B } },
];
export const OUT_OF_SCOPE = { what: "H2B-embodied (fleet manifests, HIL, spacetime reservation leases) is parallel or later and gates embodied promotion only", owner: "the embodied runtime program" };
export const DROPPED_CITATIONS = ["verify-hypervisor-auto-failover-trigger.mjs", "verify-hypervisor-cross-provider-failover.mjs"];

// ---- infrastructure --------------------------------------------------------------------------------------
const results = [];
const evidence = { schema: "ioi.horizon-2-distributed-work-evidence.v1", mode: MODE, started_at: new Date().toISOString(), drills: [], storage: null, clauses: [], verdict: null, mutation: null };
let sink = results;
function ok(name, cond, detail) {
  const row = { name, pass: !!cond, detail: detail == null ? "" : String(detail) };
  sink.push(row);
  if (sink === results) { evidence.drills.push({ ...row, at: new Date().toISOString() }); console.log(`${row.pass ? "PASS" : "FAIL"}  ${name}${row.detail ? ` — ${row.detail.slice(0, 220)}` : ""}`); }
  return row.pass;
}
function blocked(reason) { console.error(`BLOCKED: ${reason}`); writeEvidence(); process.exit(2); }
function writeEvidence() {
  evidence.finished_at = new Date().toISOString();
  evidence.summary = { passed: results.filter((r) => r.pass).length, total: results.length };
  const dir = path.join(ROOT, ".artifacts", "mvp-finish-line");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `horizon-2-distributed-work-${MODE}-${evidence.started_at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, `${JSON.stringify(evidence, null, 2)}\n`);
  const extra = flagValue("--evidence");
  if (extra) { fs.mkdirSync(path.dirname(path.resolve(ROOT, extra)), { recursive: true }); fs.writeFileSync(path.resolve(ROOT, extra), `${JSON.stringify(evidence, null, 2)}\n`); }
  return file;
}
const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");
const sha256File = (f) => (fs.existsSync(f) ? sha256(fs.readFileSync(f)) : null);
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((resolve, reject) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => resolve(port)); }); s.on("error", reject); });

// ---- the oracles (pure) -----------------------------------------------------------------------------------
export function bindingFindings(clauses, { rootPkg, appPkg, floors }) {
  const f = [];
  const seen = new Set();
  for (const c of clauses) {
    if (!Number.isInteger(c.n) || c.n < 1 || c.n > 15) f.push(`clause_out_of_range: ${c.n}`);
    if (seen.has(c.n)) f.push(`clause_duplicated: ${c.n}`);
    seen.add(c.n);
    if ((c.executed_by ?? []).length === 0 && !c.absence) f.push(`clause_${c.n}_neither_executed_nor_named`);
    for (const g of c.executed_by ?? []) {
      if (g.kind === "app") {
        if (!appPkg.scripts?.[g.script]) f.push(`clause_${c.n}_binds_missing_script: ${g.script}`);
        const row = (floors.verifiers ?? []).find((r) => r.id === g.floor);
        if (!row) f.push(`clause_${c.n}_floor_missing: ${g.floor}`);
        else if (!(row.runtime_assertions >= 1) || row.npm_script !== g.script) f.push(`clause_${c.n}_floor_mismatch: ${g.floor}`);
        if (!fs.existsSync(path.join(APP_SCRIPTS, g.source))) f.push(`clause_${c.n}_source_missing: ${g.source}`);
      } else if (g.kind === "population") {
        if (!rootPkg.scripts?.[g.script]) f.push(`clause_${c.n}_binds_missing_script: ${g.script}`);
        const file = path.join(ROOT, g.population);
        if (!fs.existsSync(file)) f.push(`clause_${c.n}_population_missing: ${g.population}`);
        else { const pop = readJson(file); const families = Array.isArray(pop.families) ? pop.families : []; if (!(families.length >= 1 && families.every((fam) => Array.isArray(fam.tests) && fam.tests.length >= 1))) f.push(`clause_${c.n}_population_empty: ${g.population}`); }
      } else if (g.kind === "root") {
        if (!rootPkg.scripts?.[g.script]) f.push(`clause_${c.n}_binds_missing_script: ${g.script}`);
      } else if (g.kind !== "storage") f.push(`clause_${c.n}_unknown_gate_kind: ${g.kind}`);
    }
    if (c.absence && !(typeof c.absence.owner === "string" && c.absence.owner.trim().length > 0 && typeof c.absence.what === "string" && c.absence.what.length > 20)) f.push(`clause_${c.n}_absence_without_owner`);
  }
  for (let n = 1; n <= 15; n += 1) if (!seen.has(n)) f.push(`clause_missing: ${n}`);
  return f;
}
/** What the sources must carry for what the clauses claim — and the named gap, anchored in code. */
export function structuralFindings(src) {
  const f = [];
  if (!/Some\("promote"\)/u.test(src.replica_bin ?? "") || !/engine\.promote\(/u.test(src.replica_bin ?? "")) f.push("replica_binary_lacks_operator_promotion");
  if (!/FENCED at handshake/u.test(src.replica_lib ?? "") || !/fenced mid-stream/u.test(src.replica_lib ?? "")) f.push("replica_link_lacks_handshake_or_midstream_fence");
  if (!/IOI_SUBSTRATE_REPLICA_ADDRS/u.test(src.substrate_store ?? "") || !/continuing without it/u.test(src.substrate_store ?? "")) f.push("daemon_does_not_consume_replica_addrs_loudly");
  if (!/load_node_evidence\(/u.test(src.membership_routes ?? "")) f.push("membership_seam_gap_not_anchored");
  if (!/quorum_replicated/u.test(src.replica_lib ?? "") || !/same-host/u.test(src.replica_lib ?? "")) f.push("replica_link_lacks_same_host_cap");
  return f;
}
export function verdict(rows) {
  const failures = [];
  const absences = [];
  const seen = new Set();
  for (const r of rows) {
    if (!Number.isInteger(r.n) || r.n < 1 || r.n > 15) { failures.push(`row_out_of_range:${r.n}`); continue; }
    if (seen.has(r.n)) failures.push(`row_duplicated:${r.n}`);
    seen.add(r.n);
    for (const g of r.executed ?? []) {
      if (g.status !== 0) failures.push(`clause_${r.n}_red: ${g.script} exit ${g.status}`);
      else if (!g.evidence || !g.evidence_sha256) failures.push(`clause_${r.n}_fabricated: ${g.script} reports success without evidence`);
      if (g.ledger && g.ledger.reach > 0) failures.push(`clause_${r.n}_undeclared_egress: ${g.script} reached ${g.ledger.reach} non-loopback destination(s)`);
      if (g.floor_expected != null && g.executed_assertions != null && g.executed_assertions < g.floor_expected) failures.push(`clause_${r.n}_below_floor: ${g.script} ${g.executed_assertions} < ${g.floor_expected}`);
    }
    if (r.absence) { if (!(r.absence.owner && r.absence.what)) failures.push(`clause_${r.n}_absence_without_owner`); else absences.push({ n: r.n, ...r.absence }); }
    if (r.not_executed) absences.push({ n: r.n, what: `not executed in this run: ${r.not_executed}`, owner: "this runner (on demand)" });
  }
  for (let n = 1; n <= 15; n += 1) if (!seen.has(n)) failures.push(`row_missing:${n}`);
  return { kind: failures.length ? "fail" : absences.length ? "named_failure" : "pass", failures, absences };
}

// ---- the drills -------------------------------------------------------------------------------------------
function readSources() {
  const rd = (p) => (fs.existsSync(p) ? fs.readFileSync(p, "utf8") : "");
  return {
    replica_bin: rd(path.join(ROOT, "crates", "agentgres", "src", "bin", "replica.rs")),
    replica_lib: rd(path.join(ROOT, "crates", "agentgres", "src", "replica.rs")),
    substrate_store: rd(path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "substrate_store.rs")),
    membership_routes: rd(path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "system_membership_routes.rs")),
  };
}
function drills() {
  const rootPkg = readJson(path.join(ROOT, "package.json"));
  const appPkg = readJson(path.join(ROOT, "apps", "hypervisor", "package.json"));
  const floors = readJson(FLOORS);
  const binding = bindingFindings(CLAUSES, { rootPkg, appPkg, floors });
  const executed = CLAUSES.filter((c) => (c.executed_by ?? []).length).map((c) => c.n);
  const unexecuted = CLAUSES.filter((c) => !(c.executed_by ?? []).length).map((c) => c.n);
  ok(`Horizon 2's fifteen demands are bound: every executed clause names a real script with a pinned floor or a pinned population (executed ${executed.join(",")}; nothing executes ${unexecuted.join(",")}), every named failure carries its owner, clauses cover 1–15 exactly once`, binding.length === 0, binding.join("; ") || "bound");
  const structural = structuralFindings(readSources());
  ok("the sources carry what the storage leg claims and the named gap is ANCHORED in code: the replica binary has the operator promotion mode; the replica link fences a stale primary at handshake and mid-stream and caps same-host peers below quorum_replicated; the daemon consumes IOI_SUBSTRATE_REPLICA_ADDRS and continues loudly without an unreachable peer; the membership seam resolves catch-up evidence from its own data dir (load_node_evidence) — which is exactly why the System-layer clauses are named, not claimed", structural.length === 0, structural.join("; ") || "read from four sources");
  const cited = DROPPED_CITATIONS.map((s) => [s, Object.values(appPkg.scripts ?? {}).some((cmd) => cmd.includes(s))]);
  ok("the two provider-placement failover verifiers (auto-failover trigger, cross-provider failover) are NOT composed: they target the shared daemon and carry no npm script, and a provider FailoverPlan is a different object from the System writer/state continuity this gate is about", cited.every(([, registered]) => !registered), cited.map(([s, r]) => `${s}: ${r ? "registered" : "unregistered"}`).join(" · "));
  const green = (n) => ({ n, executed: [{ script: `g${n}`, status: 0, evidence: "x", evidence_sha256: "ab", ledger: { reach: 0 }, executed_assertions: 5, floor_expected: 5 }] });
  const base = []; for (let n = 1; n <= 15; n += 1) base.push(green(n));
  const allGreen = verdict(base);
  const withAbsence = verdict(base.map((r) => (r.n === 12 ? { n: 12, absence: { what: "no assignment envelope", owner: "H2B" } } : r)));
  const fabricated = verdict(base.map((r) => (r.n === 5 ? { n: 5, executed: [{ script: "x", status: 0, evidence: null, evidence_sha256: null }] } : r)));
  const red = verdict(base.map((r) => (r.n === 8 ? { n: 8, executed: [{ script: "x", status: 1, evidence: "x", evidence_sha256: "ab" }] } : r)));
  const shrunk = verdict(base.map((r) => (r.n === 2 ? { n: 2, executed: [{ script: "x", status: 0, evidence: "x", evidence_sha256: "ab", executed_assertions: 4, floor_expected: 5 }] } : r)));
  const reach = verdict(base.map((r) => (r.n === 4 ? { n: 4, executed: [{ script: "x", status: 0, evidence: "x", evidence_sha256: "ab", ledger: { reach: 1 } }] } : r)));
  const noOwner = verdict(base.map((r) => (r.n === 1 ? { n: 1, absence: { what: "x", owner: "" } } : r)));
  const missing = verdict(base.filter((r) => r.n !== 15));
  ok("the verdict is a pure function of the clause rows: all executed green with no absence → PASS; a typed absence → NAMED FAILURE; a fabricated success row, a red gate, a census below its floor, a reach beyond loopback, an unowned absence or a missing clause → FAIL", allGreen.kind === "pass" && withAbsence.kind === "named_failure" && fabricated.kind === "fail" && red.kind === "fail" && shrunk.kind === "fail" && reach.kind === "fail" && noOwner.kind === "fail" && missing.kind === "fail", `${allGreen.kind}/${withAbsence.kind}/${fabricated.kind}/${red.kind}/${shrunk.kind}/${reach.kind}/${noOwner.kind}/${missing.kind}`);
  const canon = fs.readFileSync(CANON, "utf8");
  const h2 = canon.slice(canon.indexOf("## Horizon 2 — one logical DAS"), canon.indexOf("## Horizon 3"));
  const doctrine = fs.readFileSync(AGENTGRES_DOCTRINE, "utf8");
  ok("canon binds the gate: execution-horizons.md § Horizon 2 names check:horizon-2-distributed-work, types the storage-layer leg as replicated_same_host and never a System writer epoch, reads 2B's workload as the application's composition bound through the seam (R-192), and claims no Horizon 2 pass; agentgres/doctrine.md keeps the mux epoch and the System writer epoch separate", h2.includes("`check:horizon-2-distributed-work`") && /replicated_same_host/u.test(h2) && /no\s+Horizon 2 pass is claimed/u.test(h2) && !/GoalRun\/RoleTopology work/u.test(h2) && /never substitute/u.test(doctrine), "read from execution-horizons.md and agentgres/doctrine.md");
}

// ---- mutation ---------------------------------------------------------------------------------------------
function mutation() {
  const rows = [];
  const plant = (label, detected, detail) => { rows.push({ label, detected, detail }); console.log(`${detected ? "DETECTED" : "MISSED  "}  ${label}${detail ? ` — ${String(detail).slice(0, 140)}` : ""}`); };
  const rootPkg = readJson(path.join(ROOT, "package.json"));
  const appPkg = readJson(path.join(ROOT, "apps", "hypervisor", "package.json"));
  const floors = readJson(FLOORS);
  let f = bindingFindings(CLAUSES.map((c) => (c.n === 4 ? { ...c, executed_by: [{ ...BACKUP, script: "check:a-script-that-does-not-exist" }] } : c)), { rootPkg, appPkg, floors });
  plant("a clause bound to a script that does not exist", f.some((x) => /binds_missing_script/u.test(x)), f[0]);
  f = bindingFindings(CLAUSES.map((c) => (c.n === 13 ? { ...c, executed_by: [{ ...RESERVE, floor: "a-floor-nobody-pinned" }] } : c)), { rootPkg, appPkg, floors });
  plant("an executed clause whose floor row does not exist", f.some((x) => /floor_missing/u.test(x)), f[0]);
  f = bindingFindings(CLAUSES.map((c) => (c.n === 3 ? { ...c, executed_by: [{ ...MEMBERSHIP, population: "scripts/test-populations/nobody.v1.json" }] } : c)), { rootPkg, appPkg, floors });
  plant("a clause bound to a population file that does not exist", f.some((x) => /population_missing/u.test(x)), f[0]);
  f = bindingFindings(CLAUSES.map((c) => (c.n === 12 ? { ...c, absence: { what: c.absence.what, owner: "" } } : c)), { rootPkg, appPkg, floors });
  plant("a named failure without an owner", f.some((x) => /absence_without_owner/u.test(x)), f[0]);
  f = bindingFindings(CLAUSES.filter((c) => c.n !== 8), { rootPkg, appPkg, floors });
  plant("the fenced-promotion clause silently dropped", f.some((x) => /clause_missing: 8/u.test(x)), f[0]);
  const real = readSources();
  f = structuralFindings({ ...real, replica_bin: real.replica_bin.replace(/Some\("promote"\)/gu, 'Some("demote")') });
  plant("a replica binary without the operator promotion mode", f.includes("replica_binary_lacks_operator_promotion"), f[0]);
  f = structuralFindings({ ...real, replica_lib: real.replica_lib.replace(/FENCED at handshake/gu, "welcomed at handshake") });
  plant("a replica link that no longer fences a stale primary at handshake", f.includes("replica_link_lacks_handshake_or_midstream_fence"), f[0]);
  f = structuralFindings({ ...real, membership_routes: real.membership_routes.replace(/load_node_evidence\(/gu, "load_peer_evidence(") });
  plant("a membership seam whose named gap is no longer where the drill anchors it (the gap must be re-measured, not assumed)", f.includes("membership_seam_gap_not_anchored"), f[0]);
  const fake = verdict(CLAUSES.map((c) => ({ n: c.n, executed: [{ script: "x", status: 0, evidence: null, evidence_sha256: null }] })));
  plant("a run whose every clause reports success without evidence", fake.kind === "fail" && fake.failures.every((x) => /fabricated/u.test(x)), fake.failures[0]);
  const shrunk = verdict(CLAUSES.map((c) => ({ n: c.n, executed: [{ script: "x", status: 0, evidence: "x", evidence_sha256: "ab", executed_assertions: 1, floor_expected: 100 }] })));
  plant("a run whose gate census fell below its pinned floor", shrunk.kind === "fail" && /below_floor/u.test(shrunk.failures[0]), shrunk.failures[0]);
  evidence.mutation = rows;
  const detected = rows.filter((r) => r.detected).length;
  console.log(`\nMUTATION ${detected}/${rows.length} planted defects detected`);
  return detected === rows.length;
}

// ---- the storage-continuity leg ---------------------------------------------------------------------------
// Two isolated daemons, one Agentgres log, one substrate-replica peer. Every claim below is a storage-
// layer claim (replicated_same_host); the System layer is named, not claimed.
async function storageContinuity() {
  const rows = [];
  const sok = (name, cond, detail) => { const row = { name, pass: !!cond, detail: detail == null ? "" : String(detail), at: new Date().toISOString() }; rows.push(row); console.log(`${row.pass ? "PASS" : "FAIL"}  [storage] ${name}${row.detail ? ` — ${row.detail.slice(0, 200)}` : ""}`); return row.pass; };
  const inHarness = !!process.env.IOI_EGRESS_HARNESS_ISOLATION;
  if (!fs.existsSync(REPLICA_BIN)) {
    if (inHarness) blocked(`substrate-replica absent at ${REPLICA_BIN} (the harness must not build)`);
    const build = spawnSync("cargo", ["build", "-p", "agentgres", "--bin", "substrate-replica"], { cwd: ROOT, encoding: "utf8" });
    if (build.status !== 0) blocked(`cargo build -p agentgres --bin substrate-replica failed: ${String(build.stderr).slice(-400)}`);
  }
  const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
  if (!fs.existsSync(daemonBinary)) blocked(`daemon binary absent at ${daemonBinary}`);
  process.env.IOI_HYPERVISOR_DAEMON_BINARY = daemonBinary;
  const baseEnv = sanitizedVerifierBaseEnv();
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-h2-storage-"));
  const replicaDir = path.join(workDir, "replica");
  fs.mkdirSync(replicaDir);
  const port = await freePort();
  const addr = `127.0.0.1:${port}`;
  let replica = null;
  let replicaLog = "";
  const startReplica = async () => {
    replica = spawn(REPLICA_BIN, [], { env: { ...baseEnv, REPLICA_ADDR: addr, REPLICA_DIR: replicaDir, FLUSH_MS: "50" }, stdio: ["ignore", "pipe", "pipe"] });
    replica.stdout.on("data", (c) => { replicaLog += c; });
    replica.stderr.on("data", (c) => { replicaLog += c; });
    for (let i = 0; i < 100; i += 1) {
      const up = await new Promise((resolve) => { const s = net.connect(port, "127.0.0.1"); s.once("connect", () => { s.destroy(); resolve(true); }); s.once("error", () => resolve(false)); });
      if (up) return true;
      await sleep(100);
    }
    return false;
  };
  const stopReplica = async () => { if (!replica) return; const gone = new Promise((r) => replica.once("exit", r)); replica.kill("SIGTERM"); await Promise.race([gone, sleep(5000)]); replica = null; };
  const env = { IOI_SUBSTRATE_REPLICA_ADDRS: addr, IOI_SUBSTRATE_DUAL_WRITE: "1", IOI_SUBSTRATE_DUAL_WRITE_DOMAINS: "projects" };
  const muxOf = (dir) => path.join(dir, "muxlog.bin");
  const engineOf = (dataDir) => path.join(dataDir, "substrate");
  const bytes = (f) => (fs.existsSync(f) ? fs.statSync(f).size : -1);
  const daemonLogOf = (plane) => fs.readdirSync(plane.dataDir).filter((f) => f.startsWith("isolated-daemon") && f.endsWith(".log")).map((f) => fs.readFileSync(path.join(plane.dataDir, f), "utf8")).join("\n");
  const jd = async (plane, p, init = {}, cookie = "") => { const r = await fetch(`${plane.daemonUrl}${p}`, { ...init, headers: { "content-type": "application/json", ...(cookie ? { cookie: `ioi_session=${cookie}` } : {}) } }); return { status: r.status, body: await r.json().catch(() => ({})) }; };
  const bootstrap = async (plane) => {
    const token = daemonLogOf(plane).match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1);
    const boot = await jd(plane, "/v1/hypervisor/auth/bootstrap", { method: "POST", body: JSON.stringify({ token, password: "horizon-2-storage-pass", email: "horizon-2@ioi.local" }) });
    return boot.body?.session_token || boot.body?.session?.token || "";
  };
  const roots = (status) => Object.fromEntries(Object.entries(status?.engine_domains ?? {}).map(([d, v]) => [d, typeof v === "object" ? v.root : v]));
  let planeA = null;
  let planeB = null;
  let cookie = "";
  try {
    sok("PRECONDITION: the substrate-replica peer listens on loopback with its own directory", await startReplica(), `${addr} → ${replicaDir}`);
    const dataDirA = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-h2-daemon-a-"));
    planeA = await startIsolatedPlane({ dataDir: dataDirA, baseEnv, env, serve: false });
    if (!planeA) blocked("daemon A could not start");
    cookie = await bootstrap(planeA);
    const s0 = (await jd(planeA, "/v1/hypervisor/substrate/status", {}, cookie)).body ?? {};
    sok("daemon A declares its replica in its own substrate status — configured, NOT declared failure-independent (same host): the durability class this run can claim is replicated_same_host, never quorum_replicated", cookie.startsWith("ioi_sess_") && Array.isArray(s0.replication?.configured_replicas) && s0.replication.configured_replicas.includes(addr) && s0.replication.declared_failure_independent === false, `${JSON.stringify(s0.replication?.configured_replicas)} · independent=${s0.replication?.declared_failure_independent}`);
    for (let i = 1; i <= 3; i += 1) await jd(planeA, "/v1/hypervisor/projects", { method: "POST", body: JSON.stringify({ repository_url: `https://example.invalid/h2-${i}.git`, project_name: `h2-${i}` }) }, cookie);
    await sleep(600);
    const a1 = bytes(muxOf(engineOf(dataDirA)));
    const r1 = bytes(muxOf(replicaDir));
    sok("PRECONDITION: under the declared dual-write soak (projects) three admitted project records reach A's engine log", a1 > 0, `A muxlog ${a1} bytes`);
    sok("S1 — admitted batches are SHIPPED before ack: the replica's log is byte-identical to the primary's (same sha256, same length)", a1 > 0 && r1 === a1 && sha256File(muxOf(replicaDir)) === sha256File(muxOf(engineOf(dataDirA))), `A ${a1} · replica ${r1} · sha ${(sha256File(muxOf(replicaDir)) || "").slice(0, 12)}`);
    await stopReplica();
    for (let i = 4; i <= 5; i += 1) await jd(planeA, "/v1/hypervisor/projects", { method: "POST", body: JSON.stringify({ repository_url: `https://example.invalid/h2-${i}.git`, project_name: `h2-${i}` }) }, cookie);
    await sleep(300);
    const a2 = bytes(muxOf(engineOf(dataDirA)));
    const r2 = bytes(muxOf(replicaDir));
    sok("S2 — link failure: with the peer DOWN the primary keeps admitting (two more records) and the peer falls behind — durability is degraded loudly, never faked", a2 > a1 && r2 === r1, `A ${a2} · replica ${r2}`);
    sok("PRECONDITION: the peer restarts on the same address and directory", await startReplica(), addr);
    await planeA.stop();
    planeA = await startIsolatedPlane({ dataDir: dataDirA, baseEnv, env, serve: false });
    if (!planeA) blocked("daemon A could not restart");
    await sleep(800);
    const r3 = bytes(muxOf(replicaDir));
    const a3 = bytes(muxOf(engineOf(dataDirA)));
    sok("S3 — CATCH-UP by offset: at the primary's next handshake the replica's shorter log receives the gap and is byte-identical again, and the primary's log records no 'unreachable' peer", r3 === a3 && a3 >= a2 && sha256File(muxOf(replicaDir)) === sha256File(muxOf(engineOf(dataDirA))) && !/unreachable/u.test(daemonLogOf(planeA).split("isolated-daemon-restart").pop() || ""), `A ${a3} · replica ${r3}`);
    const sA = (await jd(planeA, "/v1/hypervisor/substrate/status", {}, cookie)).body ?? {};
    const rootsA = roots(sA);
    await planeA.stop();
    await stopReplica();
    const promo = spawnSync(REPLICA_BIN, ["promote"], { env: { ...baseEnv, REPLICA_DIR: replicaDir }, encoding: "utf8" });
    let record = null;
    try { record = JSON.parse(promo.stdout); } catch { record = null; }
    fs.writeFileSync(path.join(workDir, "promotion-record.json"), promo.stdout || "");
    sok("S4 — OPERATOR PROMOTION: substrate-replica promote mints the durable ioi.agentgres.writer-promotion.v1 record at epoch+1 (prior 0 → new 1) with the domain roots it carries, written as a checkpoint file", promo.status === 0 && record?.record === "ioi.agentgres.writer-promotion.v1" && record?.prior_epoch === 0 && record?.new_epoch === 1 && fs.existsSync(path.join(replicaDir, "checkpoints", "promotion-epoch-000001.json")), `${promo.status} ${JSON.stringify(record?.domain_roots ?? {}).slice(0, 120)}`);
    const dataDirB = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-h2-daemon-b-"));
    fs.cpSync(replicaDir, engineOf(dataDirB), { recursive: true });
    planeB = await startIsolatedPlane({ dataDir: dataDirB, baseEnv, env: {}, serve: false });
    if (!planeB) blocked("daemon B could not start on the promoted replica directory");
    const sB = (await jd(planeB, "/v1/hypervisor/substrate/status")).body ?? {};
    const rootsB = roots(sB);
    const sameRoots = Object.keys(rootsA).length > 0 && JSON.stringify(rootsA) === JSON.stringify(rootsB) && Object.entries(record?.domain_roots ?? {}).every(([d, v]) => rootsB[d] === (typeof v === "object" ? v.root ?? JSON.stringify(v) : v) || JSON.stringify(rootsB[d]) === JSON.stringify(v));
    sok("S5 — a SECOND daemon opened on the promoted directory replays the same engine truth: its domain roots equal the primary's last-served roots and the promotion record's, with no open error", sameRoots && !sB.engine_open_error, `A ${JSON.stringify(rootsA).slice(0, 100)} · B ${JSON.stringify(rootsB).slice(0, 100)}`);
    await planeB.stop();
    sok("PRECONDITION: the peer restarts on the promoted directory (max epoch 1)", await startReplica(), addr);
    planeA = await startIsolatedPlane({ dataDir: dataDirA, baseEnv, env, serve: false });
    if (!planeA) blocked("daemon A (deposed) could not restart");
    await sleep(500);
    const logA = daemonLogOf(planeA).split("isolated-daemon-restart").pop() || daemonLogOf(planeA);
    const fenced = /FENCED at handshake/u.test(daemonLogOf(planeA)) && /deposed/u.test(daemonLogOf(planeA)) && /continuing without it/u.test(daemonLogOf(planeA));
    sok("S6 — the DEPOSED primary (still at epoch 0) is FENCED at its next handshake by name ('this writer is deposed') and continues LOUDLY without its replica — a stale writer can never split the brain on the peer", fenced, fenced ? "fenced at handshake" : logA.slice(-300));
    const rBefore = bytes(muxOf(replicaDir));
    await jd(planeA, "/v1/hypervisor/projects", { method: "POST", body: JSON.stringify({ repository_url: "https://example.invalid/h2-deposed.git", project_name: "h2-deposed" }) }, cookie);
    await sleep(400);
    const rAfter = bytes(muxOf(replicaDir));
    const aAfter = bytes(muxOf(engineOf(dataDirA)));
    sok("S7 — NO DUAL EFFECT at the peer: a record the deposed primary admits afterwards lands in its own log and never in the promoted peer's", aAfter > a3 && rAfter === rBefore, `A ${aAfter} · replica ${rBefore} → ${rAfter}`);
  } finally {
    try { await planeA?.stop(); } catch { /* gone */ }
    try { await planeB?.stop(); } catch { /* gone */ }
    await stopReplica();
  }
  const leg = { work_dir: workDir, replica_addr: addr, rows, passed: rows.filter((r) => r.pass).length, total: rows.length, replica_log_tail: replicaLog.slice(-600) };
  evidence.storage = leg;
  const file = path.join(workDir, "storage-continuity-evidence.json");
  fs.writeFileSync(file, `${JSON.stringify(leg, null, 2)}\n`);
  console.log(`\nstorage continuity: ${leg.passed}/${leg.total} · evidence ${file}`);
  return { ok: leg.passed === leg.total, file, leg };
}

// ---- the full gate ----------------------------------------------------------------------------------------
async function runGate(g, workDir, floors, n) {
  const label = `${n}-${(g.floor || g.script).replace(/[^A-Za-z0-9]+/gu, "-")}`;
  const censusDir = path.join(workDir, "census", label);
  fs.mkdirSync(censusDir, { recursive: true });
  const env = { ...sanitizedVerifierBaseEnv(), ...process.env, IOI_VERIFIER_CENSUS_DIR: path.relative(ROOT, censusDir), CARGO_NET_OFFLINE: "true", IOI_ISOLATED_DAEMON_READY_TIMEOUT_MS: process.env.IOI_ISOLATED_DAEMON_READY_TIMEOUT_MS || "120000", IOI_WALLET_FIXTURE_READY_TIMEOUT_MS: process.env.IOI_WALLET_FIXTURE_READY_TIMEOUT_MS || "1200000" };
  const argvRun = g.kind === "storage" ? [process.execPath, SELF, "--storage", "--evidence", path.relative(ROOT, path.join(censusDir, "storage.json"))] : ["npm", "run", "-s", g.script, ...(g.workspace ? [`--workspace=${g.workspace}`] : [])];
  const iso = await runIsolated({ label, argv: argvRun, cwd: ROOT, env, workDir, bridges: [], timeoutMs: g.minutes * 60_000 });
  const classified = classifyLedger(iso.ledger, { declaredHosts: [], declaredNames: [] });
  const logFile = path.join(workDir, `${label}.log`);
  const files = fs.existsSync(censusDir) ? fs.readdirSync(censusDir).filter((f) => f.endsWith(".json")).map((f) => path.join(censusDir, f)) : [];
  const evidenceFile = files[0] || (fs.existsSync(logFile) ? logFile : null);
  const floorRow = g.floor ? (floors.verifiers ?? []).find((r) => r.id === g.floor) : null;
  const censusJson = files[0] ? readJson(files[0]) : null;
  return { script: g.script, kind: g.kind, status: iso.status, seconds: iso.seconds, isolation: iso.isolation, ledger: { attempts: classified.counts?.attempts ?? 0, loopback: classified.counts?.loopback ?? 0, reach: (classified.undeclared?.length ?? 0) + (classified.undeclared_names?.length ?? 0) }, evidence: evidenceFile ? path.relative(ROOT, evidenceFile) : null, evidence_sha256: evidenceFile ? sha256File(evidenceFile) : null, executed_assertions: censusJson?.executed_assertions ?? (g.kind === "storage" ? censusJson?.storage?.passed ?? null : null), floor_expected: floorRow?.runtime_assertions ?? null };
}
async function full() {
  const probe = probeIsolation();
  if (!probe.strace.available) blocked(`the harness cannot record: ${probe.strace.detail}`);
  const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
  if (!fs.existsSync(daemonBinary)) blocked(`daemon binary absent at ${daemonBinary} (the harness must not build)`);
  if (!fs.existsSync(REPLICA_BIN)) blocked(`substrate-replica absent at ${REPLICA_BIN} (the harness must not build)`);
  process.env.IOI_HYPERVISOR_DAEMON_BINARY = daemonBinary;
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-horizon-2-"));
  const floors = readJson(FLOORS);
  evidence.host = { isolation: probe.isolation, strace: probe.strace.version, load: os.loadavg().map((n) => n.toFixed(2)), daemon_binary: daemonBinary, work_dir: workDir };
  console.log(`\n# the full gate: isolation ${probe.isolation}; work dir ${workDir}`);
  const done = new Map();
  const rows = [];
  for (const c of CLAUSES) {
    const row = { n: c.n, demand: c.demand, executed: [], absence: c.absence || null };
    for (const g of c.executed_by ?? []) {
      if (ONLY && !ONLY.has(c.n)) { row.not_executed = `${g.script} (--only)`; continue; }
      if (!done.has(g.script)) {
        console.log(`\n# ${g.script} — inside the harness (clause ${c.n}${CLAUSES.filter((x) => x.n !== c.n && (x.executed_by ?? []).some((y) => y.script === g.script)).map((x) => `, ${x.n}`).join("")})`);
        done.set(g.script, await runGate(g, workDir, floors, c.n));
        const r = done.get(g.script);
        console.log(`  → exit ${r.status} in ${r.seconds}s · ${r.executed_assertions ?? "?"}${r.floor_expected != null ? `/${r.floor_expected}` : ""} · ledger ${r.ledger.attempts} attempts, ${r.ledger.loopback} loopback, ${r.ledger.reach} reach`);
      }
      row.executed.push(done.get(g.script));
    }
    rows.push(row);
  }
  const v = verdict(rows);
  v.absences.push({ n: 0, ...OUT_OF_SCOPE });
  if (v.kind === "pass") v.kind = "named_failure";
  evidence.clauses = rows;
  evidence.verdict = v;
  const seen = new Set();
  const runs = rows.flatMap((r) => r.executed).filter((g) => !seen.has(g.script) && seen.add(g.script));
  evidence.network_blocked_completion = { runs: runs.length, attempts: runs.reduce((a, g) => a + g.ledger.attempts, 0), reach: runs.reduce((a, g) => a + g.ledger.reach, 0) };
  console.log(`\n=== VERDICT: ${v.kind.toUpperCase()}${v.failures.length ? ` — ${v.failures.join(" ; ")}` : ""}`);
  for (const a of v.absences) console.log(`NAMED  ${a.n ? `clause ${a.n}` : "scope"}: ${a.what.slice(0, 160)} → owner ${a.owner}`);
  return v;
}

// ---- main -------------------------------------------------------------------------------------------------
(async () => {
  let exit = 0;
  if (MODE === "mutation") exit = mutation() ? 0 : 1;
  else if (MODE === "storage") { const r = await storageContinuity(); exit = r.ok ? 0 : 1; }
  else {
    drills();
    const fails = results.filter((r) => !r.pass);
    console.log(`\n${results.length - fails.length}/${results.length} drills passed`);
    emitVerifierCensus({ verifierId: "horizon-2-distributed-work", sourceUrl: import.meta.url, results });
    if (fails.length) exit = 1;
    else if (MODE === "full") { const v = await full(); exit = v.kind === "pass" ? 0 : v.kind === "named_failure" ? 2 : 1; }
  }
  const file = writeEvidence();
  console.log(`evidence: ${path.relative(ROOT, file)}`);
  process.exit(exit);
})().catch((error) => { console.error("verifier crashed:", error); writeEvidence(); process.exit(1); });
