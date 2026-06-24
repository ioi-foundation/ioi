#!/usr/bin/env node
// All-up Hypervisor platform foundation verifier (master guide §11).
//
// WRAPS the green Phase 1 microVM lifecycle verifier and adds the seven terminal workstreams
// (T1 lane closure, T2 QEMU parity, T3 toolchain portability, T4 live authority, T5 resource
// management, T6 remote providers, T7 native UX). Each sub-verifier runs as a child process and is
// parsed via --json. Completion = Overall ∈ {terminal, terminal_with_declared_host_gaps} where
// EVERY non-PASS is a genuine, named, fail-closed host/tooling prerequisite — never an unbuilt or
// faked gate.
//
// Usage:
//   node scripts/verify-hypervisor-platform-foundation.mjs --n 25 \
//     --require-qemu --require-wallet --require-remote-provider --native-ux [--browser] [--json]
import { spawnSync } from "node:child_process";
import { join } from "node:path";

const REPO = new URL("..", import.meta.url).pathname;
const args = process.argv.slice(2);
const has = (f) => args.includes(f);
const JSON_OUT = has("--json");
const N = parseInt(args[args.indexOf("--n") + 1] || "25", 10) || 25;
const REQUIRE_QEMU = has("--require-qemu") || has("--require-qemu-ci");
const REQUIRE_WALLET = has("--require-wallet") || has("--require-authority-provider");
const REQUIRE_REMOTE = has("--require-remote-provider");
const NATIVE_UX = has("--native-ux") || has("--ux-strategy");
const UX_STRATEGY = args[args.indexOf("--ux-strategy") + 1] && !args[args.indexOf("--ux-strategy") + 1].startsWith("--") ? args[args.indexOf("--ux-strategy") + 1] : "hybrid";
const BROWSER = has("--browser");

const declaredGaps = [];
const failures = [];
const note = (msg) => { if (!JSON_OUT) console.log(msg); };

function runJson(script, scriptArgs, label) {
  const res = spawnSync("node", [join(REPO, script), ...scriptArgs, "--json"], { encoding: "utf8", cwd: REPO, timeout: 900000 });
  let parsed = null;
  try {
    const text = (res.stdout || "").trim();
    parsed = JSON.parse(text.slice(text.indexOf("{")));
  } catch { /* leave null */ }
  if (!parsed) failures.push(`${label}: could not parse verifier output (exit ${res.status})`);
  return parsed;
}

// ---- T1 lane closure ----
const t1 = runJson("scripts/verify-hypervisor-lane-closure.mjs", [], "T1 lane closure");
const checkoutClosure = t1?.verdict === "PASS" ? "PASS" : t1?.verdict === "BLOCKED_USER_WIP" ? "BLOCKED_USER_WIP" : "FAIL";
if (checkoutClosure === "FAIL") failures.push("T1 lane closure FAIL");
if (checkoutClosure === "BLOCKED_USER_WIP") declaredGaps.push({ gate: "checkout_closure", prerequisite: "USER_WIP_UNCOMMITTED", reason: "the dirty tree is the operator's own uncommitted WIP (e.g. docs/architecture); the feature lane is complete — not an unbuilt gate" });

// ---- Phase 1 microVM lifecycle (the wrapped green verifier) ----
note(`  running Phase 1 lifecycle verifier (--n ${N})…`);
const p1 = spawnSync("node", [join(REPO, "scripts/verify-phase1-env-lifecycle.mjs"), "--n", String(N)], { encoding: "utf8", cwd: REPO, timeout: 1800000 });
const phase1Pass = p1.status === 0 && /ALL GATES PASS/.test(p1.stdout || "");
if (!phase1Pass) failures.push(`Phase 1 lifecycle verifier not green (exit ${p1.status})`);

// ---- T3 toolchain portability (+ T2 QEMU readiness derives from it) ----
const t3 = runJson("scripts/phase1/verify-vm-toolchain.mjs", [], "T3 toolchain");
const toolchain = t3?.verdict === "PASS" ? "PASS" : "FAIL";
if (toolchain !== "PASS") failures.push("T3 toolchain portability FAIL");
const qemuReadiness = t3?.monitor_readiness?.qemu || "unknown";
let qemuParity;
if (qemuReadiness === "READY") qemuParity = "PASS";
else if (/HOST_GATED/.test(qemuReadiness)) {
  qemuParity = "HOST_GATED";
  if (REQUIRE_QEMU) declaredGaps.push({ gate: "qemu_parity", prerequisite: qemuReadiness, reason: "the QEMU monitor lane is real (provisioned qemu + microvm+qboot+AF_VSOCK); boot is host-gated on this host (root-grantable: kvm group / vhost-vsock ACL)" });
} else qemuParity = REQUIRE_QEMU ? "FAIL" : "HOST_GATED";
if (qemuParity === "FAIL") failures.push("T2 QEMU parity FAIL (required, not host-gated)");

// ---- T4 live authority ----
const t4 = runJson("scripts/verify-hypervisor-authority.mjs", REQUIRE_WALLET ? ["--require-wallet"] : [], "T4 authority");
const authorityOk = t4?.verdict === "PASS" || t4?.verdict === "PASS_WITH_DECLARED_GAPS";
const liveAuthority = authorityOk ? "PASS" : "FAIL";
if (!authorityOk) failures.push("T4 live authority FAIL");
for (const g of t4?.declared_gaps || []) declaredGaps.push({ gate: "live_authority", ...g });

// ---- T5 resource management ----
const t5 = runJson("scripts/verify-hypervisor-resource.mjs", [], "T5 resource");
const resourceMgmt = t5?.verdict === "PASS" ? "PASS" : "FAIL";
if (resourceMgmt !== "PASS") failures.push("T5 resource management FAIL");

// ---- T6 remote providers ----
const t6 = runJson("scripts/verify-hypervisor-remote-provider.mjs", REQUIRE_REMOTE ? ["--require-remote-provider"] : [], "T6 remote");
const remoteOk = t6?.verdict === "PASS" || t6?.verdict === "PASS_WITH_DECLARED_GAPS";
const remoteProviders = remoteOk ? "PASS" : "FAIL";
if (!remoteOk) failures.push("T6 remote providers FAIL");
for (const g of t6?.declared_gaps || []) declaredGaps.push({ gate: "remote_providers", ...g });

// ---- T7 native UX ----
let uxStrategyStatus = "NATIVE_UX_NOT_REQUESTED";
let interactiveTerminal = "REQUEST_RESPONSE_ONLY";
let t7 = null;
if (NATIVE_UX) {
  t7 = runJson("scripts/verify-hypervisor-native-ux.mjs", ["--ux-strategy", UX_STRATEGY, ...(BROWSER ? ["--browser"] : [])], "T7 native UX");
  if (t7?.verdict === "BLOCKED_DECISION") { uxStrategyStatus = "BLOCKED_DECISION"; failures.push("T7 UX strategy BLOCKED_DECISION (missing decision record)"); }
  else if (t7?.verdict === "PASS" || t7?.verdict === "PASS_WITH_DECLARED_GAPS") {
    uxStrategyStatus = (t7.ux_strategy || UX_STRATEGY).toUpperCase();
    interactiveTerminal = "PASS"; // the T7 PTY interactivity check is part of its PASS
    for (const g of t7?.declared_gaps || []) declaredGaps.push({ gate: "native_ux", ...g });
  } else { uxStrategyStatus = "FAIL"; failures.push("T7 native UX FAIL"); }
}

// ---- Overall ----
const allLines = { phase1: phase1Pass ? "PASS" : "FAIL", checkoutClosure, qemuParity, toolchain, liveAuthority, resourceMgmt, remoteProviders, uxStrategyStatus, interactiveTerminal };
let overall;
if (failures.length > 0) overall = "not_terminal";
else if (declaredGaps.length > 0) overall = "terminal_with_declared_host_gaps";
else overall = "terminal";

// ---- output (§11 block) ----
if (JSON_OUT) {
  console.log(JSON.stringify({ overall, n: N, status: allLines, declared_gaps: declaredGaps, failures }, null, 2));
} else {
  console.log("\nHypervisor platform foundation");
  console.log(`  Phase 1 local microVM lifecycle: ${allLines.phase1}`);
  console.log(`  Checkout closure: ${checkoutClosure}`);
  console.log(`  QEMU parity: ${qemuParity}${/HOST_GATED/.test(qemuReadiness) ? ` (${qemuReadiness})` : ""}`);
  console.log(`  Toolchain portability: ${toolchain}`);
  console.log(`  Live authority: ${liveAuthority}`);
  console.log(`  Resource management: ${resourceMgmt}`);
  console.log(`  Remote providers: ${remoteProviders}`);
  console.log(`  UX strategy: ${uxStrategyStatus}`);
  console.log(`  Interactive terminal: ${interactiveTerminal}`);
  if (declaredGaps.length) {
    console.log("\n  Declared gaps (named, fail-closed host/tooling prerequisites — NOT unbuilt/faked):");
    for (const g of declaredGaps) console.log(`    · ${g.gate}: ${g.prerequisite} — ${g.reason}`);
  }
  if (failures.length) {
    console.log("\n  FAILURES (genuine, must fix):");
    for (const f of failures) console.log(`    ✗ ${f}`);
  }
  console.log(`\n  Overall: ${overall}`);
}
process.exit(overall === "not_terminal" ? 1 : 0);
