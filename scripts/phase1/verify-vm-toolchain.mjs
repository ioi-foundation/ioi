#!/usr/bin/env node
// T3 — VM toolchain verifier. Proves a provisioned ~/.ioi/vm-toolchain is reproducible + intact:
// every supply-manifest entry exists, sha256 matches the pin, binaries are executable, the
// guest-agent compiled artifact traces to committed source, and host capabilities are reported
// present/absent with an exact reason (so monitor lanes fail closed, never fake).
//
// Usage: node scripts/phase1/verify-vm-toolchain.mjs [--dir <toolchain-dir>] [--json]
import { execSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";

const args = process.argv.slice(2);
const JSON_OUT = args.includes("--json");
const DIR = (args[args.indexOf("--dir") + 1] && !args[args.indexOf("--dir") + 1]?.startsWith("--") ? args[args.indexOf("--dir") + 1] : null)
  || process.env.IOI_VM_TOOLCHAIN_DIR || join(homedir(), ".ioi/vm-toolchain");
const REPO = new URL("../..", import.meta.url).pathname;

const sha = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
const checks = [];
const ok = (cond, msg, detail) => checks.push({ ok: !!cond, msg, detail: detail || "" });

const manifestPath = join(DIR, "supply-manifest.json");
if (!existsSync(manifestPath)) {
  const out = { dir: DIR, verdict: "FAIL", reason: "supply-manifest.json missing — run scripts/phase1/provision-vm-toolchain.sh" };
  console.log(JSON_OUT ? JSON.stringify(out, null, 2) : `VM toolchain: FAIL — ${out.reason}`);
  process.exit(1);
}
const m = JSON.parse(readFileSync(manifestPath, "utf8"));

// pinned artifacts: every entry must exist + match its recorded sha256.
const BINARIES = new Set(["monitor", "ch_remote", "firecracker", "guest_agent"]);
for (const [key, entry] of Object.entries(m)) {
  if (!entry || typeof entry !== "object" || !entry.path) continue;
  const path = entry.path;
  const want = entry.sha256 || entry.binary_sha256;
  if (!existsSync(path)) { ok(false, `${key} present`, `${path} missing`); continue; }
  ok(true, `${key} present`);
  if (want) ok(sha(path) === want, `${key} sha256 matches pin`, want.slice(0, 12));
  if (BINARIES.has(key)) ok((statSync(path).mode & 0o111) !== 0, `${key} executable`);
}
// guest-agent compiled artifact traces to committed source.
const agentSrc = join(REPO, "scripts/phase1/guest-agent.c");
if (m.guest_agent?.source_sha256 && existsSync(agentSrc)) {
  ok(sha(agentSrc) === m.guest_agent.source_sha256, "guest-agent binary traces to committed source", m.guest_agent.source_sha256.slice(0, 12));
}

// host capabilities — present/absent with reason (monitor lanes gate on these).
const cap = (name, present, reason) => ({ name, present, reason });
const has = (bin) => { try { execSync(`command -v ${bin}`, { stdio: "ignore" }); return true; } catch { return false; } };
const caps = [
  cap("kvm", existsSync("/dev/kvm"), existsSync("/dev/kvm") ? "/dev/kvm present" : "/dev/kvm absent (no hardware virt)"),
  cap("vhost_vsock", existsSync("/dev/vhost-vsock"), existsSync("/dev/vhost-vsock") ? "present" : "absent (QEMU vsock lane host-gated; needs root modprobe vhost_vsock)"),
  cap("bwrap", has("bwrap"), has("bwrap") ? "present" : "absent"),
  cap("qemu", has("qemu-system-x86_64"), has("qemu-system-x86_64") ? "present" : "absent (QEMU lane host-gated)"),
  cap("cgroup_v2", existsSync("/sys/fs/cgroup/cgroup.controllers"), existsSync("/sys/fs/cgroup/cgroup.controllers") ? "present" : "absent"),
];

const failed = checks.filter((c) => !c.ok);
const verdict = failed.length === 0 ? "PASS" : "FAIL";
const monitorReadiness = {
  "cloud-hypervisor": existsSync("/dev/kvm") ? "READY" : "HOST_GATED:no-kvm",
  firecracker: existsSync("/dev/kvm") ? "READY" : "HOST_GATED:no-kvm",
  qemu: existsSync("/dev/kvm") && existsSync("/dev/vhost-vsock") && has("qemu-system-x86_64") ? "READY" : "HOST_GATED:needs qemu+vhost_vsock",
};

const report = { dir: DIR, manifest_version: m.schema_version, verdict, checks, host_capabilities: caps, monitor_readiness: monitorReadiness };
if (JSON_OUT) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log(`VM toolchain @ ${DIR}`);
  for (const c of checks) console.log(`  ${c.ok ? "✓" : "✗"} ${c.msg}${c.detail ? ` (${c.detail})` : ""}`);
  console.log(`  host capabilities:`);
  for (const c of caps) console.log(`    ${c.present ? "•" : "·"} ${c.name}: ${c.reason}`);
  console.log(`  monitor readiness: ${Object.entries(monitorReadiness).map(([k, v]) => `${k}=${v}`).join("  ")}`);
  console.log(`  VERDICT: ${verdict}`);
}
process.exit(verdict === "PASS" ? 0 : 1);
