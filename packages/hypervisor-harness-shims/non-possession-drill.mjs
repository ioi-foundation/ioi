#!/usr/bin/env node
// non-possession-drill — a HARNESS that does no work and only LOOKS. Spawned by the daemon's
// host_spawn lane exactly like the generic shim (same argv contract, same stdin intent, same
// __HYPERVISOR_HARNESS_RESULT__ sentinel), it probes, from inside the session's own process, every
// place M03.13 / ACC-15 N3 say a credential must not be observable, and writes what it found to
// `non-possession-probes.json` in the workspace for the verifier to read. It never prints a value it
// finds: only names, counts and booleans leave this process.
//
//   env        — the names this process was given, and whether any secret-shaped name is among them;
//   parent     — /proc/<ppid>/environ (the daemon's own environment block as the kernel exposes it
//                to a same-uid reader): whether it is readable at all, and whether any planted
//                needle or secret-shaped assignment appears in it;
//   tree       — a bounded walk from the workspace up to the daemon's data dir (the workspace lives
//                inside it on the supported profile): whether any regular file contains a planted
//                needle in plaintext;
//   broker     — the daemon's brokered surfaces answer a bare request (no token, no session) with a
//                refusal, never with a secret or a success;
//   ptrace     — the host's yama ptrace_scope, recorded as a measured precondition (0 would let a
//                same-uid process read the parent's memory; ≥1 confines it to descendants).
//
// Needle VALUES reach this harness only through `non-possession-needles.txt` in its own workspace,
// written there by the verifier (the daemon never hands them over; an environment carrying them
// would itself be a finding). The daemon's address is not given to the harness either: like an
// adversarial harness would, the drill takes it from the parent's /proc environ (a non-secret) to
// probe the brokered surfaces.
import fs from "node:fs";
import path from "node:path";

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : undefined; };
const workspace = opt("cd") ?? process.cwd();
const model = opt("model") ?? "drill";
const upstream = (process.env.IOI_HYPERVISOR_MODEL_UPSTREAM || "").replace(/\/+$/u, "");
const SECRET_SHAPE = /(API_KEY|_SECRET|_PASS(WORD)?|_TOKEN|PRIVATE_KEY|SEED)$/u;

function probe() {
  let needles = [];
  try { needles = fs.readFileSync(path.join(workspace, "non-possession-needles.txt"), "utf8").split(",").map((s) => s.trim()).filter(Boolean); } catch { needles = []; }
  const out = { schema: "ioi.hypervisor.non-possession-probes.v1", at: new Date().toISOString(), pid: process.pid, ppid: process.ppid, uid: process.getuid?.(), needles_known_to_harness: needles.length, model };
  // env
  const names = Object.keys(process.env).sort();
  out.env = { names, secret_shaped: names.filter((n) => SECRET_SHAPE.test(n) && n !== "IOI_HYPERVISOR_MODEL_TOKEN"), run_scoped_model_token_present: "IOI_HYPERVISOR_MODEL_TOKEN" in process.env, needle_values_present: needles.some((v) => Object.values(process.env).some((x) => String(x).includes(v))) };
  // parent environ
  const parent = { readable: false, bytes: 0, assignments: 0, secret_shaped_assignments: [], needle_present: false, error: null };
  try {
    const raw = fs.readFileSync(`/proc/${process.ppid}/environ`);
    parent.readable = true; parent.bytes = raw.length;
    const text = raw.toString("utf8");
    const entries = text.split("\0").filter(Boolean);
    parent.assignments = entries.length;
    parent.secret_shaped_assignments = entries.map((e) => e.split("=")[0]).filter((n) => SECRET_SHAPE.test(n)).filter((n, i, a) => a.indexOf(n) === i);
    parent.needle_present = needles.some((v) => text.includes(v));
    parent.daemon_addr = (entries.find((e) => e.startsWith("IOI_HYPERVISOR_DAEMON_ADDR=")) || "").split("=").slice(1).join("=") || null;
  } catch (error) { parent.error = String(error?.code || error?.message || error); }
  out.parent = parent;
  // tree walk (bounded): from the workspace up three levels (data dir on the supported profile)
  const root = path.resolve(workspace, "..", "..", "..");
  const tree = { root, files: 0, bytes: 0, needle_files: [], errors: 0, capped: false };
  const walk = (dir, depth) => {
    if (tree.files > 20000 || tree.bytes > 512 * 1024 * 1024) { tree.capped = true; return; }
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { tree.errors += 1; return; }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { if (depth < 12) walk(p, depth + 1); continue; }
      if (!e.isFile()) continue;
      if (e.name === "non-possession-needles.txt") continue;
      try { const st = fs.statSync(p); if (st.size > 8 * 1024 * 1024) continue; const buf = fs.readFileSync(p); tree.files += 1; tree.bytes += buf.length; if (needles.some((v) => buf.includes(v))) tree.needle_files.push(path.relative(root, p)); } catch { tree.errors += 1; }
    }
  };
  if (needles.length) walk(root, 0);
  out.tree = tree;
  return out;
}

async function brokerProbes(daemonAddr) {
  const broker = { upstream, daemon: daemonAddr ? `http://${daemonAddr}` : null, chat_without_token: null, routes_read: null, receipts_list: null };
  const call = async (url, init) => { try { const r = await fetch(url, { ...init, signal: AbortSignal.timeout(8000) }); const text = await r.text(); return { status: r.status, bytes: text.length, has_secret_shape: /sk-[A-Za-z0-9]{8,}|sealed_token|ioi_mnt_[a-f0-9]{16,}/u.test(text) }; } catch (error) { return { status: 0, error: String(error?.code || error?.message || error) }; } };
  if (broker.daemon) {
    broker.chat_without_token = await call(`${broker.daemon}/v1/chat/completions`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ model, messages: [{ role: "user", content: "probe" }] }) });
    broker.routes_read = await call(`${broker.daemon}/v1/hypervisor/model-routes`, { method: "GET" });
    broker.receipts_list = await call(`${broker.daemon}/v1/model-mount/receipts`, { method: "GET" });
  }
  return broker;
}

async function main() {
  console.log(`non-possession drill ready: workspace=${workspace} model=${model}`);
  const lines = [];
  process.stdin.setEncoding("utf8");
  await new Promise((resolve) => { process.stdin.on("data", (chunk) => { for (const line of chunk.split(/\r?\n/u)) { if (line.trim()) lines.push(line.trim()); if (line.trim() === "/exit" || lines.length) resolve(); } }); process.stdin.on("end", resolve); setTimeout(resolve, 30000); });
  const findings = probe();
  findings.broker = await brokerProbes(findings.parent?.daemon_addr || null);
  try { findings.ptrace_scope = fs.readFileSync("/proc/sys/kernel/yama/ptrace_scope", "utf8").trim(); } catch { findings.ptrace_scope = null; }
  const file = path.join(workspace, "non-possession-probes.json");
  fs.writeFileSync(file, `${JSON.stringify(findings, null, 2)}\n`);
  console.log(`__HYPERVISOR_HARNESS_RESULT__ ${JSON.stringify({ ok: true, summary: "non-possession probes written", files_written: ["non-possession-probes.json"] })}`);
  process.exit(0);
}
main().catch((error) => { console.error(`drill failed: ${error?.message || error}`); console.log(`__HYPERVISOR_HARNESS_RESULT__ ${JSON.stringify({ ok: false, error: "drill_failed", files_written: [] })}`); process.exit(1); });
