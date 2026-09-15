// egress-harness — the isolated-egress harness for the sovereign-local fixture (M12.1).
//
// Canon names the fixture (`embedded_single_operator_offline`, execution-horizons.md § Required
// sovereign-local fixture): every IOI-managed endpoint denied, loopback and explicit local IPC
// allowed, optional planes typed unavailable rather than fabricated. The daemon has ZERO hard-coded
// first-party hosts and seventy-one HTTP client sites, so egress is a RUNTIME measurement, never a
// grep. This module is that measurement, in two layers that fail independently and say which one
// they are:
//
//   REFUSAL   a nested user+network namespace. `unshare -r -n` creates a namespace whose only
//             interface is `lo`, brought up as mapped root; the work then drops back to the
//             operator's own uid through a second `unshare --map-user`, so nothing inside runs as
//             root and nothing inside can reach a non-loopback address — the KERNEL answers
//             ENETUNREACH before any packet exists.
//   RECORDING a seccomp-filtered `strace -f --seccomp-bpf -e trace=connect,sendto,sendmmsg` over
//             EVERY descendant process regardless of its environment. The daemon scrubs its
//             harness child's environment down to PATH/HOME/the model endpoint, which is exactly
//             where an LD_PRELOAD sink would have gone blind; a ptrace ledger does not. Untraced
//             syscalls run at native speed under the seccomp filter, so the ledger costs nothing
//             the journey would notice. The DNS question names are parsed from the ledger's own
//             bytes, so a name lookup for a first-party host is a finding even when no connect
//             follows it.
//
// Declared loopback dependencies the deployment needs from the HOST (Ollama at 127.0.0.1:11434)
// reach it through unix-socket bridges this module owns: a path-based unix socket is not
// network-namespaced, so the inner bridge listens on the fixture's loopback port and forwards to a
// socket the outer exporter connects onward to the real service. Every bridge connection is
// counted, and a bridge can be SEVERED on a trigger file — the in-flight stream destroyed and every
// later connect refused — which is how the negative half makes a declared dependency disappear
// mid-run without touching the deployment.
//
// Isolation is a TYPED property of every run (`refused_and_recorded` where unprivileged
// namespaces exist, `recorded_only` where they do not): the ledger proves zero reach either way,
// and only the refusal half is typed absent where the host refuses namespaces.

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const HERE = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.resolve(HERE, "..", "..");
const INNER = path.join(HERE, "egress-harness-inner.mjs");

export const STRACE_ARGS = ["-f", "--seccomp-bpf", "-qq", "-s", "160", "-e", "trace=connect,sendto,sendmmsg", "-e", "signal=none"];

/** Whether a host string names loopback (127.0.0.0/8, ::1, 0.0.0.0, localhost). */
export function isLoopbackHost(host) {
  const h = String(host || "").replace(/^\[|\]$/gu, "").toLowerCase();
  return h === "localhost" || h === "::1" || h === "0.0.0.0" || h.startsWith("127.") || h === "::ffff:127.0.0.1" || h.startsWith("::ffff:127.");
}

/**
 * Probe what this host can give the harness: strace (recording) and unprivileged nested
 * namespaces (refusal). Never throws; the answer is the typed isolation property.
 */
export function probeIsolation() {
  const uid = process.getuid();
  const gid = process.getgid();
  const st = spawnSync("strace", ["-V"], { encoding: "utf8", timeout: 10_000 });
  const straceLine = st.status === 0 ? String(st.stdout || "").split("\n")[0].trim() : null;
  const straceVersion = straceLine ? Number((straceLine.match(/version\s+(\d+(?:\.\d+)?)/u) || [])[1] || 0) : 0;
  const strace = { available: !!straceLine && straceVersion >= 5.3, version: straceLine, detail: straceLine ? (straceVersion >= 5.3 ? "seccomp-bpf filtering available" : `strace ${straceVersion} lacks --seccomp-bpf (needs ≥ 5.3)`) : "strace is not installed" };
  const ns = spawnSync("unshare", ["-r", "-n", "sh", "-c", `ip link set lo up && exec unshare --map-user=${uid} --map-group=${gid} id -u`], { encoding: "utf8", timeout: 15_000 });
  const network_namespace = ns.status === 0 && String(ns.stdout || "").trim() === String(uid);
  const nsDetail = network_namespace
    ? "unshare -r -n (loopback only, brought up as mapped root) then --map-user back to the operator's uid"
    : `unshare refused: ${String(ns.stderr || ns.stdout || ns.error?.message || "").trim().slice(0, 200) || `exit ${ns.status}`}`;
  const isolation = strace.available ? (network_namespace ? "refused_and_recorded" : "recorded_only") : "none";
  return { uid, gid, strace, network_namespace, network_namespace_detail: nsDetail, isolation };
}

/**
 * The OUTER half of a bridge: a unix-socket server in the host's network namespace that forwards
 * each connection to a real TCP service (the declared dependency, e.g. Ollama).
 */
export function startUnixExporter({ socketPath, host, port }) {
  try { fs.rmSync(socketPath, { force: true }); } catch { /* none */ }
  const stats = { socket_path: socketPath, target: `${host}:${port}`, connections: 0, failures: 0 };
  const server = net.createServer((client) => {
    stats.connections += 1;
    const up = net.connect({ host, port });
    const done = () => { client.destroy(); up.destroy(); };
    up.on("error", () => { stats.failures += 1; done(); });
    client.on("error", done);
    up.on("close", done);
    client.on("close", done);
    client.pipe(up);
    up.pipe(client);
  });
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(socketPath, () => resolve({
      stats,
      close: () => new Promise((r) => { server.close(() => { try { fs.rmSync(socketPath, { force: true }); } catch { /* none */ } r(); }); }),
    }));
  });
}

// ------------------------------------------------------------------------------ the ledger
// strace renders non-printable bytes as C escapes (\7, \n, \", \\, \xHH). Undo them.
function unescapeStraceString(text) {
  const out = [];
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (c !== "\\") { out.push(c.charCodeAt(0) & 0xff); continue; }
    const n = text[i + 1];
    if (n === "x") { out.push(parseInt(text.slice(i + 2, i + 4), 16)); i += 3; continue; }
    if (n >= "0" && n <= "7") {
      let j = i + 1; let oct = "";
      while (j < text.length && j < i + 4 && text[j] >= "0" && text[j] <= "7") { oct += text[j]; j += 1; }
      out.push(parseInt(oct, 8)); i = j - 1; continue;
    }
    const map = { n: 10, t: 9, r: 13, '"': 34, "\\": 92, a: 7, b: 8, f: 12, v: 11 };
    out.push(map[n] ?? n.charCodeAt(0)); i += 1;
  }
  return Buffer.from(out);
}

/** The QNAME of a DNS query packet (question section), or null. */
export function parseDnsQuestion(bytes) {
  if (!bytes || bytes.length < 17) return null;
  const qdcount = bytes.readUInt16BE(4);
  if (qdcount < 1 || (bytes[2] & 0x80) !== 0) return null; // a response, not a query
  const labels = [];
  let i = 12;
  while (i < bytes.length) {
    const len = bytes[i];
    if (len === 0) break;
    if (len >= 0xc0) return null;
    labels.push(bytes.subarray(i + 1, i + 1 + len).toString("latin1"));
    i += len + 1;
  }
  return labels.length ? labels.join(".").toLowerCase() : null;
}

const ADDR_INET = /sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)/u;
const ADDR_INET6 = /sa_family=AF_INET6,\s*sin6_port=htons\((\d+)\),.*?inet_pton\(AF_INET6,\s*"([^"]+)"/u;
const ADDR_UNIX = /sa_family=AF_UNIX,\s*sun_path=(?:"([^"]*)"|(@[^,}]*))/u;
const RESULT = /\)\s*=\s*(-?\d+)(?:\s+(E[A-Z]+))?/u;

/**
 * Parse an strace `-f -o` ledger into the attempts it records. Every AF_INET/AF_INET6 connect,
 * sendto and sendmmsg destination is an attempt; AF_UNIX and AF_NETLINK are counted as local IPC;
 * DNS question names are parsed from any datagram sent to port 53 (explicit address or the
 * socket's last connected address).
 */
export function parseStraceLedger(text) {
  const attempts = [];
  const dns_questions = [];
  let unix = 0;
  let netlink = 0;
  let lines = 0;
  const lastConnect = new Map(); // `${pid}:${fd}` -> {host, port}
  const unfinished = new Map(); // `${pid}:${syscall}` -> the attempt whose result is still pending
  for (const raw of String(text || "").split("\n")) {
    if (!raw.trim()) continue;
    lines += 1;
    const m = raw.match(/^(\d+)\s+(?:<\.\.\.\s+)?(connect|sendto|sendmmsg)(?:\s+resumed>)?\(?(\d*)/u);
    if (!m) continue;
    const pid = Number(m[1]);
    const syscall = m[2];
    const fd = m[3] ? Number(m[3]) : null;
    const resumed = /<\.\.\.\s+\w+\s+resumed>/u.test(raw);
    if (resumed) {
      // The address was on the `<unfinished ...>` line; this half carries the result. Attach it.
      const pending = unfinished.get(`${pid}:${syscall}`);
      const r = raw.match(RESULT);
      if (pending && r) pending.errno = r[2] || (Number(r[1]) < 0 ? "error" : "ok");
      unfinished.delete(`${pid}:${syscall}`);
      continue;
    }
    const result = raw.match(RESULT);
    const errno = result?.[2] || (raw.includes("<unfinished") ? "unfinished" : (result ? (Number(result[1]) < 0 ? "error" : "ok") : "unknown"));
    if (raw.includes("AF_NETLINK")) { netlink += 1; continue; }
    const unixMatch = raw.match(ADDR_UNIX);
    if (unixMatch) { unix += 1; continue; }
    let host = null; let port = null; let family = null;
    const v4 = raw.match(ADDR_INET);
    const v6 = raw.match(ADDR_INET6);
    if (v4) { family = "inet"; port = Number(v4[1]); host = v4[2]; }
    else if (v6) { family = "inet6"; port = Number(v6[1]); host = v6[2]; }
    if (syscall === "connect") {
      if (!family) continue;
      if (fd !== null) lastConnect.set(`${pid}:${fd}`, { host, port });
      const attempt = { pid, syscall, family, host, port, errno, loopback: isLoopbackHost(host) };
      attempts.push(attempt);
      if (errno === "unfinished") unfinished.set(`${pid}:${syscall}`, attempt);
      continue;
    }
    // sendto / sendmmsg: an explicit destination is an attempt; a connected datagram inherits the
    // socket's last connect. Either way, a port-53 payload is a DNS question worth naming.
    let dest = family ? { host, port } : (fd !== null ? lastConnect.get(`${pid}:${fd}`) : null);
    if (family) attempts.push({ pid, syscall, family, host, port, errno, loopback: isLoopbackHost(host) });
    if (dest && dest.port === 53) {
      const payloads = [...raw.matchAll(/iov_base="((?:[^"\\]|\\.)*)"/gu)].map((x) => x[1]);
      if (payloads.length === 0) { const one = raw.match(/^\d+\s+sendto\(\d+,\s+"((?:[^"\\]|\\.)*)"/u); if (one) payloads.push(one[1]); }
      for (const p of payloads) {
        const name = parseDnsQuestion(unescapeStraceString(p));
        if (name) dns_questions.push({ pid, name, resolver: `${dest.host}:${dest.port}` });
      }
    }
  }
  return { attempts, dns_questions, unix, netlink, lines };
}

/**
 * Classify a parsed ledger against the fixture: loopback is allowed egress; a declared BYO host or
 * name is allowed; everything else is an UNDECLARED reach. Search-domain suffixes appended by the
 * host resolver to a declared name are folded onto that name.
 */
export function classifyLedger(parsed, { declaredHosts = [], declaredNames = [] } = {}) {
  const declaredHostSet = new Set(declaredHosts.map((h) => String(h).toLowerCase()));
  const declaredNameList = declaredNames.map((n) => String(n).toLowerCase().replace(/\.$/u, ""));
  const loopback = [];
  const declared = [];
  const undeclared = [];
  for (const a of parsed.attempts) {
    if (a.loopback) loopback.push(a);
    else if (declaredHostSet.has(String(a.host).toLowerCase())) declared.push(a);
    else undeclared.push(a);
  }
  const dnsDeclared = [];
  const dnsUndeclared = [];
  const dnsLocal = [];
  // One row per distinct name: the resolver retries a question and appends the host's search
  // domains, and a coverage count that multiplied one lookup by its retries would mislead.
  const distinctNames = [...new Set(parsed.dns_questions.map((q) => q.name.replace(/\.$/u, "")))].sort((a, b) => a.length - b.length);
  const folded = new Map();
  for (const name of distinctNames) {
    const root = [...folded.keys()].find((shorter) => name.startsWith(`${shorter}.`));
    if (root) folded.get(root).push(name); else folded.set(name, []);
  }
  for (const [name, variants] of folded) {
    const pids = [...new Set(parsed.dns_questions.filter((q) => q.name.replace(/\.$/u, "") === name || variants.includes(q.name.replace(/\.$/u, ""))).map((q) => q.pid))];
    const row = { name, search_variants: variants, pids, questions: parsed.dns_questions.filter((q) => q.name.replace(/\.$/u, "") === name || variants.includes(q.name.replace(/\.$/u, ""))).length };
    if (name === "localhost" || name.endsWith(".localhost")) { dnsLocal.push(row); continue; }
    const matched = declaredNameList.find((d) => name === d || name.startsWith(`${d}.`));
    if (matched) dnsDeclared.push({ ...row, declared_as: matched });
    else dnsUndeclared.push(row);
  }
  const loopbackPorts = [...new Set(loopback.map((a) => a.port))].sort((x, y) => x - y);
  return {
    counts: { attempts: parsed.attempts.length, loopback: loopback.length, declared: declared.length, undeclared: undeclared.length, dns_questions: parsed.dns_questions.length, dns_declared: dnsDeclared.length, dns_undeclared: dnsUndeclared.length, dns_local: dnsLocal.length, local_ipc: parsed.unix, netlink: parsed.netlink, ledger_lines: parsed.lines },
    loopback_ports: loopbackPorts,
    declared,
    undeclared: undeclared.map((a) => ({ pid: a.pid, syscall: a.syscall, destination: `${a.host}:${a.port}`, errno: a.errno })),
    dns_undeclared: dnsUndeclared,
    dns_declared: dnsDeclared,
    clean: undeclared.length === 0 && dnsUndeclared.length === 0,
  };
}

// ------------------------------------------------------------------------------ the run
/**
 * Run `argv` inside the harness. Bridges: [{ name, listenPort, target: { host, port }, fault?: { triggerPath } }].
 * Returns the exit status, the parsed ledger, bridge statistics and the typed isolation property.
 * Throws typed `strace_unavailable` when nothing could record.
 */
export async function runIsolated({ label, argv, cwd = ROOT, env = process.env, workDir, bridges = [], timeoutMs = 60 * 60_000, onOutput = null, isolation = null }) {
  const probe = isolation ?? probeIsolation();
  if (!probe.strace.available) {
    const error = new Error(`strace_unavailable: ${probe.strace.detail}`);
    error.code = "strace_unavailable";
    throw error;
  }
  fs.mkdirSync(workDir, { recursive: true });
  const safe = String(label).replace(/[^A-Za-z0-9_-]+/gu, "-");
  const ledgerPath = path.join(workDir, `${safe}.strace`);
  const controlDir = path.join(workDir, `${safe}-control`);
  fs.mkdirSync(controlDir, { recursive: true });
  const logPath = path.join(workDir, `${safe}.log`);
  // Unix socket paths are limited to ~108 bytes: keep them short and under the OS temp dir.
  const sockDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-eh-"));
  const exporters = [];
  const bridgeConfigs = [];
  for (const b of bridges) {
    const socketPath = path.join(sockDir, `${b.name}.sock`);
    exporters.push({ name: b.name, exporter: await startUnixExporter({ socketPath, host: b.target.host, port: b.target.port }) });
    bridgeConfigs.push({ name: b.name, listenPort: b.listenPort, socketPath, statsPath: path.join(controlDir, `bridge-${b.name}.json`), faultTriggerPath: b.fault?.triggerPath ?? null });
  }
  const config = { label, ledgerPath, command: { argv, cwd, env }, bridges: bridgeConfigs, straceArgs: STRACE_ARGS, readyPath: path.join(controlDir, "ready.json") };
  const configPath = path.join(controlDir, "config.json");
  fs.writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
  const uid = probe.uid; const gid = probe.gid;
  const outer = probe.network_namespace
    ? ["unshare", ["-r", "-n", "sh", "-c", `ip link set lo up && exec unshare --map-user=${uid} --map-group=${gid} "$0" "$@"`, process.execPath, INNER, configPath]]
    : [process.execPath, [INNER, configPath]];
  const started = Date.now();
  const logFd = fs.openSync(logPath, "w");
  const child = spawn(outer[0], outer[1], { cwd, env: { ...env, IOI_EGRESS_HARNESS_ISOLATION: probe.isolation }, stdio: ["ignore", "pipe", "pipe"], detached: true });
  // The inner tree is its own process group (so a timeout can reap all of it at once), which also
  // means a parent that kills THIS process's group does not reach it. A bounded caller's kill must
  // therefore be forwarded, or a whole journey — daemon, authority node, model run — outlives the
  // verifier that started it and competes with whatever runs next (found by ACC-14 on 2026-09-15).
  const forward = (signal) => { try { process.kill(-child.pid, "SIGKILL"); } catch { /* gone */ } process.exit(signal === "SIGINT" ? 130 : 143); };
  const onExit = () => { try { process.kill(-child.pid, "SIGKILL"); } catch { /* gone */ } };
  for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"]) process.on(signal, forward);
  process.on("exit", onExit);
  let tail = "";
  const sink = (chunk) => { fs.writeSync(logFd, chunk); tail = `${tail}${chunk}`.slice(-64_000); if (onOutput) onOutput(String(chunk)); };
  child.stdout.on("data", sink);
  child.stderr.on("data", sink);
  let timedOut = false;
  const killGroup = (signal) => { try { process.kill(-child.pid, signal); } catch { /* gone */ } };
  const deadline = setTimeout(() => { timedOut = true; killGroup("SIGTERM"); setTimeout(() => killGroup("SIGKILL"), 20_000).unref(); }, timeoutMs);
  const exit = await new Promise((resolve) => { child.on("exit", (code, signal) => resolve({ code, signal })); child.on("error", (e) => resolve({ code: null, signal: `spawn-error:${e.message}` })); });
  clearTimeout(deadline);
  killGroup("SIGKILL"); // reap anything the inner runner left behind
  for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"]) process.off(signal, forward);
  process.off("exit", onExit);
  fs.closeSync(logFd);
  for (const { exporter } of exporters) { try { await exporter.close(); } catch { /* none */ } }
  try { fs.rmSync(sockDir, { recursive: true, force: true }); } catch { /* none */ }
  const ledgerText = fs.existsSync(ledgerPath) ? fs.readFileSync(ledgerPath, "utf8") : "";
  const parsed = parseStraceLedger(ledgerText);
  const bridgeStats = {};
  for (const b of bridgeConfigs) {
    let inner = null;
    try { inner = JSON.parse(fs.readFileSync(b.statsPath, "utf8")); } catch { inner = null; }
    const exporter = exporters.find((e) => e.name === b.name)?.exporter.stats ?? null;
    bridgeStats[b.name] = { inner, exporter };
  }
  let innerSummary = null;
  try { innerSummary = JSON.parse(fs.readFileSync(path.join(controlDir, "summary.json"), "utf8")); } catch { innerSummary = null; }
  return {
    label, status: exit.code, signal: exit.signal, timedOut, seconds: Math.round((Date.now() - started) / 1000),
    isolation: probe.isolation, isolation_probe: { network_namespace: probe.network_namespace, detail: probe.network_namespace_detail, strace: probe.strace.version },
    ledgerPath, logPath, ledger: parsed, ledger_bytes: ledgerText.length, bridges: bridgeStats, inner: innerSummary, output_tail: tail.slice(-8_000),
  };
}
