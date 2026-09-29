// A verifier measures the daemon AS SOMEONE, on a stack it owns (R-240, verifier auth sweep, 2026-09-29).
//
// WHY THIS EXISTS. 3aaaad467 scoped the data-source and materialized-set lists to the caller;
// 3738d5cab scoped every ODK ontology read (anonymous → 401 `request_principal_required`, an
// outsider → absent); 90cd1ddf2 refuses an anonymous control-plane WRITE on loopback too. About
// ninety verifiers still read `IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765"` — the OWNER's
// daemon — with no caller, so each one crashed, read the 401 as "daemon not reachable", or failed a
// precondition, and the result it exists to report was hidden. Worse, the ones that write wrote into
// the owner's data. This is the seam that replaces that default:
//
//   const STACK = await verifierStack({ serve: true });   // own isolated daemon (+ serve), operator signed in
//   STACK.daemonUrl · STACK.serveUrl · STACK.token · STACK.cookie · STACK.dataDir
//   await STACK.signIn(pageOrContext);                     // a browser carries the same session
//
// Every fetch to the stack's own origins carries the operator's session unless the request names its
// own identity (a `cookie` or an `authorization` header — a capability token, a second principal) or
// opts out with the ANONYMOUS header (a verifier asserting the anonymous refusal itself).
//
// NEVER THE OWNER'S STACK. An explicit URL naming :8765 (the owner's daemon), :36173 or :4173 (the
// owner's serves) is REFUSED, exit 2, before anything is sent. An explicit non-owner URL (a disposable
// stack somebody else started) is honoured; its caller is IOI_VERIFIER_SESSION_TOKEN, or the isolated
// operator signing in, or the verifier refuses to run anonymous (exit 2) — it never quietly measures
// as nobody.
//
// A 401 READS AS A 401. `describeHttp` names the status and the daemon's typed code, so a refused
// caller is never reported as an unreachable daemon.
//
// NEVER THE OWNER'S DATA (R-240, verifier hygiene, 2026-09-29). Thirteen provider-adapter verifiers
// deleted and wrote `~/.ioi/hypervisor/data/resource-budgets/*-verify.json`, swept exposure records out
// of the owner's data dir and wrote offer fixtures under `~/.ioi/hypervisor/vast-fixture`. A path under
// the owner's Hypervisor home (`~/.ioi/hypervisor`, symlinks resolved) is REFUSED by name —
// `ownerDataRefusal` says why, `refuseOwnerPath` throws, verifierStack exits 2 on an explicit
// IOI_HYPERVISOR_DATA_DIR there — and a verifier's own fixture files live in `verifierFixtureDir`, a
// temp dir it removes on exit.
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, join, resolve, sep } from "node:path";
import {
  ISOLATED_OPERATOR,
  isolatedOperatorSession,
  startIsolatedPlane,
} from "./isolated-daemon.mjs";

// The owner's stack: the daemon, the sign-in-required serve, the development serve.
export const OWNER_STACK_PORTS = Object.freeze([8765, 36173, 4173]);
export const ANONYMOUS = "x-ioi-verifier-anonymous";

/** The owner's Hypervisor home: the daemon's data dir, evidence, backups and the fixtures beside them. */
export function ownerHypervisorHome(home = homedir()) {
  return resolve(home, ".ioi", "hypervisor");
}

// The path as the kernel will resolve it: the nearest existing ancestor through realpath, the rest appended
// (a fixture file the verifier is about to create does not exist yet, and a symlinked tmp or home must not hide it).
function canonicalPath(p) {
  let head = resolve(String(p));
  const tail = [];
  for (;;) {
    try {
      return join(realpathSync(head), ...tail.reverse());
    } catch {
      const parent = dirname(head);
      if (parent === head) return resolve(String(p));
      tail.push(basename(head));
      head = parent;
    }
  }
}

/** Why `p` may not be a verifier's path (it lies under the owner's ~/.ioi/hypervisor), or null when it may. */
export function ownerDataRefusal(p, { home = homedir() } = {}) {
  if (p === undefined || p === null || p === "") return null;
  const owner = ownerHypervisorHome(home);
  const owners = [...new Set([owner, canonicalPath(owner)])];
  for (const candidate of new Set([resolve(String(p)), canonicalPath(p)])) {
    for (const root of owners) {
      if (candidate === root || candidate.startsWith(`${root}${sep}`)) {
        return `${candidate} is under the owner's Hypervisor home (${root}); a verifier writes only into a data dir and fixture dir it owns`;
      }
    }
  }
  return null;
}

/** Throws when `p` lies under the owner's Hypervisor home; returns `p` otherwise (wrap every path a verifier writes). */
export function refuseOwnerPath(p, what = "path") {
  const why = ownerDataRefusal(p);
  if (why) throw new Error(`refused ${what}: ${why}`);
  return p;
}

/**
 * A temp directory for a verifier's own fixture files (offer/bid/facts documents a provider account reads),
 * never under the owner's ~/.ioi/hypervisor. Removed by remove() and, failing that, when the process exits.
 * Returns { dir, file(name), remove() } — file() refuses a name that escapes the dir.
 */
export function verifierFixtureDir(label = "fixture") {
  const safe = String(label).replace(/[^a-z0-9-]+/giu, "-").slice(0, 40) || "fixture";
  const dir = mkdtempSync(join(refuseOwnerPath(tmpdir(), "temp root"), `ioi-verifier-${safe}-`));
  refuseOwnerPath(dir, "fixture dir");
  let removed = false;
  const remove = () => {
    if (removed) return;
    removed = true;
    rmSync(dir, { recursive: true, force: true });
  };
  process.on("exit", remove);
  return {
    dir,
    file(name) {
      const target = resolve(dir, String(name));
      if (!target.startsWith(`${dir}${sep}`)) throw new Error(`refused fixture file ${JSON.stringify(name)}: outside ${dir}`);
      return target;
    },
    remove,
  };
}

/** Why `url` may not be a verifier's target (it names the owner's stack), or null when it may. */
export function ownerStackRefusal(url) {
  if (url === undefined || url === null || url === "") return null;
  let parsed;
  try {
    parsed = new URL(String(url));
  } catch {
    return `not a URL: ${JSON.stringify(String(url))}`;
  }
  const port = Number(parsed.port || (parsed.protocol === "https:" ? 443 : 80));
  if (OWNER_STACK_PORTS.includes(port)) {
    return `${parsed.origin} is the owner's stack (:${port}); a verifier runs on a stack it owns — never the owner's daemon or serves`;
  }
  return null;
}

/** "HTTP 401 request_principal_required" — the status and the daemon's typed code, never "unreachable". */
export function describeHttp(status, body) {
  if (!status) return "no answer (connection refused or timed out)";
  const code =
    body?.error?.code ?? body?.code ?? body?.reason ?? body?.error_code ??
    (typeof body?.error === "string" ? body.error : null);
  return `HTTP ${status}${code ? ` ${code}` : ""}`;
}

const hasHeader = (headers, name) => headers.has(name);

/**
 * Wrap globalThis.fetch so every request to one of `origins` carries `cookie` unless it names its
 * own identity or opts out with ANONYMOUS. Returns the function that restores the original.
 */
export function installCallerFetch({ origins, cookie, onRefusal = null }) {
  const original = globalThis.fetch;
  // Every refusal the stack answers is handed to onRefusal (status + typed code), so a verifier that gives up with
  // "could not build the fixture" can still say which answer stopped it.
  const observe = (method, url, promise) => {
    if (!onRefusal) return promise;
    return promise.then((r) => {
      if (r.status >= 400) {
        r.clone().json().catch(() => null).then((body) => onRefusal({ method, path: new URL(url).pathname, status: r.status, described: describeHttp(r.status, body) }));
      }
      return r;
    });
  };
  const wrapped = (input, init = {}) => {
    // Read on every call: a verifier that starts a serve of its own adds its origin later (STACK.addOrigin).
    const own = origins.filter(Boolean).map((o) => String(o).replace(/\/$/u, ""));
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input?.url;
    if (typeof url !== "string" || !own.some((o) => url === o || url.startsWith(`${o}/`) || url.startsWith(`${o}?`))) {
      return original(input, init);
    }
    const headers = new Headers(init.headers ?? (input instanceof Request ? input.headers : undefined));
    const method = String(init.method || (input instanceof Request ? input.method : "GET")).toUpperCase();
    if (hasHeader(headers, ANONYMOUS)) {
      headers.delete(ANONYMOUS);
      return observe(method, url, original(input, { ...init, headers }));
    }
    if (!hasHeader(headers, "cookie") && !hasHeader(headers, "authorization")) headers.set("cookie", cookie);
    return observe(method, url, original(input, { ...init, headers }));
  };
  globalThis.fetch = wrapped;
  return () => {
    if (globalThis.fetch === wrapped) globalThis.fetch = original;
  };
}

function refuse(message) {
  console.error(`BLOCKED: ${message}`);
  process.exit(2);
}

async function explicitCaller(daemonUrl) {
  if (process.env.IOI_VERIFIER_SESSION_TOKEN) return process.env.IOI_VERIFIER_SESSION_TOKEN;
  const { email, password } = ISOLATED_OPERATOR;
  const login = await fetch(`${daemonUrl}/v1/hypervisor/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password }),
  })
    .then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }))
    .catch(() => ({ status: 0, body: null }));
  return login.body?.session_token || null;
}

/**
 * The daemon a census gate's OWN serve reads — never the owner's (R-240, verifier auth sweep,
 * 2026-09-29). check:dead-controls and check:named-gap-perception started their own serve and handed
 * it no daemon URL, so it read the owner's :8765 as nobody. With no explicit IOI_HYPERVISOR_DAEMON_URL
 * this starts an isolated daemon and signs its operator in; an explicit URL naming the owner's stack
 * THROWS (the gate reports it by name); any other explicit URL is used as given, its caller
 * IOI_VERIFIER_SESSION_TOKEN when set.
 * Returns { daemonUrl, token (or null), serveEnv, signIn(context, origins), stop() }.
 */
export async function gateDaemon({ env = {} } = {}) {
  const explicit = process.env.IOI_HYPERVISOR_DAEMON_URL || "";
  const why = ownerStackRefusal(explicit);
  if (why) throw new Error(`refused: ${why}`);
  let daemonUrl;
  let token = null;
  let stop = async () => {};
  if (explicit) {
    daemonUrl = explicit.replace(/\/$/u, "");
    token = process.env.IOI_VERIFIER_SESSION_TOKEN || null;
  } else {
    const plane = await startIsolatedPlane({ env });
    if (!plane) throw new Error("no isolated daemon: target/debug/hypervisor-daemon is not built (or IOI_HYPERVISOR_DAEMON_BINARY)");
    daemonUrl = plane.daemonUrl;
    try {
      token = await isolatedOperatorSession(plane);
    } catch (error) {
      await plane.stop();
      throw error;
    }
    stop = () => plane.stop();
  }
  console.log(`IOI_GATE_DAEMON daemon=${daemonUrl} caller=${token ? "operator" : "none"}`);
  return {
    daemonUrl,
    token,
    serveEnv: { IOI_HYPERVISOR_DAEMON_URL: daemonUrl },
    /** The browser context carries the operator's session on each origin (the gate's serve). */
    async signIn(context, origins) {
      if (!token) return false;
      await context.addCookies(origins.map((url) => ({ name: "ioi_session", value: token, url })));
      return true;
    },
    stop,
  };
}

/**
 * The stack a verifier measures, with the operator signed in.
 * options.serve — also a serve-product-ui bound to the same daemon (a verifier that reads pages).
 * options.env / options.serveEnv — extra env for the isolated processes (see startIsolatedPlane).
 * options.fresh — always a new isolated plane (exact-count verifiers); an explicit URL is not adopted.
 * Exits 2 (BLOCKED) when the daemon binary is missing, an explicit URL names the owner's stack, or an
 * explicit stack offers no caller. Throws when an isolated process never becomes healthy (a real
 * failure, not an environment gap).
 */
export async function verifierStack({ serve = false, env = {}, serveEnv = null, fresh = false } = {}) {
  // fresh — a verifier whose assertions count records exactly (1 source, 1 receipt file) needs an EMPTY
  // plane of its own, so it never adopts an explicit stack somebody else started.
  const explicitDaemon = fresh ? "" : process.env.IOI_HYPERVISOR_DAEMON_URL || "";
  const explicitServe = fresh ? "" : process.env.IOI_HYPERVISOR_SERVE_URL || "";
  for (const url of [explicitDaemon, explicitServe]) {
    const why = ownerStackRefusal(url);
    if (why) refuse(why);
  }
  let daemonUrl;
  let serveUrl = null;
  let dataDir = null;
  let token;
  let stop = async () => {};
  let mode;
  if (explicitDaemon) {
    daemonUrl = explicitDaemon.replace(/\/$/u, "");
    if (serve) {
      if (!explicitServe) refuse(`IOI_HYPERVISOR_DAEMON_URL=${daemonUrl} names a stack this verifier did not start; it also reads pages, so name that stack's serve in IOI_HYPERVISOR_SERVE_URL (or unset both and it starts its own)`);
      serveUrl = explicitServe.replace(/\/$/u, "");
    }
    // Its data dir is only known when named (a verifier that counts receipt files reads it) — and never the owner's
    // ~/.ioi/hypervisor, whatever port the daemon answers on (R-240, verifier hygiene, 2026-09-29).
    dataDir = process.env.IOI_HYPERVISOR_DATA_DIR || null;
    const dataWhy = ownerDataRefusal(dataDir);
    if (dataWhy) refuse(`IOI_HYPERVISOR_DATA_DIR: ${dataWhy}`);
    token = await explicitCaller(daemonUrl);
    if (!token) refuse(`the stack at ${daemonUrl} offers this verifier no caller: set IOI_VERIFIER_SESSION_TOKEN, or unset IOI_HYPERVISOR_DAEMON_URL and it starts its own stack and signs its operator in`);
    mode = "explicit";
  } else {
    // The isolated plane's data dir is a mkdtemp under the temp root; a temp root inside the owner's home is refused.
    const tmpWhy = ownerDataRefusal(tmpdir());
    if (tmpWhy) refuse(`the temp root (TMPDIR): ${tmpWhy}`);
    const plane = await startIsolatedPlane({ serve, env, serveEnv });
    if (!plane) refuse("target/debug/hypervisor-daemon is not built — cargo build -p ioi-node --bin hypervisor-daemon (or IOI_HYPERVISOR_DAEMON_BINARY)");
    ({ daemonUrl, serveUrl, dataDir } = plane);
    try {
      token = await isolatedOperatorSession(plane);
    } catch (error) {
      await plane.stop();
      throw error;
    }
    stop = () => plane.stop();
    mode = "isolated";
  }
  const cookie = `ioi_session=${token}`;
  const origins = [daemonUrl, serveUrl].filter(Boolean);
  // A verifier that exits non-zero names the last refusals its stack answered (status + typed code), so "BLOCKED: could
  // not build the fixture" arrives with the answer that stopped it — a 401 reads as a 401, a 501 as a 501.
  const refusals = [];
  const restoreFetch = installCallerFetch({ origins, cookie, onRefusal: (r) => { refusals.push(r); if (refusals.length > 64) refusals.shift(); } });
  process.on("exit", (code) => {
    if (code === 0 || refusals.length === 0) return;
    const last = [];
    for (const r of refusals.slice().reverse()) {
      const line = `${r.method} ${r.path.replace(/\/[a-z]+_[0-9a-f]{8,}/gu, "/:id")} → ${r.described}`;
      if (!last.includes(line)) last.push(line);
      if (last.length === 6) break;
    }
    console.error(`IOI_VERIFIER_STACK exit=${code} — the last refusals this stack answered (newest first):\n  ${last.join("\n  ")}`);
  });
  // The organization the operator's records are owned by (an owner_ref every owned create now requires).
  const who = await fetch(`${daemonUrl}/v1/hypervisor/auth/whoami`).then((r) => r.json()).catch(() => null);
  const owner = (who?.principal?.tenant_refs || []).find((t) => typeof t === "string" && t.startsWith("org://")) || null;
  console.log(`IOI_VERIFIER_STACK mode=${mode} daemon=${daemonUrl}${serveUrl ? ` serve=${serveUrl}` : ""} caller=operator owner=${owner ?? "none"}`);
  return {
    mode,
    daemonUrl,
    serveUrl,
    dataDir,
    token,
    cookie,
    owner,
    /** A serve this verifier started itself on this stack's daemon: its requests and pages carry the operator too. */
    addOrigin(url) {
      if (ownerStackRefusal(url)) throw new Error(ownerStackRefusal(url));
      origins.push(String(url).replace(/\/$/u, ""));
    },
    /** A browser page or context carries the operator's session on this stack's origins. */
    async signIn(target) {
      const context = typeof target?.addCookies === "function" ? target : target?.context?.();
      if (!context) throw new Error("signIn needs a Playwright page or browser context");
      await context.addCookies(origins.map((url) => ({ name: "ioi_session", value: token, url })));
    },
    /** The environment a child script (a parity harness) inherits: this stack and its operator, never :8765/:4173. */
    childEnv() {
      return {
        ...process.env,
        IOI_HYPERVISOR_DAEMON_URL: daemonUrl,
        ...(serveUrl ? { IOI_HYPERVISOR_SERVE_URL: serveUrl } : {}),
        ...(dataDir ? { IOI_HYPERVISOR_DATA_DIR: dataDir } : {}),
        IOI_VERIFIER_SESSION_TOKEN: token,
      };
    },
    /** GET a daemon path as the operator: { status, body, described }. */
    async read(path) {
      const r = await fetch(`${daemonUrl}${path}`).catch(() => null);
      const body = r ? await r.json().catch(() => null) : null;
      return { status: r?.status ?? 0, body, described: describeHttp(r?.status ?? 0, body) };
    },
    /**
     * The precondition read a verifier used to spell `fetch(...).then((r) => r.ok)` + "BLOCKED: daemon not
     * reachable": no answer is BLOCKED (exit 2); any other refusal is a FAIL (exit 1) that names its status and
     * typed code — a signed-in operator refused on its own stack is a finding, never an unreachable daemon.
     */
    async requireRead(path, what = path) {
      const r = await this.read(path);
      if (r.status >= 200 && r.status < 300) return r.body;
      if (!r.status) {
        console.error(`BLOCKED: ${what} at ${daemonUrl}: ${r.described}`);
        process.exit(2);
      }
      console.error(`FAIL: ${what} at ${daemonUrl} answered ${r.described} to the signed-in operator`);
      process.exit(1);
    },
    async stop() {
      restoreFetch();
      await stop();
    },
  };
}
