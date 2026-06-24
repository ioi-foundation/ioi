// WS2 — Environment lifecycle behind a provider abstraction.
//
// The object model is independent of the substrate; the substrate is swappable behind
// EnvironmentProvider. This ships the interim **SimulatedProvider** (no real VM): a
// time-driven lifecycle state machine that *represents* the canonical environment
// lifecycle so the whole object shape works today. Phase 0 of the master guide swaps in
// daemon-owned providers (VM / microVM / devcontainer) behind the SAME interface —
// object model and UI unchanged.
//
// SPLIT-BRAIN GUARD: a real provider's lifecycle execution is DAEMON-OWNED (the daemon
// EXECUTES; it owns environment runtime truth). This Simulated provider owns lifecycle
// state in JS, which is a localized split-brain seam — tolerated ONLY as a deletable,
// non-authoritative stand-in. Three hard rules:
//   1. NON-AUTHORITATIVE: its state lives in an app-local sim dir, NOT the daemon data dir
//      (.ioi/hypervisor/data is daemon truth and must not be polluted by JS-owned state).
//   2. NO COEXISTENCE: when the daemon owns the EnvironmentProvider, this file is DELETED
//      and the JS layer PROJECTS the daemon's environment (exactly like Session) — it must
//      never run beside a daemon env owner.
//   3. SEAM ONLY: the EnvironmentProvider interface is the canonical seam Phase 0 swaps.
//
// EnvironmentProvider interface:
//   create(spec) -> id        start(id)      stop(id)      del(id)
//   get(id) -> env            list() -> env[]   logs(id) -> string[]   actions(id) -> string[]
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
// App-local, NON-AUTHORITATIVE simulation state — deliberately separate from the daemon
// data dir so JS-owned state can never be mistaken for (or collide with) daemon truth.
const APP_LOCAL = join(REPO_ROOT, ".ioi", "hypervisor-app-local");
const STORE = join(APP_LOCAL, "simulated-environments.json");

// Canonical lifecycle taxonomy (subset): queued -> provisioning -> ready ; stopping ->
// stopped ; failed. Simulated transition delays (ms).
const PROVISION_MS = 4000;
const STOP_MS = 1500;

function load() {
  try {
    return JSON.parse(readFileSync(STORE, "utf8"));
  } catch {
    return {};
  }
}
function save(s) {
  mkdirSync(dirname(STORE), { recursive: true });
  writeFileSync(STORE, JSON.stringify(s, null, 2));
}

// Advance an env's lifecycle based on elapsed time toward its desired phase.
function settle(env, now) {
  const since = now - (env.phaseAt || now);
  if (env.desired === "running") {
    if (env.phase === "queued" || env.phase === "provisioning") {
      env.phase = since >= PROVISION_MS ? "ready" : "provisioning";
    }
  } else if (env.desired === "stopped") {
    if (env.phase === "stopping") env.phase = since >= STOP_MS ? "stopped" : "stopping";
  }
  return env;
}

function newEnv(id, spec, now) {
  return {
    id,
    spec: spec || {},
    desired: "stopped",
    phase: "stopped",
    phaseAt: now,
    createdAt: new Date(now).toISOString(),
    lastStartedAt: null,
    logs: [`[${new Date(now).toISOString()}] environment ${id} registered (simulated provider)`],
  };
}

export const SimulatedProvider = {
  name: "simulated",

  get(id, now = Date.now()) {
    const store = load();
    if (!store[id]) {
      // auto-vivify: any environment the UI references exists, in stopped state.
      store[id] = newEnv(id, {}, now);
      save(store);
    }
    settle(store[id], now);
    save(store);
    return store[id];
  },

  list(now = Date.now()) {
    const store = load();
    for (const id of Object.keys(store)) settle(store[id], now);
    save(store);
    return Object.values(store);
  },

  create(spec, id, now = Date.now()) {
    const store = load();
    const envId = id || spec?.environmentId || `env-${Buffer.from(String(now)).toString("hex").slice(0, 12)}`;
    store[envId] = newEnv(envId, spec, now);
    // create implies start in the reference flow
    store[envId].desired = "running";
    store[envId].phase = "queued";
    store[envId].phaseAt = now;
    store[envId].lastStartedAt = new Date(now).toISOString();
    store[envId].logs.push(`[${new Date(now).toISOString()}] create -> queued -> provisioning`);
    save(store);
    return envId;
  },

  start(id, now = Date.now()) {
    const store = load();
    const env = store[id] || newEnv(id, {}, now);
    env.desired = "running";
    if (env.phase === "stopped" || env.phase === "failed") {
      env.phase = "queued";
      env.phaseAt = now;
      env.lastStartedAt = new Date(now).toISOString();
      env.logs.push(`[${new Date(now).toISOString()}] start -> queued -> provisioning`);
    }
    store[id] = env;
    save(store);
    return settle(env, now);
  },

  stop(id, now = Date.now()) {
    const store = load();
    const env = store[id] || newEnv(id, {}, now);
    env.desired = "stopped";
    if (env.phase !== "stopped") {
      env.phase = "stopping";
      env.phaseAt = now;
      env.logs.push(`[${new Date(now).toISOString()}] stop -> stopping`);
    }
    store[id] = env;
    save(store);
    return settle(env, now);
  },

  del(id, now = Date.now()) {
    const store = load();
    if (store[id]) {
      store[id].desired = "deleted";
      store[id].phase = "deleting";
      store[id].phaseAt = now;
      save(store);
    }
    return store[id] || newEnv(id, {}, now);
  },

  logs(id) {
    return (this.get(id).logs || []).slice(-200);
  },

  actions(id) {
    const ph = this.get(id).phase;
    if (ph === "ready") return ["stop", "restart", "open-logs"];
    if (ph === "stopped" || ph === "failed") return ["start", "delete"];
    return ["open-logs"]; // transient phases
  },
};

// ---- project an internal env -> the Gitpod EnvironmentService shape the UI renders ----
const RUNNING = "ENVIRONMENT_PHASE_RUNNING";
function gitpodPhase(env) {
  switch (env.phase) {
    case "ready":
      return RUNNING;
    case "queued":
    case "provisioning":
      return "ENVIRONMENT_PHASE_STARTING";
    case "stopping":
      return "ENVIRONMENT_PHASE_STOPPING";
    case "deleting":
      return "ENVIRONMENT_PHASE_DELETING";
    case "failed":
      return "ENVIRONMENT_PHASE_FAILED";
    default:
      return "ENVIRONMENT_PHASE_STOPPED";
  }
}

export function toGitpodEnvironment(env) {
  const phase = gitpodPhase(env);
  const running = phase === RUNNING;
  const status = {
    statusVersion: String(env.phaseAt || 1),
    phase,
    machine: { phase: running ? "PHASE_RUNNING" : phase === "ENVIRONMENT_PHASE_STOPPING" ? "PHASE_STOPPING" : "PHASE_STOPPED" },
    environmentUrls: { logs: `local://environments/${env.id}/logs` },
  };
  if (running) {
    status.devcontainer = { phase: "CONTENT_PHASE_READY", remoteWorkspaceFolder: "/workspaces/workspace" };
    status.content = { phase: "CONTENT_PHASE_READY", contentLocationInMachine: "/workspaces/workspace" };
  }
  return {
    id: env.id,
    metadata: { lastStartedAt: env.lastStartedAt || env.createdAt, createdAt: env.createdAt },
    spec: { desiredPhase: env.desired === "running" ? RUNNING : env.desired === "deleted" ? "ENVIRONMENT_PHASE_DELETED" : "ENVIRONMENT_PHASE_STOPPED" },
    status,
  };
}
