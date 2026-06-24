// IOI-owned API adapter for the live reference's Gitpod Connect-RPC surface.
//
// "Working backwards" from the live reference: instead of the mirror's in-memory mocks,
// endpoints implemented here are backed by real IOI-owned behavior (persisted storage
// now; the IOI hypervisor-daemon next). handle() returns a response for endpoints we own
// and null for the rest, so the serve layer transparently proxies anything not-yet-ported
// to the live reference — no breakage during the migration.
//
// Per-endpoint daemon-wiring plan: internal-docs/implementation/reference-api-integration.md
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

// Anchor to the repo root so the app shares the daemon's data dir (default
// .ioi/hypervisor/data at the repo root), regardless of the process cwd.
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const RAW_DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || ".ioi/hypervisor/data";
const DATA_DIR = isAbsolute(RAW_DATA_DIR) ? RAW_DATA_DIR : join(REPO_ROOT, RAW_DATA_DIR);
const PREF_STORE = join(DATA_DIR, "hypervisor-app-preferences.json");

function loadStore() {
  try {
    return JSON.parse(readFileSync(PREF_STORE, "utf8"));
  } catch {
    return {};
  }
}
function saveStore(store) {
  mkdirSync(dirname(PREF_STORE), { recursive: true });
  writeFileSync(PREF_STORE, JSON.stringify(store, null, 2));
}

function makePreference(key, value, entry) {
  const stableId = Buffer.from(key).toString("hex").slice(0, 24).padEnd(24, "0");
  return { key, value, id: `ioi-${stableId}`, createdAt: entry.createdAt, updatedAt: entry.updatedAt };
}

const json = (payload) => ({ contentType: "application/json", body: JSON.stringify(payload) });

/**
 * @returns {{contentType: string, body: string} | null} response for an owned endpoint,
 *   or null to let the serve layer proxy to the live reference.
 */
export function handle(pathname, bodyText) {
  // UserService preferences — REAL IOI-owned persistence (survives restart), replacing
  // the mirror's ephemeral in-memory Map.
  if (pathname === "/api/gitpod.v1.UserService/GetPreference") {
    let key;
    try {
      const b = JSON.parse(bodyText || "{}");
      key = b.preferenceKey || b.preference?.value || b.preference?.preferenceKey;
    } catch {
      /* fall through to null preference */
    }
    if (!key) return json({ preference: null });
    const entry = loadStore()[key];
    return json({ preference: entry ? makePreference(key, entry.value, entry) : null });
  }

  if (pathname === "/api/gitpod.v1.UserService/SetPreference") {
    let b = {};
    try {
      b = JSON.parse(bodyText || "{}");
    } catch {
      /* keep defaults */
    }
    const key = b.preference?.key || b.key || b.preferenceKey || "DEFAULT_PREFERENCE";
    const value = b.preference?.value ?? b.value ?? "";
    const store = loadStore();
    const now = new Date().toISOString();
    store[key] = { value, createdAt: store[key]?.createdAt || now, updatedAt: now };
    saveStore(store);
    return json({ preference: makePreference(key, value, store[key]) });
  }

  // Not yet IOI-backed -> proxy to the live reference. Next per the integration plan:
  //   EnvironmentService/* -> daemon environment API (start/stop/create/get)
  //   AgentService/*       -> daemon sessions/turns + event stream
  //   EventService/Watch   -> daemon event stream (Connect streaming frames)
  //   RunnerService/*      -> daemon runner registration
  return null;
}
