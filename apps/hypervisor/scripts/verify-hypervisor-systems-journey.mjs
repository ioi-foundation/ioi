#!/usr/bin/env node
// Systems workspace journey verifier (greenfield packet, next-legs III Leg 4).
//
// Proves, against an ISOLATED real daemon + serve lane, the SURF-systems acceptance for the
// canonical /systems greenfield workspace (typed non-parity lane — seed-ux-provenance.v1.json;
// the module claims no seed preservation and no parity):
//
//   - the inventory is the daemon's compact read projection VERBATIM: honest_empty renders the
//     daemon's own state/source/nonclaims, and no System row is ever fabricated;
//   - the genesis chain is TRIED for real against the isolated daemon with the exact M1.3
//     fixture recipe, THROUGH the surface's lease-client crossing, and WHEREVER it refuses the
//     typed refusal ladder is asserted verbatim — every stop-point is an assertion, not a skip.
//     Check names report honestly WHICH arm ran (real receipted transition vs refusal ladder).
//     RECORDED FINDING: the genesis plane resolves its governing authority THROUGH the wallet
//     network BEFORE computing any 403 challenge (governed_authority.rs
//     resolve_required_authority; the M1.x verifiers always carried the wallet-network fixture
//     env, which CI's Node-only journeys job cannot run), so on this fixture-less plane the
//     chain's first stop is the typed authority PREFLIGHT
//     (system_genesis_authority_binding_unavailable, 501) — asserted verbatim, alongside the
//     compiler blocker rung, the grant-shape rung (a structurally real minted grant does not
//     bypass the preflight), the typed not-found readback, and the sequence-zero stop; the 403
//     commitment band and 428 credential band are asserted as rendering contracts with
//     representative facts, named honestly as such;
//   - detail panes (Overview / Govern preview / Operate desired-vs-observed / Writer /
//     Amendments) render live daemon truth or typed refusals verbatim — zero fabricated rows;
//   - Interfaces mode is the OQ-9 disabled named gap (HypervisorSystemInterfaceBinding:
//     registered schema, zero rows, zero routes) — asserted on the control's own reason;
//   - no scheduler-health and no machinery content anywhere on the surface;
//   - daemon kill → typed unavailability with zero rows; restart → the same truth (honest
//     empty inventory; the refusal posture re-renders IDENTICALLY — continuity across restart);
//   - 3-posture browser matrix; the M1.6/M1.7 genesis cockpit keeps serving untouched.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon or grant-signer binary missing).
//   IOI_HYPERVISOR_DAEMON_BINARY      default target/debug/hypervisor-daemon
//   IOI_MINT_APPROVAL_GRANT_BINARY    default target/debug/mint-approval-grant

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const FIXTURES = path.join(ROOT, "docs", "architecture", "_meta", "schemas", "fixtures");

const CANONICAL = "/systems";
const LANE = "/__ioi/systems-workspace";
const API = "/v1/hypervisor/autonomous-systems";
const OWNER_APPROVER_SEED = "07".repeat(32); // the M1.x owner-approver fixture seed

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => {
    const { port } = srv.address();
    srv.close(() => resolve(port));
  });
  srv.on("error", reject);
});

const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try {
      const r = await fetch(url);
      if (r.status < 500) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(`timeout waiting for ${url}`);
};

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
const mintBinary = path.resolve(ROOT, process.env.IOI_MINT_APPROVAL_GRANT_BINARY ?? "target/debug/mint-approval-grant");
for (const [label, binary] of [["daemon", daemonBinary], ["mint-approval-grant signer", mintBinary]]) {
  try {
    fs.accessSync(binary, fs.constants.X_OK);
  } catch {
    console.error(`BLOCKED: ${label} binary not executable at ${binary}`);
    process.exit(2);
  }
}

// ---- the exact M1.3 fixture recipe (byte-identical hashing to the M1.x verifiers) ------------
const clone = (value) => structuredClone(value);
const fixture = (relative) => JSON.parse(fs.readFileSync(path.join(FIXTURES, relative), "utf8"));

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
const sha256hex = (text) => createHash("sha256").update(text).digest("hex");
const domainHash = (domain, value) => `sha256:${sha256hex(canonicalJson({ domain, value }))}`;

function recomputeReleaseHashes(release) {
  const componentMaterial = clone(release.typed_components);
  delete componentMaterial.component_set_hash;
  release.typed_components.component_set_hash = domainHash(
    "ioi.autonomous-system-component-set-jcs-sha256.v1",
    componentMaterial,
  );
  const releaseMaterial = clone(release);
  delete releaseMaterial.release_root;
  delete releaseMaterial.registry_status;
  delete releaseMaterial.receipts.package_readiness_receipt_ref;
  delete releaseMaterial.release.publisher_signature_ref;
  delete releaseMaterial.release.registry_published_at;
  release.release_root = domainHash(
    "ioi.autonomous-system-manifest-release-root-jcs-sha256.v1",
    releaseMaterial,
  );
}

function exactGenesisBody() {
  const release = fixture("autonomous-system-manifest-v1/positive-reusable-release.json");
  recomputeReleaseHashes(release);
  const candidate = fixture("autonomous-system-genesis-v1/positive-proposed.json");
  delete candidate.admitted_manifest_root;
  delete candidate.initial_profile_bundle_root;
  delete candidate.cryptographic_origin.genesis_operation_commitment;
  delete candidate.cryptographic_origin.genesis_transition_commitment_ref;
  candidate.initial_component_bindings.admitted_component_set_hash =
    release.typed_components.component_set_hash;
  return {
    release,
    proposed_instantiation: {
      schema_version: "ioi.autonomous-system-genesis-proposal-input.v1",
      candidate,
      template_bindings: {
        constitution_template_ref: release.constitution_template_ref,
        deployment_template_ref: release.required_profile_templates.deployment_template_ref,
        ordering_admission_finality_template_ref:
          release.required_profile_templates.ordering_admission_finality_template_ref,
        oracle_evidence_template_refs:
          release.required_profile_templates.oracle_evidence_template_refs,
        lifecycle_continuity_template_ref:
          release.required_profile_templates.lifecycle_continuity_template_ref,
        network_enrollment_constraint_ref:
          release.required_profile_templates.network_enrollment_constraint_ref,
      },
      constitution: fixture("autonomous-system-constitution-v1/positive-draft.json"),
      ordering_profile: fixture("ordering-admission-finality-profile-v1/positive-single-authority.json"),
      oracle_profiles: [fixture("oracle-evidence-profile-v1/positive-fail-closed.json")],
      lifecycle_profile: fixture("lifecycle-continuity-profile-v1/positive-successor-governed.json"),
      network_enrollment: null,
    },
  };
}

// The daemon's deterministic admission-record tail for one system_id
// (system_genesis_routes.rs record_tail: sha256 over the canonical identity material).
const recordTailFor = (systemId) =>
  `asg_${sha256hex(canonicalJson({ domain: "hypervisor.autonomous-system-genesis.identity.v1", system_id: systemId }))}`;

// A structurally real dcrypt-signed grant from the Rust signer — passes the runtime authority's
// structural verify AND the settlement layer's cryptographic signature verify; no bypass.
function mintGrant(policyHash, requestHash) {
  const result = spawnSync(mintBinary, [
    "--seed", OWNER_APPROVER_SEED,
    "--policy-hash", policyHash,
    "--request-hash", requestHash,
  ], { cwd: ROOT, encoding: "utf8" });
  if (result.status !== 0) throw new Error(`mint-approval-grant failed:\n${result.stdout}\n${result.stderr}`);
  return JSON.parse(result.stdout.trim());
}

// ---- isolated plane ---------------------------------------------------------------------------
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-systems-journey-"));
let daemon = null;
let serve = null;
let daemonPort = 0;
let DAEMON = "";
let SERVE = "";
let SESSION = "";

async function startDaemon() {
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);
  return () => log;
}

const jd = (p, init) => fetch(`${DAEMON}${p}`, {
  headers: {
    "content-type": "application/json",
    ...(SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
  },
  ...init,
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
  .catch(() => ({ status: 0, body: {} }));

const pageText = (p, { authenticated = true } = {}) => fetch(`${SERVE}${p}`, {
  headers: authenticated && SESSION ? { cookie: `ioi_session=${SESSION}` } : {},
}).then(async (r) => ({ status: r.status, text: await r.text(), headers: r.headers }))
  .catch(() => ({ status: 0, text: "", headers: new Headers() }));

// POST one surface action form; returns the 303 redirect location plus the followed page.
async function postAction(actionPath, params, { authenticated = true } = {}) {
  const body = new URLSearchParams(params).toString();
  let status = 0;
  let location = "";
  try {
    const response = await fetch(`${SERVE}${actionPath}`, {
      method: "POST",
      redirect: "manual",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        ...(authenticated && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
      },
      body,
    });
    status = response.status;
    location = response.headers.get("location") || "";
    await response.text().catch(() => "");
  } catch { /* typed below */ }
  const page = location ? await pageText(location, { authenticated }) : { status: 0, text: "", headers: new Headers() };
  return { status, location, page };
}

const systemRows = (text) => [...text.matchAll(/data-ioi-system-row="([^"]*)"/gu)].map((m) => m[1]);
const challengeHash = (text, which) => (text.match(new RegExp(`data-ioi-challenge="${which}">(sha256:[0-9a-f]{64})<`, "u")) || [])[1] || "";
const attr = (text, name) => (text.match(new RegExp(`${name}="([^"]*)"`, "u")) || [])[1] || "";

async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  const daemonLogFn = await startDaemon();
  const token = daemonLogFn().match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ token, password: "systems-journey-bootstrap-v1", email: "systems-journey@ioi.local" }),
    });
    SESSION = boot.body?.session_token ?? "";
  }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));

  const servePort = await freePort();
  const productUiPort = await freePort();
  SERVE = `http://127.0.0.1:${servePort}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: APP,
    env: {
      ...process.env,
      PORT: String(servePort),
      PRODUCT_UI_PORT: String(productUiPort),
      IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"),
      IOI_HYPERVISOR_DAEMON_URL: DAEMON,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitFor(`${SERVE}${CANONICAL}`, 30000);

  // -- canonical + fresh legacy mounts render with truthful ownership ----------
  const landing = await pageText(CANONICAL);
  ok("canonical /systems 200s as the module's own mount (ownership headers + heading)",
    landing.status === 200 && landing.headers.get("x-ioi-surface-route") === CANONICAL
      && landing.headers.get("x-ioi-surface-owner") === "Systems"
      && landing.text.includes("<h1>Systems</h1>"),
    `status ${landing.status} route ${landing.headers.get("x-ioi-surface-route")}`);
  const legacy = await pageText(LANE);
  ok("the fresh legacy lane serves the same module with its own truthful marker",
    legacy.status === 200 && legacy.headers.get("x-ioi-surface-route") === LANE
      && legacy.headers.get("x-ioi-surface-owner") === "Systems",
    `status ${legacy.status} route ${legacy.headers.get("x-ioi-surface-route")}`);
  ok("the workspace names its greenfield provenance honestly (typed non-parity lane, no seed/parity claim)",
    landing.text.includes("greenfield") && landing.text.includes("seed-ux-provenance.v1.json")
      && landing.text.includes("no seed preservation and no parity"),
    "");

  // -- inventory: the projection's honest_empty passes through VERBATIM --------
  ok("inventory renders the projection's honest_empty state VERBATIM — daemon state, source, and nonclaims block; zero System rows, nothing fixtured",
    landing.text.includes('data-ioi-projection-state="honest_empty"')
      && landing.text.includes("honest_empty")
      && landing.text.includes("verified_owner_reconstruction")
      && landing.text.includes("network_assurance")
      && systemRows(landing.text).length === 0,
    "");
  ok("no scheduler-health and no machinery content on the workspace",
    !/scheduler/iu.test(landing.text) && !/machinery/iu.test(landing.text),
    "");
  ok("the blank-to-genesis compose crossing renders where it crosses the lease client (form → the declared action route)",
    landing.text.includes(`action="${LANE}/actions/genesis-compose"`)
      && landing.text.includes("CapabilityLease"),
    "");
  ok("Interfaces mode is the OQ-9 disabled named gap on the workspace — reason on the control, no fabricated launch affordance",
    landing.text.includes('data-ioi-pane="interfaces"')
      && landing.text.includes('data-ioi-pane-state="disabled_named_gap"')
      && /data-ioi-disabled-reason="[^"]*OQ-9[^"]*HypervisorSystemInterfaceBinding[^"]*"/u.test(landing.text),
    "");

  // -- the genesis chain, TRIED for real through the surface crossing ----------
  const genesisBody = exactGenesisBody();
  const declaration = JSON.stringify(genesisBody);
  const systemId = genesisBody.proposed_instantiation.candidate.system_id;
  const recordTail = recordTailFor(systemId);
  ok("the M1.3 fixture recipe reconstructs its immutable release commitments (the exact-compiler-input recipe, not an approximation)",
    genesisBody.release.typed_components.component_set_hash === "sha256:8cd8d649b1ae06bb99cf6cbe9fa671ef47b48ca523cbdce8b943224c279340fc"
      && genesisBody.release.release_root === "sha256:78ca76fbeb4fc51bdc114f68afd9078cedf52c8a3760ed1e2bb3be173091858b",
    genesisBody.release.release_root);

  // (a) UNAUTHENTICATED, ungranted compose through the surface. FINDING this verifier records
  // honestly: the genesis plane resolves its governing authority THROUGH the wallet network
  // BEFORE computing any challenge (governed_authority.rs resolve_required_authority — the
  // M1.x verifiers always carried the wallet-network fixture env), so on this fixture-less
  // isolated plane the chain's first stop is the typed wallet PREFLIGHT refusal
  // (system_genesis_authority_binding_unavailable, HTTP 501) — one rung BEFORE the 403
  // challenge. Reaching the AUTHORITY stage is itself the byte-integrity proof: an altered or
  // truncated declaration would stop EARLIER at the typed blocker report, so this rung also
  // proves the 26KB hash-committed declaration crossed the governed action runtime unmangled
  // and COMPILED.
  const challenged = await postAction(`${LANE}/actions/genesis-compose`, { declaration, return: LANE }, { authenticated: false });
  const chPage = challenged.page.text;
  ok("REFUSAL LADDER rung 1 — unauthenticated ungranted genesis compose stops at the daemon's typed wallet-network authority PREFLIGHT (system_genesis_authority_binding_unavailable, HTTP 501 — even the 403 challenge needs the wallet network), rendered verbatim through the lease client; reaching the authority stage proves the 26KB declaration compiled unmangled",
    challenged.status === 303 && challenged.page.status === 200
      && chPage.includes('data-ioi-refusal-stage="gateway"')
      && chPage.includes('data-ioi-refusal-code="system_genesis_authority_binding_unavailable"')
      && chPage.includes("HTTP 501"),
    `303→${challenged.location.slice(0, 90)}`);

  // (b) The daemon's own answer for the byte-same declaration: same typed stop — the surface
  // rendered the daemon's refusal verbatim, not a paraphrase.
  const direct = await jd(API, { method: "POST", body: declaration });
  ok("the surface-rendered stop equals the daemon's own typed refusal for the byte-same declaration (code + status verbatim)",
    direct.status === 501
      && direct.body?.error?.code === "system_genesis_authority_binding_unavailable"
      && attr(chPage, "data-ioi-refusal-code") === direct.body?.error?.code,
    `daemon ${direct.status}/${direct.body?.error?.code}`);
  ok("the same PRG banner renders identically on the CANONICAL mount (one module, two truthful mounts)",
    await pageText(`${CANONICAL}${challenged.location.includes("?") ? challenged.location.slice(challenged.location.indexOf("?")) : ""}`)
      .then((r) => r.status === 200 && r.text.includes('data-ioi-refusal-stage="gateway"')
        && r.text.includes('data-ioi-refusal-code="system_genesis_authority_binding_unavailable"')),
    "");

  // (c) A structurally REAL dcrypt-signed grant (mint-approval-grant, no bypass) attached to
  // the same declaration: authority preflight still owns the stop — a signed grant cannot
  // bypass wallet-network authority resolution, and nothing is admitted. A plane that DOES
  // carry a wallet network admits here instead — the check names report which arm ran.
  const grant = mintGrant(`sha256:${"ab".repeat(32)}`, `sha256:${"cd".repeat(32)}`);
  const granted = await postAction(`${LANE}/actions/genesis-compose`, {
    declaration,
    wallet_approval_grant: JSON.stringify(grant),
    return: LANE,
  });
  const grantedPage = granted.page.text;
  const grantedCrossed = grantedPage.includes('data-ioi-crossing="crossed"');
  let realArm = false;
  if (grantedCrossed) {
    realArm = true;
    ok("CHAIN ARM: REAL RECEIPTED ADMISSION — the granted compose crossed with its receipt rendered (this plane resolved a wallet network)",
      grantedPage.includes("data-ioi-receipt-ref="),
      "real arm");
  } else {
    ok("CHAIN ARM: REFUSAL LADDER rung 2 — a structurally real signed grant does NOT bypass the wallet-network authority preflight: the same typed stop renders verbatim and nothing is admitted (the real-transition arm is unreachable on this isolated plane and is NOT claimed)",
      granted.status === 303
        && grantedPage.includes('data-ioi-refusal-stage="gateway"')
        && grantedPage.includes('data-ioi-refusal-code="system_genesis_authority_binding_unavailable"'),
      attr(grantedPage, "data-ioi-refusal-code") || granted.location.slice(0, 100));
  }

  // (c2) A declaration whose proposal is INVALID stops EARLIER at the compiler's typed blocker
  // refusal — the "missing profile refs" stop-point, asserted as its own rung (and the
  // contrast that makes rung 1's compiled-unmangled proof meaningful).
  const invalidDecl = clone(genesisBody);
  delete invalidDecl.proposed_instantiation.candidate.initial_profile_refs;
  const blocked = await postAction(`${LANE}/actions/genesis-compose`, {
    declaration: JSON.stringify(invalidDecl),
    return: LANE,
  });
  ok("REFUSAL LADDER rung 3 — a proposal missing its profile refs stops at the compiler's typed blocker refusal (system_genesis_proposal_invalid, before any authority), rendered verbatim",
    blocked.page.text.includes('data-ioi-refusal-code="system_genesis_proposal_invalid"')
      && blocked.page.text.includes('data-ioi-refusal-stage="gateway"'),
    attr(blocked.page.text, "data-ioi-refusal-code"));

  // (d) Readback: nothing was admitted, so the daemon owns the absence — detail renders the
  // typed not-found truth verbatim (no plausible System invented), and the inventory stays
  // honest_empty. On the real arm the detail renders the admitted Overview instead.
  const detail = await pageText(`${CANONICAL}?system=${recordTail}`);
  const detailState = attr(detail.text, "data-ioi-detail-state");
  if (realArm) {
    ok("REAL ARM: detail Overview renders the admitted identity from the admission record",
      detail.status === 200 && detailState === "admitted" && detail.text.includes(systemId),
      detailState);
  } else {
    ok("REFUSAL LADDER rung 4 — detail readback renders the daemon's OWN typed absence for the never-admitted System (system_genesis_not_found), verbatim — nothing substituted",
      detail.status === 200 && detailState === "system_genesis_not_found"
        && detail.text.includes("system_genesis_not_found"),
      detailState || `status ${detail.status}`);
    ok("the inventory stays honest through every refused crossing: zero effect, honest_empty verbatim, no row invented",
      await pageText(CANONICAL).then((r) => r.text.includes('data-ioi-projection-state="honest_empty"') && systemRows(r.text).length === 0),
      "");
  }

  // (e) Detail panes: Govern preview + Operate desired-vs-observed + Writer + Amendments all
  // render as live reads with typed states — zero fabricated rows anywhere.
  const paneStates = Object.fromEntries(
    ["membership-projection", "topology-minimum", "writer-epoch", "writer-lost-suffixes", "amendments"].map((pane) => {
      const m = detail.text.match(new RegExp(`data-ioi-pane="${pane}" data-ioi-pane-state="([^"]*)"`, "u"));
      return [pane, m ? m[1] : ""];
    }),
  );
  ok("Operate/Writer/Amendments panes render read-first with nonempty typed states (daemon truth or typed refusal verbatim — never a fabricated pane)",
    Object.values(paneStates).every((state) => state.length > 0) && systemRows(detail.text).length === 0,
    JSON.stringify(paneStates));
  ok("the Govern preview renders the governed ladder as live reads (admission stage present, preview-not-authority stated, approval verbs not here)",
    detail.text.includes('data-ioi-pane="govern-preview"')
      && detail.text.includes('data-ioi-ladder-stage="admission"')
      && detail.text.includes("Preview, not authority"),
    "");
  ok("desired-vs-observed renders as its two named panes (observed membership projection + declared minimum topology), each carrying its own truth state",
    detail.text.includes("Observed membership") && detail.text.includes("Desired topology"),
    "");
  ok("every unwired family verb is disabled WITH its named reason (membership ops, desired topology, writer transitions, amendment execution, initialize/activate/transitions/continuity) — read-first, never a second mutation path",
    (detail.text.match(/data-ioi-disabled-reason="[^"]*CapabilityLease[^"]*W2 continuation[^"]*"/gu) || []).length >= 8,
    `${(detail.text.match(/data-ioi-disabled-reason=/gu) || []).length} disabled controls`);
  ok("Interfaces stays the OQ-9 disabled named gap on the detail view",
    detail.text.includes('data-ioi-pane="interfaces"')
      && /data-ioi-disabled-reason="[^"]*OQ-9[^"]*"/u.test(detail.text),
    "");
  ok("no scheduler-health and no machinery content on the detail view",
    !/scheduler/iu.test(detail.text) && !/machinery/iu.test(detail.text),
    "");

  // (f) Sequence-zero — the second wired crossing — TRIED against the same daemon. On this
  // plane the admission never converged, so the daemon refuses the crossing typed; on a
  // wallet-carrying plane the same form crosses to the 403 materialize challenge and onward.
  const seqZero = await postAction(`${LANE}/actions/sequence-zero`, {
    system: recordTail,
    expected_genesis_admission_record_root: `sha256:${"0".repeat(64)}`,
    expected_genesis_admission_receipt_root: `sha256:${"0".repeat(64)}`,
    return: `${LANE}?system=${recordTail}`,
  });
  const seqZeroCode = attr(seqZero.page.text, "data-ioi-refusal-code");
  const seqZeroStage = attr(seqZero.page.text, "data-ioi-refusal-stage");
  ok(`REFUSAL LADDER rung 5 — the sequence-zero crossing stops typed for the unadmitted System and renders verbatim through the lease client (stage=${seqZeroStage || "?"}, code=${seqZeroCode || "?"})`,
    seqZero.status === 303 && seqZero.page.status === 200
      && (seqZeroStage === "gateway" || seqZeroStage === "wallet_challenge")
      && seqZeroCode.length > 0,
    `${seqZeroStage}/${seqZeroCode}`);

  // (g) The remaining ladder rungs are surface-owned typed refusals with ZERO daemon effect.
  const badKey = await postAction(`${LANE}/actions/sequence-zero`, { system: "not-a-key", return: LANE });
  ok("surface input refusal: a non-canonical System key never reaches the daemon (typed, zero effect)",
    badKey.page.text.includes('data-ioi-refusal-stage="input"')
      && badKey.page.text.includes('data-ioi-refusal-code="system_key_invalid"'),
    "");
  const badDecl = await postAction(`${LANE}/actions/genesis-compose`, { declaration: "{not json", return: LANE });
  ok("surface input refusal: an unparseable declaration never reaches the daemon (typed, zero effect)",
    badDecl.page.text.includes('data-ioi-refusal-code="system_declaration_unparseable"')
      && badDecl.page.text.includes("nothing was sent"),
    "");
  const badGrant = await postAction(`${LANE}/actions/genesis-compose`, {
    declaration,
    wallet_approval_grant: JSON.stringify({ bogus: true }),
    return: LANE,
  });
  ok("REFUSAL LADDER rung 6 — a non-canonical grant earns the daemon's typed 422 (system_genesis_wallet_grant_invalid), rendered verbatim",
    badGrant.page.text.includes('data-ioi-refusal-code="system_genesis_wallet_grant_invalid"'),
    attr(badGrant.page.text, "data-ioi-refusal-code"));

  // (h) The two lease-client lanes this plane cannot emit, asserted as RENDERING CONTRACTS
  // with representative facts — honest about what they prove: the 403 wallet-challenge lane
  // (the genesis route stops at the authority preflight BEFORE any challenge here; on a
  // wallet-carrying plane the same band renders the daemon's live commitments) and the 428
  // sealed-credential lane (the connector-gateway lane; no systems route emits it).
  const chPolicy = `sha256:${"ab".repeat(32)}`;
  const chRequest = `sha256:${"cd".repeat(32)}`;
  const chEffect = `sha256:${"ef".repeat(32)}`;
  const challengeLane = await pageText(`${LANE}?chS=wallet_challenge&chC=system_genesis_host_authority_required&chH=403&chSc=scope%3Aautonomous_system.genesis_admit&chA=org%3A%2F%2Facme%2Fresearch&chP=${chPolicy}&chR=${chRequest}&chE=${chEffect}&refused=system_genesis_host_authority_required&reason=owner+wallet+authority+required`);
  ok("the 403 wallet-challenge lane renders its hash-shaped public commitments as a named state (rendering contract — this plane's genesis route stops at the authority preflight before any challenge, stated honestly)",
    challengeLane.status === 200
      && challengeLane.text.includes('data-ioi-refusal-stage="wallet_challenge"')
      && challengeHash(challengeLane.text, "policy_hash") === chPolicy
      && challengeHash(challengeLane.text, "request_hash") === chRequest
      && challengeHash(challengeLane.text, "effect_hash") === chEffect
      && challengeLane.text.includes("scope:autonomous_system.genesis_admit"),
    "");
  const credentialLane = await pageText(`${LANE}?chS=credential&chC=credential_unresolved&chH=428&refused=credential_unresolved&reason=sealed+backing+credential+did+not+resolve`);
  ok("the 428 credential lane renders as a named state (rendering contract — no systems route emits 428 on this isolated plane, stated honestly)",
    credentialLane.status === 200
      && credentialLane.text.includes('data-ioi-refusal-stage="credential"')
      && credentialLane.text.includes("Sealed credential unresolved"),
    "");

  // -- daemon outage: typed unavailability, zero fabricated rows ---------------
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  const down = await pageText(CANONICAL);
  ok("daemon down: the inventory renders its typed unavailability with ZERO rows — nothing cached, nothing substituted",
    down.status === 200 && down.text.includes('data-ioi-projection-state="unavailable"')
      && down.text.includes("data-ioi-degraded=")
      && systemRows(down.text).length === 0,
    `status ${down.status}`);

  // -- restart: truth returns and the refusal posture re-renders IDENTICALLY ---
  await startDaemon();
  let back = { status: 0, text: "" };
  for (let attempt = 0; attempt < 5; attempt++) {
    await new Promise((r) => setTimeout(r, 1200));
    back = await pageText(CANONICAL);
    if (back.status === 200 && back.text.includes("data-ioi-projection-state=")
      && !back.text.includes('data-ioi-projection-state="unavailable"')) break;
  }
  const detailAfter = await pageText(`${CANONICAL}?system=${recordTail}`);
  if (realArm) {
    ok("REAL ARM continuity: the admitted System re-renders identically after restart",
      back.status === 200 && attr(detailAfter.text, "data-ioi-detail-state") === detailState,
      attr(detailAfter.text, "data-ioi-detail-state"));
  } else {
    ok("continuity across restart: the inventory returns to the same honest_empty truth (no refused crossing left anything that could fabricate a row)",
      back.status === 200 && back.text.includes('data-ioi-projection-state="honest_empty"')
        && systemRows(back.text).length === 0,
      attr(back.text, "data-ioi-projection-state"));
    ok("continuity across restart: the refusal posture re-renders IDENTICALLY (detail still the daemon's own typed absence — recovery holds without invention)",
      detailAfter.status === 200
        && attr(detailAfter.text, "data-ioi-detail-state") === "system_genesis_not_found"
        && attr(detailAfter.text, "data-ioi-detail-state") === detailState,
      attr(detailAfter.text, "data-ioi-detail-state"));
  }

  // -- the M1.6/M1.7 genesis cockpit keeps serving untouched -------------------
  const cockpit = await fetch(`${SERVE}/__ioi/systems`, { redirect: "manual", headers: SESSION ? { cookie: `ioi_session=${SESSION}` } : {} })
    .then((r) => ({ status: r.status, location: r.headers.get("location") || "" }))
    .catch(() => ({ status: 0, location: "" }));
  ok("the provisional /__ioi/systems genesis cockpit keeps serving untouched (302 to its packages census — the W4 cutover has not happened)",
    cockpit.status === 302 && cockpit.location === "/__ioi/systems/packages",
    `${cockpit.status}→${cockpit.location}`);

  // -- 3-posture matrix --------------------------------------------------------
  let pw = null;
  try { pw = await import("playwright"); } catch { pw = null; }
  if (!pw) {
    ok("posture matrix skipped — playwright unavailable", false, "install playwright to run the browser matrix");
  } else {
    const browser = await pw.chromium.launch();
    for (const [name, opts] of [
      ["light-desktop", { viewport: { width: 1440, height: 900 }, colorScheme: "light" }],
      ["dark-desktop", { viewport: { width: 1440, height: 900 }, colorScheme: "dark" }],
      ["narrow-reduced-motion", { viewport: { width: 390, height: 844 }, colorScheme: "light", reducedMotion: "reduce" }],
    ]) {
      const ctx = await browser.newContext(opts);
      const page = await ctx.newPage();
      const errors = [];
      page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
      const resp = await page.goto(`${SERVE}${CANONICAL}`, { waitUntil: "networkidle", timeout: 45000 }).catch(() => null);
      const body = resp ? await page.evaluate(() => document.body.innerText) : "";
      await page.keyboard.press("Tab");
      const focused = resp ? await page.evaluate(() => document.activeElement?.tagName ?? "") : "";
      ok(`posture ${name}: renders, keyboard-focusable, zero console errors`,
        resp && resp.status() === 200 && body.length > 0 && errors.length === 0 && focused !== "" && focused !== "BODY",
        errors[0]?.slice(0, 100) ?? `focus ${focused}`);
      await ctx.close();
    }
    await browser.close();
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  cleanup();
  process.exit(fails.length ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  cleanup();
  process.exit(1);
});

function cleanup() {
  try { serve?.kill("SIGTERM"); } catch { /* gone */ }
  try { daemon?.kill("SIGTERM"); } catch { /* gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* keep */ }
}
