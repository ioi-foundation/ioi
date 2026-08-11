#!/usr/bin/env node
// Packages lifecycle journey verifier (W2.3 bar, next-legs II Leg 2; recall + launcher join,
// next-legs III Leg 2 — the W2.3/W2.4 pull).
//
// Proves, against an ISOLATED real daemon + serve lane, the full chain the closed
// /v1/hypervisor/packages daemon family actually owns — candidate → immutable release →
// installation binding (FORCED DISABLED — the assertion is the binding truth, never
// launchability) → RECALL (the one disposition successor, active → recalled) → uninstall —
// through the UI action lane where the verbs exist there and direct daemon calls for
// setup/readback. Identity-first refusals, exact-head CAS conflicts (typed AND rendered
// verbatim), idempotent replay returning the original receipt, restart reconstruction, the
// canonical /packages + /packages/marketplace mounts, and the 3-posture browser matrix.
//
// What W2.3 stated as TYPED ABSENCE is now journeyed truth:
//   - RECALL VERB: POST .../releases/:digest/recall appends an immutable successor revision on
//     the release stream under exact-head CAS with a bounded verbatim reason; replay returns
//     the original receipt; a second recall refuses typed (package_release_not_recallable).
//   - CASCADE (derived at read): bindings keep their admitted bytes; every binding read
//     resolves the CURRENT release head, so a recalled release reads back on its bindings as
//     launch_eligible:false with surface_release_recalled — immediately and after restart —
//     and NEW installs over the recalled release refuse typed (package_release_not_installable).
//   - LAUNCHER JOIN: the product-surface projection consumes the registry namespace live —
//     the installed binding's surface://extensions/… ref appears in application_entries as an
//     honest INELIGIBLE entry (launchable:false, exact derived reasons); after recall (and
//     after uninstall) the surface is GONE from the feed, and stays gone across restart.
//   - The route inventory is EXACTLY the eight-route family (the seven W2.3 routes + recall).
//
// The owner scope is the daemon's own whoami answer, never a verifier constant.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");

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
try {
  fs.accessSync(daemonBinary, fs.constants.X_OK);
} catch {
  console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`);
  process.exit(2);
}

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-packages-journey-"));
let daemon = null;
let serve = null;
let daemonPort = 0;
let DAEMON = "";
let SERVE = "";
let SESSION = "";

const PKG = "packages-journey-app";
const INST = "primary";
const LANE = "/__ioi/packages/registry";
const SURFACE_REF = `surface://extensions/${PKG}`;

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

// Daemon JSON with the operator session (the family is identity-first on reads AND writes).
const jd = (p, init) => fetch(`${DAEMON}${p}`, {
  headers: {
    "content-type": "application/json",
    ...(SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
  },
  ...init,
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
  .catch(() => ({ status: 0, body: {} }));

// A served page, optionally carrying the operator session — the module's reads ride the
// request's own identity envelope, so the SAME page is registry truth for the operator and a
// typed refusal band for an anonymous caller.
const pageText = (p, { authenticated = true } = {}) => fetch(`${SERVE}${p}`, {
  headers: authenticated && SESSION ? { cookie: `ioi_session=${SESSION}` } : {},
}).then(async (r) => ({ status: r.status, text: await r.text(), headers: r.headers }))
  .catch(() => ({ status: 0, text: "", headers: new Headers() }));

// A module action POST on the legacy lane: form-encoded, PRG 303, result in the redirect query.
async function act(tail, fields, { authenticated = true } = {}) {
  const r = await fetch(`${SERVE}${LANE}${tail}`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(authenticated && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
    },
    body: new URLSearchParams(fields).toString(),
    redirect: "manual",
  }).catch(() => null);
  const location = r?.headers?.get("location") || "";
  const q = new URLSearchParams(location.split("?")[1]?.split("#")[0] ?? "");
  return { status: r?.status ?? 0, location, q };
}

const pkgGet = async () => (await jd(`/v1/hypervisor/packages/${PKG}`)).body;
const relGet = async (digest) => (await jd(`/v1/hypervisor/packages/${PKG}/releases/${encodeURIComponent(digest)}`)).body;
const instGet = async (digest) => (await jd(`/v1/hypervisor/packages/${PKG}/releases/${encodeURIComponent(digest)}/installations/${INST}`)).body;
// The launcher feed — the product-surface compiler projection, requested under the caller's
// own org so the registry join answers for the same owner the bindings were admitted under.
const launcherFeed = async (orgRef) => (await jd("/v1/hypervisor/product-surface-projections", {
  method: "POST",
  body: JSON.stringify(orgRef ? { org_ref: orgRef } : {}),
})).body;

function packageFamilyRoutes(index) {
  return (index.families ?? [])
    .flatMap((family) => family.paths ?? [])
    .filter((row) => row.path.startsWith("/v1/hypervisor/packages"))
    .map((row) => ({ path: row.path, methods: [...row.methods].sort() }))
    .sort((left, right) => left.path.localeCompare(right.path));
}

async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  const daemonLogFn = await startDaemon();
  const token = daemonLogFn().match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ token, password: "packages-journey-bootstrap-v1", email: "packages-journey@ioi.local" }),
    });
    SESSION = boot.body?.session_token ?? "";
  }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));

  const who = (await jd("/v1/hypervisor/auth/whoami")).body || {};
  const OWNER = (who.principal?.tenant_refs || []).find((t) => typeof t === "string" && t.startsWith("org://")) || "";
  ok("the session authenticates a principal with an org:// owner tenant to admit under", !!OWNER, OWNER || "no owner tenant");

  // -- the admitted family is EXACTLY the eight candidate/release/recall/installation routes:
  // the W2.3 seven-route slice plus the ONE disposition successor verb this leg lands. The
  // inventory is mechanical (derived from the daemon's own route registrations), so a stray
  // deprecate/revoke/enable verb would fail here, not hide.
  const index = await jd("/v1");
  const familyRoutes = packageFamilyRoutes(index.body);
  const expectedRoutes = [
    { path: "/v1/hypervisor/packages", methods: ["GET", "POST"] },
    { path: "/v1/hypervisor/packages/:package_id", methods: ["GET"] },
    { path: "/v1/hypervisor/packages/:package_id/releases", methods: ["GET", "POST"] },
    { path: "/v1/hypervisor/packages/:package_id/releases/:release_digest", methods: ["GET"] },
    { path: "/v1/hypervisor/packages/:package_id/releases/:release_digest/recall", methods: ["POST"] },
    { path: "/v1/hypervisor/packages/:package_id/releases/:release_digest/installations", methods: ["GET", "POST"] },
    { path: "/v1/hypervisor/packages/:package_id/releases/:release_digest/installations/:installation_id", methods: ["GET"] },
    { path: "/v1/hypervisor/packages/:package_id/releases/:release_digest/installations/:installation_id/uninstall", methods: ["POST"] },
  ].sort((left, right) => left.path.localeCompare(right.path));
  ok("recall verb LANDS: the package family route inventory is exactly the eight-route slice — the seven W2.3 routes plus POST .../recall, and still no deprecate/revoke/enable route",
    JSON.stringify(familyRoutes) === JSON.stringify(expectedRoutes),
    JSON.stringify(familyRoutes.map((r) => r.path)));

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
  await waitFor(`${SERVE}/packages`, 30000);

  // -- canonical mounts render with truthful ownership -----------------------
  const anonLanding = await pageText("/packages", { authenticated: false });
  ok("canonical /packages 200s as the module's own mount (ownership headers)",
    anonLanding.status === 200 && anonLanding.headers.get("x-ioi-surface-route") === "/packages" && anonLanding.headers.get("x-ioi-surface-owner") === "Packages",
    `status ${anonLanding.status} route ${anonLanding.headers.get("x-ioi-surface-route")}`);
  ok("an ANONYMOUS /packages render shows the family's typed identity refusal, never fabricated rows (identity-first reads)",
    anonLanding.text.includes("request_principal_required") && anonLanding.text.includes("Packages"),
    "");
  const mkt = await pageText("/packages/marketplace", { authenticated: false });
  ok("canonical /packages/marketplace renders the read-first Marketplace MODE under the Packages owner",
    mkt.status === 200 && mkt.headers.get("x-ioi-surface-route") === "/packages/marketplace" && mkt.headers.get("x-ioi-surface-owner") === "Packages"
      && mkt.text.includes("Packages / Marketplace") && mkt.text.includes("never becomes a second package owner"),
    `status ${mkt.status} route ${mkt.headers.get("x-ioi-surface-route")}`);
  ok("the marketplace mode is HONEST-EMPTY over the empty substrate (no fixture listings) with the ladder named to its owner lane",
    mkt.text.includes("No marketplace listings") && mkt.text.includes('data-ioi-disabled-reason='),
    "");
  const legacyRegistry = await pageText(LANE, { authenticated: false });
  const legacyMkt = await pageText("/__ioi/packages/marketplace", { authenticated: false });
  ok("the fresh legacy lanes serve the same module with their own truthful markers",
    legacyRegistry.status === 200 && legacyRegistry.headers.get("x-ioi-surface-route") === LANE
      && legacyMkt.status === 200 && legacyMkt.headers.get("x-ioi-surface-route") === "/__ioi/packages/marketplace",
    "");
  const seedListings = await pageText("/__ioi/marketplace/listings", { authenticated: false });
  ok("the /__ioi/marketplace/listings seed lane keeps serving untouched (seed preservation)",
    seedListings.status === 200, `status ${seedListings.status}`);

  // -- ODK source mesh fixtures (direct daemon setup — the packaging lane's admission inputs) --
  const ont = await jd("/v1/hypervisor/odk/domain-ontologies", {
    method: "POST",
    body: JSON.stringify({ domain: "packages-journey", owner_ref: OWNER, idempotency_key: "packages-journey-ont-1" }),
  });
  const ontRef = ont.body?.ontology?.ref || "";
  const sd = await jd("/v1/hypervisor/odk/surface-descriptors", {
    method: "POST",
    body: JSON.stringify({ name: "Packages journey surface", composition_pattern: "domain_app", ontology_ref: ontRef, owner_ref: OWNER, idempotency_key: "packages-journey-sd-1" }),
  });
  const sdRef = sd.body?.surface_descriptor?.ref || "";
  const man = await jd("/v1/hypervisor/odk/manifests", {
    method: "POST",
    body: JSON.stringify({ name: "Packages journey manifest", ontology_refs: [ontRef], recipe_refs: [], surface_descriptor_refs: [sdRef], owner_ref: OWNER, idempotency_key: "packages-journey-man-1" }),
  });
  const manRef = man.body?.manifest?.ref || "";
  const dapp = await jd("/v1/hypervisor/domain-apps", {
    method: "POST",
    body: JSON.stringify({ name: "Packages journey app", surface_descriptor_ref: sdRef, odk_manifest_ref: manRef, owner_ref: OWNER, idempotency_key: "packages-journey-dapp-1" }),
  });
  const dappRef = dapp.body?.domain_app?.domain_app_ref || "";
  ok("the ODK source mesh admits (ontology → domain_app descriptor → manifest → draft DomainApp)",
    ont.status === 201 && sd.status === 201 && man.status === 201 && dapp.status === 201 && !!dappRef,
    dappRef || `statuses ${ont.status}/${sd.status}/${man.status}/${dapp.status}`);

  // -- identity-first refusal through the UI action lane ----------------------
  const anonAdmit = await act("/actions/admit-candidate", {
    owner_ref: OWNER, package_id: PKG, domain_app_ref: dappRef,
    idempotency_key: "packages-journey-candidate-1", return: LANE,
  }, { authenticated: false });
  ok("an unauthenticated candidate admission refuses TYPED (request_principal_required, no record)",
    anonAdmit.status === 303 && anonAdmit.q.get("refused") === "request_principal_required",
    anonAdmit.q.get("refused") || "");

  // -- candidate admission through the UI action lane -------------------------
  const admitted = await act("/actions/admit-candidate", {
    owner_ref: OWNER, package_id: PKG, domain_app_ref: dappRef,
    idempotency_key: "packages-journey-candidate-1", return: LANE,
  });
  const candidateReceipt = admitted.q.get("receipt") || "";
  ok("candidate admission crosses with admission evidence (303 acted + receipt:// + record)",
    admitted.status === 303 && admitted.q.get("acted") === "admit-candidate" && candidateReceipt.startsWith("receipt://") && admitted.q.get("record") === PKG,
    admitted.location.slice(0, 140));
  let candidate = await pkgGet();
  const candidateHead = candidate.package?.agentgres?.head || "";
  const snaps = candidate.package?.record?.source_snapshots || {};
  ok("the admitted candidate freezes the source mesh content-addressed and NAMES the missing registration",
    candidate.ok === true && candidate.package?.record?.registration_state === "absent"
      && candidate.package?.record?.surface_class === "extension_application"
      && [snaps.domain_app_content_hash, snaps.odk_manifest_content_hash, snaps.surface_descriptor_content_hash].every((v) => /^sha256:[0-9a-f]{64}$/u.test(v || ""))
      && !!candidateHead,
    `head ${String(candidateHead).slice(0, 14)}…`);

  // -- idempotent replay through the UI lane returns the ORIGINAL receipt -----
  const replay = await act("/actions/admit-candidate", {
    owner_ref: OWNER, package_id: PKG, domain_app_ref: dappRef,
    idempotency_key: "packages-journey-candidate-1", return: LANE,
  });
  ok("an exact candidate retry REPLAYS: same receipt_ref, replayed result, head unchanged",
    replay.status === 303 && replay.q.get("receipt") === candidateReceipt && replay.q.get("result") === "replayed"
      && (await pkgGet()).package?.agentgres?.head === candidateHead,
    `${replay.q.get("result")} ${replay.q.get("receipt")?.slice(0, 40)}`);

  // -- the operator's registry pages render admitted truth --------------------
  const catalogPage = await pageText("/packages");
  ok("the authenticated /packages catalog renders the candidate with its registration-absent truth",
    catalogPage.status === 200 && catalogPage.text.includes(PKG) && catalogPage.text.includes("registration absent"),
    "");
  const pkgPage = await pageText(`/packages?pkg=${PKG}`);
  ok("the package detail seeds the exact admitted head into the release CAS form",
    pkgPage.status === 200 && pkgPage.text.includes(`name="expected_package_head" value="${candidateHead}"`)
      && pkgPage.text.includes(candidate.package?.record?.candidate_content_hash || "@"),
    "");

  // -- immutable release through the UI action lane ---------------------------
  const releaseCut = await act(`/${PKG}/cut-release`, {
    idempotency_key: "packages-journey-release-1",
    expected_package_head: candidateHead,
    surface_distribution: "private_registry",
    surface_capability_depth: "propose",
    object_contract_refs: "object-model://packages-journey",
    action_contract_refs: "action://packages-journey/propose",
    evidence_refs: "artifact://packages-journey/conformance",
    return: `${LANE}?pkg=${PKG}`,
  });
  const releaseDigest = releaseCut.q.get("record") || "";
  ok("release admission crosses with admission evidence (303 acted + receipt + content-addressed digest)",
    releaseCut.status === 303 && releaseCut.q.get("acted") === "cut-release"
      && (releaseCut.q.get("receipt") || "").startsWith("receipt://") && /^sha256:[0-9a-f]{64}$/u.test(releaseDigest),
    releaseCut.location.slice(0, 140));
  let release = await relGet(releaseDigest);
  const releaseHead = release.release?.agentgres?.head || "";
  ok("the release is immutable canonical truth: admitted + active disposition, candidate receipt bound as evidence, recall_reason null on the genesis admission",
    release.ok === true && release.release?.record?.surface_admission_state === "admitted"
      && release.release?.record?.surface_package_disposition === "active"
      && (release.release?.record?.evidence_refs || []).includes(candidateReceipt)
      && release.release?.recall_reason == null
      && !!releaseHead,
    "");

  // -- CAS conflict: typed AND rendered verbatim ------------------------------
  const staleRelease = await act(`/${PKG}/cut-release`, {
    idempotency_key: "packages-journey-release-stale",
    expected_package_head: `sha256:${"0".repeat(64)}`,
    surface_distribution: "private_registry",
    surface_capability_depth: "propose",
    object_contract_refs: "object-model://packages-journey",
    action_contract_refs: "action://packages-journey/propose",
    return: `${LANE}?pkg=${PKG}`,
  });
  ok("a stale expected_package_head refuses TYPED (package_expected_head_conflict)",
    staleRelease.status === 303 && staleRelease.q.get("refused") === "package_expected_head_conflict",
    staleRelease.q.get("refused") || "");
  const stalePage = await pageText(staleRelease.location.split("#")[0]);
  const releasesAfterStale = await jd(`/v1/hypervisor/packages/${PKG}/releases`);
  ok("the CAS refusal renders VERBATIM with the fresh-head remedy, state unchanged (still exactly one release)",
    stalePage.status === 200 && stalePage.text.includes("package_expected_head_conflict")
      && stalePage.text.includes("re-open") && stalePage.text.includes("state unchanged")
      && (releasesAfterStale.body?.releases || []).length === 1,
    "");

  // -- installation: contract narrowing enforced, then the disabled binding ---
  const widening = await act(`/${PKG}/install`, {
    idempotency_key: "packages-journey-install-widening",
    release_digest: releaseDigest,
    expected_release_head: releaseHead,
    installation_id: "widening",
    visibility: "organization",
    allowed_object_contract_refs: "object-model://packages-journey",
    allowed_action_refs: "action://not-in-release",
    return: `${LANE}?pkg=${PKG}&rel=${encodeURIComponent(releaseDigest)}`,
  });
  ok("an installation that would WIDEN the release contract set refuses typed (package_installation_contract_widening)",
    widening.status === 303 && widening.q.get("refused") === "package_installation_contract_widening",
    widening.q.get("refused") || "");
  const installed = await act(`/${PKG}/install`, {
    idempotency_key: "packages-journey-install-1",
    release_digest: releaseDigest,
    expected_release_head: releaseHead,
    installation_id: INST,
    visibility: "organization",
    allowed_object_contract_refs: "object-model://packages-journey",
    allowed_action_refs: "action://packages-journey/propose",
    return: `${LANE}?pkg=${PKG}&rel=${encodeURIComponent(releaseDigest)}`,
  });
  ok("installation crosses with admission evidence (303 acted + receipt + binding id)",
    installed.status === 303 && installed.q.get("acted") === "install-release"
      && (installed.q.get("receipt") || "").startsWith("receipt://") && installed.q.get("record") === INST,
    installed.location.slice(0, 140));
  let binding = await instGet(releaseDigest);
  const installationHead = binding.installation?.agentgres?.head || "";
  ok("the binding is REAL and FORCED DISABLED — the asserted truth is the binding, never launchability: installed + disabled + launch_eligible:false + the daemon's exact DERIVED reason codes + active release disposition + registration absent",
    binding.ok === true
      && binding.installation?.record?.surface_installation_state === "installed"
      && binding.installation?.record?.surface_enablement_state === "disabled"
      && binding.installation?.launch_eligible === false
      && JSON.stringify(binding.installation?.disabled_reason_codes) === JSON.stringify(["extension_application_registration_absent", "surface_serving_binding_absent"])
      && binding.installation?.release_disposition === "active"
      && binding.installation?.registration_state === "absent"
      && !!installationHead,
    JSON.stringify(binding.installation?.disabled_reason_codes));
  const instPage = await pageText(`/packages?pkg=${PKG}&rel=${encodeURIComponent(releaseDigest)}&inst=${INST}`);
  ok("the installation page renders the forced-disabled truth VERBATIM: launch_eligible false, the derived reason pair, the active release disposition, the enable named gap, and the live launcher-join doctrine",
    instPage.status === 200
      && instPage.text.includes("launch_eligible: false")
      && instPage.text.includes("extension_application_registration_absent")
      && instPage.text.includes("surface_serving_binding_absent")
      && instPage.text.includes("release active")
      && instPage.text.includes('data-ioi-disabled-reason=')
      && instPage.text.includes("Launcher feed (live join)"),
    "");

  // -- LAUNCHER JOIN: the projection consumes the registry namespace ----------
  let feed = await launcherFeed();
  let feedEntry = (feed.application_entries || []).find((e) => e.identity_ref === SURFACE_REF);
  ok("launcher join PRESENT: the product-surface projection consumes the registry namespace — the installed binding's surface ref appears in application_entries under the caller's own org as an honest INELIGIBLE entry",
    Array.isArray(feed.application_entries) && feed.application_entries.length > 0
      && feed.org_ref === OWNER && !!feedEntry,
    feedEntry ? feedEntry.identity_ref : `entries ${feed.application_entries?.length ?? "none"} org ${feed.org_ref}`);
  ok("the feed entry carries the EXACT eligibility facts, never a launch claim: launchable false, the derived reason pair, active disposition, the binding + release refs, registry entry source",
    !!feedEntry && feedEntry.launchable === false
      && JSON.stringify(feedEntry.disabled_reason_codes) === JSON.stringify(["extension_application_registration_absent", "surface_serving_binding_absent"])
      && feedEntry.release_disposition === "active"
      && feedEntry.entry_source === "hypervisor-package-registry"
      && feedEntry.installation_ref === `install://${PKG}/${INST}`
      && feedEntry.resolved_launch_route === null
      && feedEntry.surface_enablement_state === "disabled",
    JSON.stringify(feedEntry ?? {}).slice(0, 200));

  // -- RECALL: identity-first, successor revision, receipts, replay, CAS ------
  const anonRecall = await act(`/${PKG}/recall`, {
    idempotency_key: "packages-journey-recall-anon",
    release_digest: releaseDigest,
    expected_release_head: releaseHead,
    reason: "anonymous recall must refuse",
    return: `${LANE}?pkg=${PKG}&rel=${encodeURIComponent(releaseDigest)}`,
  }, { authenticated: false });
  ok("an ANONYMOUS recall refuses TYPED (request_principal_required) — identity-first on the successor verb, state unchanged",
    anonRecall.status === 303 && anonRecall.q.get("refused") === "request_principal_required"
      && (await relGet(releaseDigest)).release?.record?.surface_package_disposition === "active",
    anonRecall.q.get("refused") || "");
  const RECALL_REASON = "conformance defect: the packaged surface misreports its capability depth";
  const recalled = await act(`/${PKG}/recall`, {
    idempotency_key: "packages-journey-recall-1",
    release_digest: releaseDigest,
    expected_release_head: releaseHead,
    reason: RECALL_REASON,
    return: `${LANE}?pkg=${PKG}&rel=${encodeURIComponent(releaseDigest)}`,
  });
  const recallReceipt = recalled.q.get("receipt") || "";
  ok("recall crosses under exact-head CAS with admission evidence (303 acted + receipt, result recalled)",
    recalled.status === 303 && recalled.q.get("acted") === "recall-release"
      && recallReceipt.startsWith("receipt://") && recalled.q.get("result") === "recalled",
    recalled.location.slice(0, 140));
  release = await relGet(releaseDigest);
  const recallHead = release.release?.agentgres?.head || "";
  ok("the recall is an IMMUTABLE SUCCESSOR REVISION on the release stream: disposition recalled, the bounded reason verbatim, same release_ref, head advanced, admission state untouched",
    release.ok === true && release.release?.record?.surface_package_disposition === "recalled"
      && release.release?.recall_reason === RECALL_REASON
      && release.release?.record?.surface_admission_state === "admitted"
      && release.release?.record?.release_ref === `package://${PKG}/release/${releaseDigest}`
      && !!recallHead && recallHead !== releaseHead,
    `head ${String(recallHead).slice(0, 14)}…`);
  const recallReplay = await act(`/${PKG}/recall`, {
    idempotency_key: "packages-journey-recall-1",
    release_digest: releaseDigest,
    expected_release_head: recallHead,
    reason: RECALL_REASON,
    return: `${LANE}?pkg=${PKG}&rel=${encodeURIComponent(releaseDigest)}`,
  });
  ok("an exact recall retry REPLAYS the original transition (same receipt, head unchanged)",
    recallReplay.status === 303 && recallReplay.q.get("receipt") === recallReceipt
      && (await relGet(releaseDigest)).release?.agentgres?.head === recallHead,
    recallReplay.q.get("receipt")?.slice(0, 40) || "");
  const staleRecall = await act(`/${PKG}/recall`, {
    idempotency_key: "packages-journey-recall-stale",
    release_digest: releaseDigest,
    expected_release_head: releaseHead,
    reason: "stale head must refuse",
    return: `${LANE}?pkg=${PKG}&rel=${encodeURIComponent(releaseDigest)}`,
  });
  ok("a stale recall head under a NEW key refuses typed (package_expected_head_conflict)",
    staleRecall.status === 303 && staleRecall.q.get("refused") === "package_expected_head_conflict",
    staleRecall.q.get("refused") || "");
  const doubleRecall = await act(`/${PKG}/recall`, {
    idempotency_key: "packages-journey-recall-2",
    release_digest: releaseDigest,
    expected_release_head: recallHead,
    reason: "a second recall must refuse",
    return: `${LANE}?pkg=${PKG}&rel=${encodeURIComponent(releaseDigest)}`,
  });
  ok("recalling an already-recalled release refuses typed (package_release_not_recallable) — the transition is one-way and one-shot",
    doubleRecall.status === 303 && doubleRecall.q.get("refused") === "package_release_not_recallable",
    doubleRecall.q.get("refused") || "");

  // -- the CASCADE is derived at read: binding ineligible naming the recall ---
  binding = await instGet(releaseDigest);
  ok("the recall CASCADES to the binding at read time WITHOUT mutating it: same admitted head and revision, launch_eligible false, surface_release_recalled leads the derived reasons, the bounded reason travels verbatim",
    binding.ok === true
      && binding.installation?.agentgres?.head === installationHead
      && binding.installation?.record?.revision === 1
      && binding.installation?.launch_eligible === false
      && binding.installation?.release_disposition === "recalled"
      && binding.installation?.release_recall_reason === RECALL_REASON
      && JSON.stringify(binding.installation?.disabled_reason_codes) === JSON.stringify(["surface_release_recalled", "extension_application_registration_absent", "surface_serving_binding_absent"]),
    JSON.stringify(binding.installation?.disabled_reason_codes));
  const installOnRecalled = await act(`/${PKG}/install`, {
    idempotency_key: "packages-journey-install-after-recall",
    release_digest: releaseDigest,
    expected_release_head: recallHead,
    installation_id: "post-recall",
    visibility: "organization",
    return: `${LANE}?pkg=${PKG}&rel=${encodeURIComponent(releaseDigest)}`,
  });
  ok("a NEW installation over the recalled release refuses typed (package_release_not_installable)",
    installOnRecalled.status === 303 && installOnRecalled.q.get("refused") === "package_release_not_installable",
    installOnRecalled.q.get("refused") || "");

  // -- the recalled surface is GONE from the launcher feed --------------------
  feed = await launcherFeed();
  ok("launcher join LOSS: after recall the surface ref is GONE from the projection entirely (no entry, no residue anywhere in the reply) while the compiled estate keeps projecting",
    Array.isArray(feed.application_entries) && feed.application_entries.length > 0
      && !JSON.stringify(feed).includes(SURFACE_REF),
    `entries ${feed.application_entries?.length ?? "none"}`);

  // -- the pages render the recall truth verbatim -----------------------------
  const relPageRecalled = await pageText(`/packages?pkg=${PKG}&rel=${encodeURIComponent(releaseDigest)}`);
  ok("the release page renders the recalled disposition, the verbatim reason, the replay-only band, and withholds the install form naming the daemon's refusal",
    relPageRecalled.status === 200 && relPageRecalled.text.includes("recalled")
      && relPageRecalled.text.includes(RECALL_REASON)
      && relPageRecalled.text.includes("Already recalled")
      && relPageRecalled.text.includes("package_release_not_installable"),
    "");
  const instPageRecalled = await pageText(`/packages?pkg=${PKG}&rel=${encodeURIComponent(releaseDigest)}&inst=${INST}`);
  ok("the binding page renders the derived cascade verbatim: surface_release_recalled among the reasons, the recall reason text, launch_eligible false",
    instPageRecalled.status === 200 && instPageRecalled.text.includes("surface_release_recalled")
      && instPageRecalled.text.includes(RECALL_REASON)
      && instPageRecalled.text.includes("launch_eligible: false"),
    "");

  // -- restart: recalled disposition, cascade, and feed truth all reconstruct --
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  await startDaemon();
  candidate = await pkgGet();
  release = await relGet(releaseDigest);
  binding = await instGet(releaseDigest);
  ok("candidate, recalled release, and installation reconstruct after a daemon restart with EXACT heads",
    candidate.package?.agentgres?.head === candidateHead
      && release.release?.agentgres?.head === recallHead
      && binding.installation?.agentgres?.head === installationHead,
    "");
  feed = await launcherFeed();
  ok("the recalled disposition, the derived binding cascade, and the launcher-feed absence all SURVIVE restart (derived from admitted truth, not process state)",
    release.release?.record?.surface_package_disposition === "recalled"
      && release.release?.recall_reason === RECALL_REASON
      && binding.installation?.release_disposition === "recalled"
      && JSON.stringify(binding.installation?.disabled_reason_codes) === JSON.stringify(["surface_release_recalled", "extension_application_registration_absent", "surface_serving_binding_absent"])
      && Array.isArray(feed.application_entries) && feed.application_entries.length > 0
      && !JSON.stringify(feed).includes(SURFACE_REF),
    "");
  let reload = { status: 0, text: "" };
  for (let attempt = 0; attempt < 3; attempt++) {
    await new Promise((r) => setTimeout(r, 1500));
    reload = await pageText(`/packages?pkg=${PKG}`);
    if (reload.status === 200 && reload.text.includes(PKG)) break;
  }
  ok("the canonical registry view re-renders admitted state after restart",
    reload.status === 200 && reload.text.includes(PKG) && reload.text.includes(candidateHead),
    `status ${reload.status}`);

  // -- uninstall still operates over the recalled release (the cleanup path) --
  const uninstalled = await act(`/${PKG}/uninstall`, {
    idempotency_key: "packages-journey-uninstall-1",
    release_digest: releaseDigest,
    installation_id: INST,
    expected_installation_head: installationHead,
    return: `${LANE}?pkg=${PKG}&rel=${encodeURIComponent(releaseDigest)}&inst=${INST}`,
  });
  const uninstallReceipt = uninstalled.q.get("receipt") || "";
  ok("uninstall crosses under exact-head CAS (303 acted + receipt, result uninstalled)",
    uninstalled.status === 303 && uninstalled.q.get("acted") === "uninstall"
      && uninstallReceipt.startsWith("receipt://") && uninstalled.q.get("result") === "uninstalled",
    uninstalled.location.slice(0, 140));
  binding = await instGet(releaseDigest);
  const uninstalledHead = binding.installation?.agentgres?.head || "";
  ok("uninstall IMMEDIATELY revokes the binding: state uninstalled, immutable revision 2, launch_eligible stays false, the derived reasons name BOTH the uninstall and the recall, head advanced",
    binding.installation?.record?.surface_installation_state === "uninstalled"
      && binding.installation?.record?.revision === 2
      && binding.installation?.record?.surface_enablement_state === "disabled"
      && binding.installation?.launch_eligible === false
      && JSON.stringify(binding.installation?.disabled_reason_codes) === JSON.stringify(["surface_installation_uninstalled", "surface_release_recalled", "extension_application_registration_absent", "surface_serving_binding_absent"])
      && !!uninstalledHead && uninstalledHead !== installationHead,
    `state ${binding.installation?.record?.surface_installation_state} rev ${binding.installation?.record?.revision}`);
  const uninstallReplay = await act(`/${PKG}/uninstall`, {
    idempotency_key: "packages-journey-uninstall-1",
    release_digest: releaseDigest,
    installation_id: INST,
    expected_installation_head: uninstalledHead,
    return: `${LANE}?pkg=${PKG}&rel=${encodeURIComponent(releaseDigest)}&inst=${INST}`,
  });
  ok("an exact uninstall retry REPLAYS the original transition (same receipt, head unchanged)",
    uninstallReplay.status === 303 && uninstallReplay.q.get("receipt") === uninstallReceipt
      && (await instGet(releaseDigest)).installation?.agentgres?.head === uninstalledHead,
    uninstallReplay.q.get("receipt")?.slice(0, 40) || "");
  const staleUninstall = await act(`/${PKG}/uninstall`, {
    idempotency_key: "packages-journey-uninstall-stale",
    release_digest: releaseDigest,
    installation_id: INST,
    expected_installation_head: installationHead,
    return: `${LANE}?pkg=${PKG}&rel=${encodeURIComponent(releaseDigest)}&inst=${INST}`,
  });
  ok("a stale uninstall head under a NEW key refuses typed (package_expected_head_conflict)",
    staleUninstall.status === 303 && staleUninstall.q.get("refused") === "package_expected_head_conflict",
    staleUninstall.q.get("refused") || "");
  const instPageAfter = await pageText(`/packages?pkg=${PKG}&rel=${encodeURIComponent(releaseDigest)}&inst=${INST}`);
  ok("the uninstalled binding renders its terminal truth (uninstalled state + launch_eligible false + the immutable-history band)",
    instPageAfter.status === 200 && instPageAfter.text.includes("uninstalled")
      && instPageAfter.text.includes("launch_eligible: false")
      && instPageAfter.text.includes("Already uninstalled"),
    "");
  feed = await launcherFeed();
  ok("after uninstall the surface STAYS gone from the launcher feed (recalled + uninstalled: absent for two derived reasons, still zero residue)",
    Array.isArray(feed.application_entries) && !JSON.stringify(feed).includes(SURFACE_REF),
    "");

  // -- 3-posture matrix -------------------------------------------------------
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
      const resp = await page.goto(`${SERVE}/packages`, { waitUntil: "networkidle", timeout: 45000 }).catch(() => null);
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
