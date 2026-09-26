#!/usr/bin/env node
// THE DOMAINAPP CHAIN, THROUGH THE PRODUCT'S OWN FORMS (R-240).
//
// Proves, against an ISOLATED real daemon + serve lane (never the shared dev processes), that a
// person can build and release a package without leaving the product: an ontology draft gains a type
// and is PUBLISHED from Ontology Manager's History as an M05.1 revision; Studio's descriptor form binds
// that revision; ODK's manifest form lists the ontology and the descriptor; the New Domain App form
// builds a draft app over both; Packages freezes it as a candidate and cuts a release; the app is then
// edited and a second one deleted through their own forms, and a kill switch on it trips and enforces.
//
// Every write submits the form the surface RENDERED — its action, its hidden values, and only options
// it offers — and every outcome is read back from the daemon. The chain was dead at four links before
// this gate existed, each invisible to the dead-control census because a form refused on every submit
// never writes: no surface published a revision; the Domain App form sent no owner or idempotency key
// (every create, save, delete, mount and serve refused); a v2 DomainApp's identity was read under its
// v1 name (Packages offered it with an empty value; its links and the create redirect landed on "not
// found"); and the daemon's patch route refused the very owner claim its own write foundation requires.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
//   node apps/hypervisor/scripts/verify-hypervisor-domainapp-chain-forms.mjs

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  srv.on("error", reject);
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try { const r = await fetch(url); if (r.status < 500) return; } catch { /* not up yet */ }
    await sleep(400);
  }
  throw new Error(`timeout waiting for ${url}`);
};

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try { fs.accessSync(daemonBinary, fs.constants.X_OK); } catch {
  console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`);
  process.exit(2);
}

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-domainapp-chain-forms-"));
let daemon = null, serve = null, DAEMON = "", SERVE = "", COOKIE = "";

// The form the page RENDERED that posts to `action`: its fields with the values a browser would send
// untouched (a checkbox only when checked, each select's selected option), and what each choice offers.
const unesc = (s) => String(s).replace(/&quot;/gu, '"').replace(/&#39;/gu, "'").replace(/&gt;/gu, ">").replace(/&lt;/gu, "<").replace(/&amp;/gu, "&");
const attrOf = (tag, name) => { const m = tag.match(new RegExp(`\\b${name}="([^"]*)"`, "u")); return m ? unesc(m[1]) : null; };
function renderedForm(html, action) {
  const at = html.lastIndexOf(`action="${action}"`);
  if (at < 0) return null;
  const inner = html.slice(html.lastIndexOf("<form", at), html.indexOf("</form>", at));
  const names = new Set([...inner.matchAll(/\bname="([^"]+)"/gu)].map((m) => m[1]));
  const values = [];
  const options = {};
  for (const [tag] of inner.matchAll(/<input\b[^>]*>/gu)) {
    const name = attrOf(tag, "name");
    const type = (attrOf(tag, "type") || "text").toLowerCase();
    if (!name || ["submit", "button", "file", "image", "reset"].includes(type)) continue;
    if (type === "checkbox" || type === "radio") {
      (options[name] ||= new Set()).add(attrOf(tag, "value") ?? "on");
      if (!/\bchecked\b/u.test(tag)) continue;
    }
    values.push([name, attrOf(tag, "value") ?? (type === "checkbox" ? "on" : "")]);
  }
  for (const m of inner.matchAll(/<select\b([^>]*)>([\s\S]*?)<\/select>/gu)) {
    const name = attrOf(m[1], "name");
    const offered = [...m[2].matchAll(/<option\b([^>]*)>/gu)].map((o) => o[1]);
    const chosen = offered.find((o) => /\bselected\b/u.test(o)) ?? offered[0];
    if (name) options[name] = new Set(offered.map((o) => attrOf(o, "value") ?? ""));
    if (name && chosen !== undefined) values.push([name, attrOf(chosen, "value") ?? ""]);
  }
  for (const m of inner.matchAll(/<textarea\b([^>]*)>([\s\S]*?)<\/textarea>/gu)) {
    const name = attrOf(m[1], "name");
    if (name) values.push([name, unesc(m[2])]);
  }
  return { names, values, options };
}

const page = async (route, { anonymous = false } = {}) => {
  const r = await fetch(`${SERVE}${route}`, { headers: { accept: "text/html", ...(anonymous ? {} : { cookie: COOKIE }) }, redirect: "manual" }).catch(() => null);
  return { status: r?.status ?? 0, text: r ? await r.text() : "", location: r?.headers.get("location") || "" };
};
const daemonRead = async (route) => fetch(`${DAEMON}${route}`, { headers: { cookie: COOKIE } })
  .then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) })).catch(() => ({ status: 0, body: {} }));

/**
 * Submit the rendered form with only what a person would fill in. A form that is not on the page, a
 * field it does not render, or a choice it does not offer is a FAILED STEP, never a hand-built post.
 */
async function submit(route, action, fields, { anonymous = false, postAnonymously = false } = {}) {
  const from = await page(route, { anonymous });
  const form = renderedForm(from.text, action);
  if (!form) return { error: `no form posting to ${action} is rendered at ${route} (HTTP ${from.status})` };
  const missing = Object.keys(fields).filter((n) => !form.names.has(n));
  if (missing.length) return { error: `the form at ${route} renders no field ${missing.join(", ")}` };
  const unoffered = Object.entries(fields).filter(([n, v]) => form.options[n] && !form.options[n].has(String(v)));
  if (unoffered.length) return { error: `the form at ${route} offers no option ${unoffered.map(([n, v]) => `${n}=${v}`).join(", ")}` };
  const body = new URLSearchParams();
  for (const [n, v] of form.values) if (!(n in fields)) body.append(n, v);
  for (const [n, v] of Object.entries(fields)) body.append(n, v);
  const r = await fetch(`${SERVE}${action}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "text/html", ...(anonymous || postAnonymously ? {} : { cookie: COOKIE }) },
    body: body.toString(), redirect: "manual",
  }).catch(() => null);
  const location = r?.headers.get("location") || "";
  return { status: r?.status ?? 0, location, q: new URLSearchParams(location.split("?")[1]?.split("#")[0] || ""), text: r ? await r.text() : "" };
}
const said = (res) => res.error || res.q?.get("refused") || (res.text || "").match(/(Create|Save|Delete) (failed|refused):[^<]*/u)?.[0] || `${res.status} ${res.location}`.slice(0, 160);

async function run() {
  const daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  let log = "";
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: { ...process.env, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);
  const token = log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = token ? await fetch(`${DAEMON}/v1/hypervisor/auth/bootstrap`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ token, password: "domainapp-chain-forms-bootstrap-v1", email: "domainapp-chain@ioi.local" }),
  }).then((r) => r.json()).catch(() => ({})) : {};
  COOKIE = boot.session_token ? `ioi_session=${boot.session_token}` : "";
  ok("operator bootstrap yields an authenticated session", COOKIE.startsWith("ioi_session=ioi_sess_"), COOKIE.slice(0, 24));

  const servePort = await freePort();
  SERVE = `http://127.0.0.1:${servePort}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: APP,
    env: { ...process.env, PORT: String(servePort), PRODUCT_UI_PORT: String(await freePort()), IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"), IOI_HYPERVISOR_DAEMON_URL: DAEMON, IOI_PRODUCT_SIGNIN_REQUIRED: "0" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitFor(`${SERVE}/ontology/schema`, 30000);
  const who = await daemonRead("/v1/hypervisor/auth/whoami");
  const tenants = who.body?.principal?.tenant_refs ?? [];
  const owner = tenants.find((t) => t === "org://local") || tenants.find((t) => String(t).startsWith("org://")) || "";
  const tag = `dc${Date.now().toString(36).slice(-5)}`;

  // ---- 1. an ontology draft with a type, then PUBLISHED from History ----------------------------
  const created = await submit("/__ioi/ontology/manager?section=create", "/__ioi/ontology/manager/actions/create-ontology", { domain: `${tag}-lending` });
  const ontId = created.q?.get("record") || "";
  const typed = ontId ? await submit(`/__ioi/ontology/manager?ontology=${ontId}&section=create&newKind=object-type`, "/__ioi/ontology/manager/actions/upsert-object-type", { def_id: "loan", name: "Loan" }) : { error: "no ontology" };
  const published = ontId ? await submit(`/__ioi/ontology/manager?ontology=${ontId}&section=history`, `/__ioi/ontology/manager/actions/publish-revision?ontology=${ontId}`, {}) : { error: "no ontology" };
  const revisionRef = published.q?.get("record") || "";
  const families = (await daemonRead("/v1/hypervisor/ontology-versions")).body?.ontology_families ?? [];
  ok("an ontology draft with a type is PUBLISHED from Ontology Manager's History as an admitted M05.1 revision the caller's family inventory holds",
    !!ontId && typed.q?.get("acted") === "upsert-object-type" && published.q?.get("acted") === "publish-revision" && /^ontology:\/\/[a-z0-9-]+\/[a-z0-9-]+\/revision\/1$/u.test(revisionRef)
      && families.some((f) => revisionRef.startsWith(`${f}/revision/`)),
    `${said(created)} · ${said(typed)} · ${said(published)} · ${revisionRef || "no revision"}`);

  // ---- 2. Studio's descriptor form binds that revision -------------------------------------------
  const studioRoute = "/__ioi/studio/workbench?view=descriptors";
  const studioPage = await page(studioRoute);
  const offered = renderedForm(studioPage.text, "/__ioi/studio/workbench/actions/create-descriptor")?.options?.ontology_refs ?? new Set();
  const described = await submit(studioRoute, "/__ioi/studio/workbench/actions/create-descriptor", {
    display_name: `${tag} lending surface`, surface_ref: `surface://${tag}/lending`, composition_pattern: "domain_app", ontology_refs: revisionRef,
    canonical_object_model_refs: `object-model://${tag}/lending/loan`, policy_bound_data_view_refs: `view://${tag}/lending/reviewer`, authority_requirement_refs: "scope:lending.review",
    daemon_api_refs: "api://v1/hypervisor/odk", receipt_obligations: `receipt://${tag}/lending/decision`, conformance_profile_refs: `profile://${tag}/lending/v1`,
  });
  const sdId = described.q?.get("record") || "";
  const sdRec = sdId ? (await daemonRead(`/v1/hypervisor/odk/surface-descriptors/${sdId}`)).body?.surface_descriptor : null;
  const sdRef = sdRec?.surface_descriptor_id || "";
  ok("Studio's descriptor form OFFERS the published revision and admits a domain_app descriptor bound to exactly that revision, by the daemon's own resolver",
    offered.has(revisionRef) && described.q?.get("acted") === "create-descriptor" && JSON.stringify(sdRec?.ontology_refs) === JSON.stringify([revisionRef])
      && sdRec?.bound_ontology_revision_count === 1 && sdRec?.composition_pattern === "domain_app",
    `offered ${offered.has(revisionRef)} · ${said(described)} · ${sdRef || "no descriptor"}`);

  // ---- 3. ODK's manifest form over the ontology and the descriptor ------------------------------
  const ontRef = (await daemonRead(`/v1/hypervisor/odk/domain-ontologies/${ontId}`)).body?.ontology?.ref || "";
  const manifested = await submit("/__ioi/odk/manifests/new", "/__ioi/odk/manifests", { name: `${tag} manifest`, ontology_refs: ontRef, surface_descriptor_refs: sdRef });
  const manifestId = (manifested.location || "").match(/^\/__ioi\/odk\/manifests\/(odk_[0-9a-f]+)/u)?.[1] || "";
  const manRow = manifestId ? (await daemonRead(`/v1/hypervisor/odk/manifests/${manifestId}`)).body : {};
  const manRec = manRow?.manifest?.manifest || manRow?.manifest || {};
  ok("ODK's manifest form offers the ontology and the descriptor and admits a manifest naming both",
    manifested.status === 302 && !!manifestId && (manRec.ontology_refs || []).includes(ontRef) && (manRec.surface_descriptor_refs || []).includes(sdRef),
    `${said(manifested)} · ${manifestId || "no manifest"}`);
  const manRef = manifestId ? `odk://${manifestId}` : "";

  // ---- 4. the New Domain App form: owner from the sign-in, never typed ---------------------------
  const newAppPage = await page("/__ioi/domain-apps/new");
  const appForm = renderedForm(newAppPage.text, "/__ioi/domain-apps");
  ok("the New Domain App form asks for no owner — it states the caller's organization, read from the sign-in (a typed owner was refused for every guess but the exact ref)",
    !!appForm && !appForm.names.has("owner_ref") && !!owner && newAppPage.text.includes(`Owned by <code>${owner}</code>`),
    appForm ? `fields ${[...appForm.names].join(",")}` : "no form");
  const apped = await submit("/__ioi/domain-apps/new", "/__ioi/domain-apps", { name: `${tag} Lending`, surface_descriptor_ref: sdRef, odk_manifest_ref: manRef, operator_contract_refs: `contract://${tag}/lending-ops` });
  const appId = (apped.location || "").match(/^\/__ioi\/domain-apps\/(dapp_[0-9a-f]+)$/u)?.[1] || "";
  const appPage = appId ? await page(apped.location) : { status: 0, text: "" };
  const appRec = appId ? (await daemonRead(`/v1/hypervisor/domain-apps/${appId}`)).body?.domain_app : null;
  ok("submitting it creates a draft DomainApp owned by the caller's organization, and the redirect lands on the app's own page — not 'not found'",
    apped.status === 302 && !!appId && appPage.status === 200 && !appPage.text.includes("Domain App not found") && appRec?.owner_ref === owner
      && appRec?.surface_descriptor_ref === sdRef && appRec?.odk_manifest_ref === manRef,
    `${said(apped)} · page ${appPage.status} · owner ${appRec?.owner_ref || "—"}`);

  // ---- 5. Packages: the app is OFFERED by its v2 identity, frozen, released ----------------------
  const registryRoute = "/__ioi/packages/registry";
  const appOptions = renderedForm((await page(registryRoute)).text, "/__ioi/packages/registry/actions/admit-candidate")?.options?.domain_app_ref ?? new Set();
  const packageId = `pkg-${tag}`;
  const candidate = await submit(registryRoute, "/__ioi/packages/registry/actions/admit-candidate", { package_id: packageId, domain_app_ref: `domain-app://${appId}` });
  const released = candidate.q?.get("acted") === "admit-candidate"
    ? await submit(`${registryRoute}?pkg=${packageId}`, `${registryRoute}/${packageId}/cut-release`, { object_contract_refs: `object-model://${tag}/lending/loan` })
    : { error: "no candidate" };
  const packagesPage = await page("/packages");
  ok("Packages offers the draft app under its own identity (never an empty value), freezes it as a candidate, cuts an immutable release, and /packages lists it by name",
    appOptions.has(`domain-app://${appId}`) && !appOptions.has("") && candidate.q?.get("acted") === "admit-candidate" && released.q?.get("acted") === "cut-release"
      && /^sha256:[0-9a-f]{64}$/u.test(released.q?.get("record") || "") && packagesPage.status === 200 && packagesPage.text.includes(packageId),
    `offered ${[...appOptions].join("|") || "nothing"} · ${said(candidate)} · ${said(released)}`);

  // ---- 6. edit and delete through their own forms ------------------------------------------------
  const edited = appId ? await submit(`/__ioi/domain-apps/${appId}/edit`, `/__ioi/domain-apps/${appId}/patch`, { description: "edited through the form" }) : { error: "no app" };
  const afterEdit = appId ? (await daemonRead(`/v1/hypervisor/domain-apps/${appId}`)).body?.domain_app : null;
  ok("the Edit draft form SAVES — the patch names the record's own owner, which the daemon had refused on every patch — and the author's operator contract survives the save",
    edited.status === 302 && afterEdit?.description === "edited through the form" && (afterEdit?.operator_contract_refs || []).includes(`contract://${tag}/lending-ops`) && afterEdit?.owner_ref === owner,
    `${said(edited)} · description '${afterEdit?.description ?? ""}' · ops ${JSON.stringify(afterEdit?.operator_contract_refs ?? [])}`);
  const second = await submit("/__ioi/domain-apps/new", "/__ioi/domain-apps", { name: `${tag} Throwaway`, surface_descriptor_ref: sdRef, odk_manifest_ref: manRef });
  const secondId = (second.location || "").match(/dapp_[0-9a-f]+/u)?.[0] || "";
  const deleted = secondId ? await submit(`/__ioi/domain-apps/${secondId}`, `/__ioi/domain-apps/${secondId}/delete`, {}) : { error: "no second app" };
  const gone = secondId ? (await daemonRead(`/v1/hypervisor/domain-apps/${secondId}`)).status : 0;
  ok("the Delete form deletes (the daemon no longer serves the app) and only then lands on the list",
    deleted.status === 302 && deleted.location === "/__ioi/domain-apps" && gone === 404, `${said(deleted)} · daemon GET after ${gone}`);

  // ---- 7. a kill switch on the app: created, tripped and ENFORCED through Governance's forms -------
  // Enforcement admits as an owner-scoped write; the lane posted "{}", so every Enforce was refused
  // and the flat refusal redirected back as though the runtimes had been stopped.
  const ksRoute = "/__ioi/governance?tab=kill-switches";
  const ksCreated = appId ? await submit(ksRoute, "/__ioi/governance/kill-switches", { subject_ref: `domain-app://${appId}` }) : { error: "no app" };
  const ks = ((await daemonRead("/v1/hypervisor/governance/kill-switches")).body?.kill_switches ?? []).find((k) => k.subject_ref === `domain-app://${appId}`);
  const tripped = ks ? await submit(ksRoute, `/__ioi/governance/kill-switches/${encodeURIComponent(ks.id)}/transition`, { transition: "trip", trip_reason: "chain forms verifier" }) : { error: "no kill switch" };
  const enforced = ks ? await submit(ksRoute, `/__ioi/governance/kill-switches/${encodeURIComponent(ks.id)}/enforce`, {}) : { error: "no kill switch" };
  const ksAfter = ks ? (await daemonRead(`/v1/hypervisor/governance/kill-switches/${ks.id}`)).body?.kill_switch : null;
  ok("a kill switch on the app is created, tripped and ENFORCED through Governance's own forms — the enforcement is recorded, never a redirect over a refusal",
    !!ks && tripped.status === 302 && enforced.status === 302 && ksAfter?.state === "tripped" && typeof ksAfter?.enforcement_state === "string" && ksAfter.enforcement_state.length > 0,
    `${said(ksCreated)} · ${said(tripped)} · ${said(enforced)} · state ${ksAfter?.state ?? "—"} · enforcement ${ksAfter?.enforcement_state ?? "none"}`);

  // ---- 8. an anonymous create is refused by name and creates nothing -----------------------------
  // The form a signed-in page rendered, posted with no session — a tab left open after sign-out. (A
  // signed-out page renders no descriptor to pick, which proves nothing about the server.)
  const before = ((await daemonRead("/v1/hypervisor/domain-apps")).body?.domain_apps ?? []).length;
  const anon = await submit("/__ioi/domain-apps/new", "/__ioi/domain-apps", { name: `${tag} Anonymous`, surface_descriptor_ref: sdRef }, { postAnonymously: true });
  const after = ((await daemonRead("/v1/hypervisor/domain-apps")).body?.domain_apps ?? []).length;
  ok("a Domain App create posted with no session is refused, said on the page, and creates nothing",
    !anon.error && anon.status === 200 && /Create failed:/u.test(anon.text) && after === before,
    `${said(anon)} · ${before} → ${after}`);
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "domainapp-chain-forms", sourceUrl: import.meta.url, results });
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
