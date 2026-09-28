#!/usr/bin/env node
// THE ADOPTED ONTOLOGY MANAGER READS THE CALLER'S ONTOLOGY, AND NOTHING RECORDED (R-241, Ontology Manager O1–O3, Object Explorer O4).
//
// The reference Ontology Manager (booted by the local mirror, routed at /workspace/ontology) answers from the caller's
// ODK domain ontologies (adopted-ontology.mjs), in a real browser against an ISOLATED daemon + serve:
//   - it opens the caller's ontology, not the platform's all-zeros default, with its real counts;
//   - its sections (object, link, action and value types), Discover, History and configuration read daemon truth —
//     History names who made each revision and the types it created (ODK records them);
//   - an object type's page and its Properties, Security and History tabs, and a link type's page, read daemon truth,
//     and say edits are not offered; what an ODK model does not hold shows the reference's own empty states;
//   - Health issues searches the loaded ontology; Cleanup names its unbound usage read; Functions lists the released
//     functions of the Hypervisor's registry;
//   - Object Explorer (/workspace/hubble, the same surface) lists the caller's types, and its Recents lists the type
//     just opened in the Ontology Manager;
//   - no read reaches the mirror but the reference's chrome, an unbound read is a named gap (never the serve's HTML
//     page), and a GraphQL batch on the surface is answered by the adopted layer (it had returned a recorded tenant
//     module);
//   - with the daemon stopped, each page shows its error rather than an empty ontology.
//
// Exit: 0 pass · 1 fail · 2 blocked (no daemon binary, or the local mirror cannot boot the reference app).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
//   node apps/hypervisor/scripts/verify-hypervisor-adopted-ontology.mjs

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
const BIN = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
const MIRROR = process.env.IOI_HARVEST_CAPTURE_URL || "http://127.0.0.1:9225";
// the reference's chrome reads the mirror still answers (the same set the adopted Automate verifier allows)
const CHROME = new Set(["GET /multipass/api/sessions/definitions/current", "GET /multipass/api/sessions/selection", "POST /documentation/api/v2/release-notes/pagination",
  "GET /aip-assist/api/chat/checkAvailability", "GET /workspace/api/lifecycleStatusByApplication", "POST /log-receiver/api/beacon", "GET /compass/api/registry/actions"]);

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((r) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => r(p)); }); });
const waitFor = async (url, ms = 60000) => { const end = Date.now() + ms; while (Date.now() < end) { try { const r = await fetch(url); if (r.status < 500) return true; } catch { /* not yet */ } await sleep(300); } return false; };

let daemon = null, serve = null;
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-adopted-ontology-"));

async function run() {
  if (!fs.existsSync(BIN)) { console.log(`BLOCKED: no daemon binary at ${BIN}`); process.exit(2); }
  if (!(await fetch(`${MIRROR}/workspace/ontology/`, { signal: AbortSignal.timeout(3000) }).then((r) => r.ok).catch(() => false))) { console.log(`BLOCKED: the local mirror (${MIRROR}) does not boot /workspace/ontology/`); process.exit(2); }
  const daemonPort = await freePort();
  const DAEMON = `http://127.0.0.1:${daemonPort}`;
  let log = "";
  daemon = spawn(BIN, [], { cwd: ROOT, env: { ...process.env, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1" }, stdio: ["ignore", "pipe", "pipe"] });
  daemon.stdout.on("data", (c) => (log += c)); daemon.stderr.on("data", (c) => (log += c));
  await waitFor(`${DAEMON}/healthz`);
  const token = log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1);
  const boot = await (await fetch(`${DAEMON}/v1/hypervisor/auth/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, password: "adopted-ontology-bootstrap-v1", email: "ontology@ioi.local" }) })).json();
  const COOKIE = `ioi_session=${boot.session_token}`;
  const d = (method, route, body) => fetch(`${DAEMON}${route}`, { method, headers: { cookie: COOKIE, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }).then(async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) }));
  const servePort = await freePort();
  const SERVE = `http://127.0.0.1:${servePort}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: APP,
    env: { ...process.env, PORT: String(servePort), PRODUCT_UI_PORT: String(await freePort()), IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"), IOI_HYPERVISOR_DAEMON_URL: DAEMON, IOI_PRODUCT_SIGNIN_REQUIRED: "0", IOI_ADOPTED_SURFACES: "1", IOI_HARVEST_CAPTURE_URL: MIRROR },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitFor(`${SERVE}/__ioi/login`);

  // ---- the fixture: an ODK draft with a link, then a revision that adds a type (ODK records the change and its actor) --
  const made = (await d("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "Loans", description: "Loan book", canonical_object_model: {
    value_types: [{ id: "money", name: "Money", base: "double" }],
    object_types: [
      { id: "loan", name: "Loan", title_property: "title", properties: [{ id: "loan_id", name: "Loan Id", value_type: "string", required: true }, { id: "title", name: "Title", value_type: "string" }, { id: "amount", name: "Amount", value_type: "money" }] },
      { id: "borrower", name: "Borrower", title_property: "name", properties: [{ id: "name", name: "Name", value_type: "string" }] }],
    link_types: [{ id: "held_by", name: "Held by", from: "loan", to: "borrower", cardinality: "one_to_many" }],
    action_types: [{ id: "approve", name: "Approve", kind: "modify_object", applies_to: "loan" }] } })).j.ontology;
  const revised = await d("PATCH", `/v1/hypervisor/odk/domain-ontologies/${made?.id}`, { expected_revision: 1, canonical_object_model: { ...made.canonical_object_model, object_types: [...made.canonical_object_model.object_types, { id: "branch", name: "Branch", title_property: "city", properties: [{ id: "city", name: "City", value_type: "string" }] }] } });
  const odkHistory = (await d("GET", `/v1/hypervisor/odk/domain-ontologies/${made?.id}/history`)).j.history || [];
  // and a function, declared in the Hypervisor's function registry (the Functions section lists the registry)
  const owner = ((await d("GET", "/v1/hypervisor/auth/whoami")).j.principal?.tenant_refs || []).find((t) => String(t).startsWith("org://"));
  const fn = await d("POST", "/v1/hypervisor/functions", { owner_ref: owner, idempotency_key: `adopted-ontology-fn-${process.pid}`, display_name: "Loan score", api_name: "loanScore", version: "1.0.0", documentation: "",
    inputs: [{ name: "amount", description: "", data_type: { type: "integer" }, required: true }], output: { data_type: { type: "integer" }, description: "" },
    implementation: { runtime: "python3", source: "import json, sys\nprint(json.dumps(json.load(sys.stdin)['amount'] // 100))\n" }, timeout_ms: 30000 });
  // released (the section lists released functions: a draft revision is not yet offered to anything)
  const fnId = String(fn.j.revision?.function_ref || "").replace(/^function:\/\//u, "");
  const released = fnId ? await d("POST", `/v1/hypervisor/functions/${fnId}/revisions/1/release`, { owner_ref: owner, idempotency_key: `adopted-ontology-release-${process.pid}` }) : { status: 0, j: {} };
  ok("PRECONDITION: an ODK draft exists and its revision records which type it created (ODK keeps each revision's changes), and a function is declared and released",
    revised.status === 200 && odkHistory.at(-1)?.affected?.object_types?.branch === "CREATED" && fn.status < 300 && released.status < 300,
    `${JSON.stringify(odkHistory.at(-1)?.affected || null)} · function ${fn.status} ${fnId} · release ${released.status} ${released.j.error?.code || ""}`);

  const { chromium } = await import(path.join(ROOT, "node_modules", "playwright", "index.mjs"));
  const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
    await ctx.addCookies([{ name: "ioi_session", value: boot.session_token, url: SERVE }]);
    const pg = await ctx.newPage();
    // What the pages read that the adopted layer does not answer: a mirror passthrough (only the reference's chrome may
    // pass), a 501 that is not the named gap, a service read answered with this serve's HTML page, a GraphQL error.
    const passthrough = new Set(), fenced = new Set(), unnamed = new Set(), htmlAnswers = new Set(), gqlErrors = new Set(), pageErrors = [];
    pg.on("pageerror", (e) => pageErrors.push(String(e.message).slice(0, 160)));
    pg.on("response", async (r) => {
      const u = new URL(r.url()); const key = `${r.request().method()} ${u.pathname.replace(/ri\.[\w.-]+/gu, "<rid>")}`;
      if (r.headers()["x-ioi-mirror-passthrough"] === "1") passthrough.add(key);
      if (/^\/[a-z][a-z0-9-]*\/api\//u.test(u.pathname) && /text\/html/u.test(r.headers()["content-type"] || "")) htmlAnswers.add(key);
      if (r.status() === 501) { fenced.add(key); const j = await r.json().catch(() => ({})); if (j.errorName !== "Hypervisor:OntologyReadNotBound") unnamed.add(key); }
      if (/graphql/u.test(u.pathname)) { const t = await r.text().catch(() => ""); for (const m of t.matchAll(/"message":"([^"]{0,90})/gu)) gqlErrors.add(m[1]); }
    });
    const text = async () => (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    const visit = async (p, until) => { await pg.goto(`${SERVE}${p}`, { waitUntil: "domcontentloaded", timeout: 60000 }); let t = ""; for (let i = 0; i < 25; i++) { await pg.waitForTimeout(800); t = await text(); if (!until || until.test(t)) break; } return t; };
    const after = (t, marker, n = 200) => (t.includes(marker) ? t.slice(t.indexOf(marker), t.indexOf(marker) + n) : `(no "${marker}")`);

    // a browser that had another ontology selected (the platform's all-zeros default, the app's own fallback) is
    // moved to the caller's: the stored pick is what the app loads, and a stale one had opened an empty ontology
    await pg.goto(`${SERVE}/__ioi/login`, { waitUntil: "domcontentloaded" });
    const seeded = await pg.evaluate(() => { localStorage.setItem("@foundry/ontology/vv/13/currentOntologyRid", JSON.stringify({ version: 13, value: "ri.ontology.main.ontology.00000000-0000-0000-0000-000000000000" })); return JSON.parse(localStorage.getItem("@foundry/ontology/vv/13/currentOntologyRid")).value; });
    const landing = await visit("/workspace/ontology/", /Object types 3/u);
    const storedRid = await pg.evaluate(() => { try { return JSON.parse(localStorage.getItem("@foundry/ontology/vv/13/currentOntologyRid") || "null")?.value || null; } catch { return null; } });
    const ours = Object.keys((await fetch(`${SERVE}/ontology-metadata/api/ontology/v2/load/all`, { method: "POST", headers: { cookie: COOKIE, "content-type": "application/json" }, body: "{}" }).then((r) => r.json()).catch(() => ({}))).ontologies || {});
    ok("the adopted Ontology Manager opens the caller's ontology with its real counts, even over a stale pick of the platform's all-zeros default",
      /0{8}-0{4}-0{4}-0{4}-0{12}$/u.test(seeded) && ours.length === 1 && storedRid === ours[0] && ["Object types 3", "Link types 1", "Action types 1", "Value types 1"].every((c) => landing.includes(c)),
      `seeded ${seeded.slice(-12)} → stored ${storedRid === ours[0] ? "the caller's" : storedRid} · ${(landing.match(/(Object|Link|Action|Value) types \d+/gu) || []).join(" · ")}`);
    const discover = await visit("/workspace/ontology/home/discover", /recently modified/u);
    const recent = after(discover, "recently modified in Loans", 240);
    ok("Discover lists the object types the draft's revisions recorded, not \"Get started\" beside three types",
      discover.includes("recently modified in Loans") && ["Loan", "Borrower", "Branch"].every((n) => recent.includes(n)) && !/Get started with the ontology/u.test(discover), recent);

    const types = await visit("/workspace/ontology/home/object-type", /Borrower/u);
    ok("the Object types section lists the caller's types from their ODK model, EXPERIMENTAL (a draft)",
      ["Loan", "Borrower", "Branch"].every((n) => types.includes(n)) && /Experimental/u.test(types) && !/Something went wrong/u.test(types), after(types, "Object types 3 Modify", 160));
    const links = await visit("/workspace/ontology/home/link-type", /Held by|Could not find/u);
    const linkPage = await visit("/workspace/ontology/link-type/held_by/overview", /link type/u);
    ok("the Link types section lists the ODK link type, and its page opens over daemon truth: its endpoints, its cardinality and that edits are not offered",
      /Held by/u.test(after(links, "Link type 1", 120)) && !/Could not find any link types/u.test(links)
        && /Held by/u.test(linkPage) && /Borrower/u.test(linkPage) && /Many-to-one link type/u.test(linkPage) && /You do not have edit permissions to this link type/u.test(linkPage) && !/was not found/u.test(linkPage),
      `${after(links, "Link type 1", 80)} · ${(linkPage.match(/Many-to-one link type|link type was not found|ID held_by/gu) || []).join(" · ")}`);
    const actions = await visit("/workspace/ontology/home/action-type", /Approve/u);
    ok("the Action types section lists the ODK action type, with no rules (an ODK action type declares none)",
      /Approve/u.test(actions) && /No rules/u.test(actions), after(actions, "Action type 1", 120));
    const values = await visit("/workspace/ontology/home/value-types", /Money/u);
    ok("the Value types section lists the ODK value type with its base type",
      /Money Double/u.test(values), after(values, "Value types 1", 100));
    const functions = await visit("/workspace/ontology/home/function", /Loan score|Could not find any functions|An error occurred/u);
    ok("the Functions section lists the functions released in the Hypervisor's registry",
      /Loan score/u.test(after(functions, "Function 1 New function", 200)) && /Visible/u.test(after(functions, "Loan score", 80)) && !/Could not find any functions|An error occurred/u.test(functions),
      after(functions, "Function 1 New function", 140));
    const history = await visit("/workspace/ontology/home/history", /Created|No changes|do not have perm/u);
    ok("History lists the revision with its author (its ODK receipt) and the type it created — not \"edits you do not have permission to view\"",
      /You/u.test(history) && /patched: canonical_object_model/u.test(history) && /Branch/u.test(history) && /Created/u.test(history) && !/do not have perm/u.test(history),
      after(history, "Ontology history"));
    const config = await visit("/workspace/ontology/home/advanced", /API name/u);
    ok("Ontology configuration shows the ontology's name, description and API name (its family's name, valid), and its settings cannot be changed here",
      /Display name Loans/u.test(config) && /Description Loan book/u.test(config) && /API name ont-[0-9a-f]+/u.test(config) && !/invalid/u.test(after(config, "API name", 60))
        && await pg.getByRole("button", { name: "Save" }).first().isDisabled().catch(() => false),
      after(config, "API name", 60));

    const overview = await visit("/workspace/ontology/object-type/loan/overview", /Last edited (?!X days).*You do not have edit permissions/u);
    ok("an object type opens over daemon truth: its properties, its last edit and its author, and that edits are not offered (none is bound)",
      /Loan/u.test(overview) && /Properties 3/u.test(overview) && /Last edited .* by/u.test(overview) && /You do not have edit permissions/u.test(overview) && !/Failed to load object type/u.test(overview),
      `${(overview.match(/Properties \d+|Last edited [^·]{0,40}by \w+|You do not have edit permissions/gu) || []).join(" · ")}`);
    const props = await visit("/workspace/ontology/object-type/loan/properties-tab", /Loan Id/u);
    const security = await visit("/workspace/ontology/object-type/loan/security", /Object type roles Read-only/u);
    const typeHistory = await visit("/workspace/ontology/object-type/loan/history", /draft created/u);
    ok("an object type's Properties, Security and History tabs answer over daemon truth: its properties, no role grants (read-only), and the revision that created it",
      ["Title", "Amount", "Loan Id"].every((n) => after(props, "Properties 3 Property name", 200).includes(n))
        && /Object type roles Read-only/u.test(security) && /DomainOntology draft created/u.test(typeHistory),
      `${after(props, "Properties 3 Property name", 90)} · ${after(security, "Object type roles", 30)} · ${after(typeHistory, "You •", 60)}`);

    // Object Explorer reads the same ontology: its catalog lists the caller's types, and its Recents lists the type just
    // opened in the Ontology Manager (one Recently viewed per person, across both apps)
    const explorer = await visit("/workspace/hubble/", /3 of 3|Failed to load|No object types/u);
    const catalog = after(explorer, "Object type catalog", 400);
    const recentsShortcut = after(explorer, "Shortcuts", 160);
    ok("Object Explorer's catalog lists the caller's types from their ODK model, and its Recents lists the type opened in the Ontology Manager",
      /3 of 3/u.test(catalog) && ["Loan", "Borrower", "Branch"].every((n) => catalog.includes(n)) && /Loan/u.test(recentsShortcut) && !/No recents|Failed to load recents|Failed to load type groups/u.test(explorer),
      `${recentsShortcut.slice(0, 90)} · ${catalog.slice(0, 160)}`);
    // what an ODK model does not hold is shown as none, in the reference's own empty states
    const empties = [
      ["/workspace/ontology/home/interfaces", "Could not find any Interfaces"], ["/workspace/ontology/home/shared-properties", "Could not find any shared properties"],
      ["/workspace/ontology/home/type-groups", "Could not find any Groups"], ["/workspace/ontology/object-type/loan/datasources", "No datasource selected"],
      ["/workspace/ontology/object-type/loan/capabilities", "Set up time series properties"], ["/workspace/ontology/object-type/loan/interfaces", "No interfaces implemented"],
      ["/workspace/ontology/object-type/loan/materializations", "No object datasets created"], ["/workspace/ontology/object-type/loan/automations", "No automations defined for this object type"],
    ];
    const missing = [];
    for (const [p, want] of empties) { const t = await visit(p, new RegExp(want, "u")); if (!t.includes(want)) missing.push(`${p.split("/").pop()}: ${t.slice(-120)}`); }
    ok("the sections and tabs for what an ODK model does not hold (interfaces, shared properties, groups, datasources, capabilities, materializations, automations) show none, in the reference's own empty states",
      missing.length === 0, missing.join(" | ") || `${empties.length} empty states`);

    ok("no page reached the mirror beyond the reference's chrome, every read the adopted layer does not bind is a named gap (never the serve's HTML page), and no GraphQL operation on these pages is unbound",
      [...passthrough].every((p) => CHROME.has(p)) && unnamed.size === 0 && htmlAnswers.size === 0 && gqlErrors.size === 0 && pageErrors.length === 0,
      `passthrough ${[...passthrough].filter((p) => !CHROME.has(p)).join(",") || "chrome only"} · named gaps ${fenced.size} · unnamed ${[...unnamed].join(",") || "none"} · html ${[...htmlAnswers].join(",") || "none"} · gql ${[...gqlErrors].slice(0, 2).join(" | ") || "none"} · page ${pageErrors.slice(0, 1).join("") || "none"}`);

    // Health issues searches the whole loaded ontology; Cleanup's checks read usage metrics, which are not kept
    await visit("/workspace/ontology/home/health-issues", /Click here to run a search/u);
    await pg.getByText("Click here to run a search").click({ timeout: 8000 }).catch(() => {});
    let health = ""; for (let i = 0; i < 15 && !/No health issues found|Registration and index failures [1-9]|Loading full ontology failed/u.test(health); i++) { await pg.waitForTimeout(800); health = await text(); }
    await visit("/workspace/ontology/home/cleanup", /Start cleanup/u);
    await pg.getByText("Start cleanup").click({ timeout: 8000 }).catch(() => {});
    let cleanupText = ""; for (let i = 0; i < 15 && !/cleanup results|Object types \d+ Snooze/u.test(cleanupText); i++) { await pg.waitForTimeout(800); cleanupText = await text(); }
    ok("Health issues searches the loaded ontology and finds no registration or index failure (an ODK type is indexed nowhere); Cleanup names its unbound usage read",
      /Registration and index failures 0 No health issues found/u.test(health) && !/Loading full ontology failed/u.test(health)
        && /Failed to load cleanup results Hypervisor:OntologyReadNotBound/u.test(cleanupText) && !/Datasource not updated/u.test(cleanupText),
      `${after(health, "Registration and index failures", 60)} · ${after(cleanupText, "Failed to load cleanup", 70)}`);

    // ---- the fence: an unbound read is a named gap, a service no lane answers is a named gap (never the serve's HTML
    // page), and a GraphQL batch on the surface is answered by the adopted layer
    const H = { cookie: COOKIE, "content-type": "application/json", referer: `${SERVE}/workspace/ontology/home/discover` };
    const unbound = await fetch(`${SERVE}/ontology-metadata/api/usage/getSettings/user`, { method: "POST", headers: H, body: "{}" }).then(async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) }));
    const service = await fetch(`${SERVE}/objects-data-funnel/api/status/object-type`, { method: "POST", headers: H, body: "{}" }).then(async (r) => ({ status: r.status, ct: r.headers.get("content-type") || "", j: await r.json().catch(() => ({})) }));
    const batch = await fetch(`${SERVE}/graphql-gateway/api/graphql/batch`, { method: "POST", headers: H, body: JSON.stringify([{ operationName: "GetResourceQuery", query: "query GetResourceQuery($rid: RID!) { resourceMetadata(rid: $rid) { rid __typename } __typename }", variables: { rid: "ri.workshop.main.module.00000000-0000-0000-0000-000000000000" } }]) }).then(async (r) => ({ status: r.status, headers: r.headers, text: await r.text() }));
    // a function-registry read from another adopted surface answers the Hypervisor's functions too (passed through, it had
    // answered the recorded tenant's)
    const elsewhere = await fetch(`${SERVE}/graphql-gateway/api/graphql?q=SearchAllFunctionsQuery`, { method: "POST", headers: { ...H, referer: `${SERVE}/workspace/object-monitoring/` }, body: JSON.stringify({ operationName: "SearchAllFunctionsQuery", query: "query SearchAllFunctionsQuery($filter: FunctionFilter) { functionsV2(filter: $filter) { totalNumberOfResults __typename } __typename }", variables: { filter: { clauses: [], type: "OR" } } }) }).then(async (r) => ({ status: r.status, pass: r.headers.get("x-ioi-mirror-passthrough"), j: await r.json().catch(() => ({})) }));
    ok("on the ontology surface an unbound read is a named gap and a GraphQL batch is answered by the adopted layer — never the recorded tenant's answer",
      unbound.status === 501 && unbound.j.errorName === "Hypervisor:OntologyReadNotBound" && service.status === 501 && /json/u.test(service.ct) && service.j.errorName === "Hypervisor:OntologyReadNotBound"
        && batch.status === 200 && !batch.headers.get("x-ioi-mirror-passthrough") && /not bound in the Hypervisor adapter yet/u.test(batch.text)
        && !elsewhere.pass && elsewhere.j.data?.functionsV2?.totalNumberOfResults === 1,
      `unbound ${unbound.status} ${unbound.j.errorName} · service ${service.status} ${service.ct.split(";")[0]} · batch ${batch.status} ${batch.text.slice(0, 60)} · functions from Automate ${elsewhere.j.data?.functionsV2?.totalNumberOfResults}`);

    // ---- degraded: the daemon stopped — each page shows its own error, never an empty ontology -----------------------
    daemon.kill("SIGTERM");
    for (let i = 0; i < 30 && daemon.exitCode === null && daemon.signalCode === null; i++) await sleep(200);
    const downDiscover = await visit("/workspace/ontology/home/discover", /Failed to load discover page|recently modified/u);
    const downTypes = await visit("/workspace/ontology/home/object-type", /Something went wrong|Could not find|Borrower/u);
    const downType = await visit("/workspace/ontology/object-type/loan/overview", /Failed to load object type|Last edited (?!X days)/u);
    ok("with the daemon stopped, Discover, the Object types section and an object type's page each show their error — never an empty ontology",
      /Failed to load discover page/u.test(downDiscover) && /Something went wrong while loading results from the ontology/u.test(downTypes) && /Failed to load object type/u.test(downType)
        && !/Could not find any object types/u.test(downTypes),
      `${after(downDiscover, "Failed to load discover", 40)} · ${after(downTypes, "Something went wrong", 40)} · ${after(downType, "Failed to load object", 30)}`);
  } finally {
    await browser.close();
  }
}

function cleanup() {
  try { serve?.kill("SIGTERM"); } catch { /* gone */ }
  try { daemon?.kill("SIGTERM"); } catch { /* gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* keep */ }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "adopted-ontology", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}).catch((e) => { console.error(e); cleanup(); process.exit(1); });
