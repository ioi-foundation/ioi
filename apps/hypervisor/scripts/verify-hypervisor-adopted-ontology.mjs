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
//   - Proposals (cut O6) lists the caller's ODK ontology proposals by state; a proposal's page reads its record; Approve is
//     the daemon's /apply (a stale one its ontology_proposal_stale refusal), Close its /withdraw; Create branch, rejecting,
//     reviewers and editing the request are refused by name;
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
  // a second person in the same organization (cut O7): they see the ontology, and may not change it — only its owner (the
  // bootstrap operator who created it) or an administrator of its organization may
  const memberEmail = "ontology-member@ioi.local";
  const member = await d("POST", "/v1/hypervisor/principals", { email: memberEmail, name: "Ontology Member", role: "member", password: "adopted-ontology-member-v1" });
  await d("POST", `/v1/hypervisor/principals/${member.j?.principal?.principal_id}/tenant-memberships`, { tenant_ref: owner, expected_revision: 0, idempotency_key: `adopted-ontology-member-${process.pid}`, reason: "verifier fixture: an ordinary member of the ontology's organization" });
  const memberLogin = await fetch(`${DAEMON}/v1/hypervisor/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: memberEmail, password: "adopted-ontology-member-v1" }) }).then((r) => r.json()).catch(() => ({}));
  const MEMBER_COOKIE = `ioi_session=${memberLogin.session_token}`;
  const dm = (method, route, body) => fetch(`${DAEMON}${route}`, { method, headers: { cookie: MEMBER_COOKIE, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }).then(async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) }));
  const mayChange = async (read) => { const one = (await read("GET", `/v1/hypervisor/odk/domain-ontologies/${made?.id}`)).j.ontology?.caller_may_change; const listed = ((await read("GET", "/v1/hypervisor/odk/domain-ontologies")).j.ontologies || []).find((o) => o.id === made?.id)?.caller_may_change; return one === listed ? one : `list ${listed} ≠ get ${one}`; };
  const [ownerMay, memberMay] = [await mayChange(d), await mayChange(dm)];
  const memberPatch = await dm("PATCH", `/v1/hypervisor/odk/domain-ontologies/${made?.id}`, { expected_revision: 2, description: "the member's edit" });
  ok("PRECONDITION: a member of the ontology's organization sees it but the daemon reads them as one who may not change it (caller_may_change false, its owner true) and refuses their patch by name",
    ownerMay === true && memberMay === false && memberPatch.status === 403 && memberPatch.j.error?.code === "odk_ontology_not_owner",
    `owner ${ownerMay} · member ${memberMay} · member's patch ${memberPatch.status} ${memberPatch.j.error?.code || ""}`);

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
    const linkPage = await visit("/workspace/ontology/link-type/held_by/overview", /Many-to-one link type|was not found/u);
    ok("the Link types section lists the ODK link type, and its page opens over daemon truth: its endpoints and its cardinality",
      /Held by/u.test(after(links, "Link type 1", 120)) && !/Could not find any link types/u.test(links)
        && /Held by/u.test(linkPage) && /Borrower/u.test(linkPage) && /Many-to-one link type/u.test(linkPage) && !/was not found/u.test(linkPage),
      `${after(links, "Link type 1", 80)} · ${(linkPage.match(/Many-to-one link type|link type was not found|ID held_by/gu) || []).join(" · ")}`);
    const actions = await visit("/workspace/ontology/home/action-type", /Approve/u);
    ok("the Action types section lists the ODK action type, with no rules (an ODK action type declares none)",
      /Approve/u.test(actions) && /No rules/u.test(actions), after(actions, "Action type 1", 120));
    const values = await visit("/workspace/ontology/home/value-types", /Money/u);
    ok("the Value types section lists the ODK value type with its base type",
      /Money Double/u.test(values), after(values, "Value types 1", 100));
    const functions = await visit("/workspace/ontology/home/function", /Loan score|Could not find any functions|An error occurred/u);
    ok("the Functions section lists the functions released in the Hypervisor's registry",
      // (the reference's current build lists Name, Source, Owning project, Status and Published date; a released
      // function is Active)
      /Loan score/u.test(after(functions, "Function 1 New function", 200)) && /Active/u.test(after(functions, "Loan score", 80)) && !/Could not find any functions|An error occurred/u.test(functions),
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

    const overview = await visit("/workspace/ontology/object-type/loan/overview", /Last edited (?!X days).* by \w+/u);
    ok("an object type opens over daemon truth: its properties, its last edit and its author",
      /Loan/u.test(overview) && /Properties 3/u.test(overview) && /Last edited .* by/u.test(overview) && !/Failed to load object type/u.test(overview),
      `${(overview.match(/Properties \d+|Last edited [^·]{0,40}by \w+/gu) || []).join(" · ")}`);
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
    // (waited for until the search has counted: the page says "No health issues found" before the search runs too)
    let health = ""; for (let i = 0; i < 15 && !/Registration and index failures \d+ |Loading full ontology failed/u.test(health); i++) { await pg.waitForTimeout(800); health = await text(); }
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

    // ---- Proposals (cut O6): the caller's ODK ontology proposals, a proposal's page, and its decisions ------------------
    // Three proposals on the draft's current revision, each describing one type. Approving the first applies it (the
    // ontology moves on, so the third goes stale); the second is closed; the third's approval is refused by the daemon.
    passthrough.clear(); fenced.clear(); unnamed.clear(); htmlAnswers.clear(); gqlErrors.clear(); pageErrors.length = 0;
    const ONT = await import(path.join(HERE, "adopted-ontology.mjs"));
    const cur = (await d("GET", `/v1/hypervisor/odk/domain-ontologies/${made?.id}`)).j.ontology || {};
    const withDesc = (id, text) => (cur.canonical_object_model?.object_types || []).map((o) => (o.id === id ? { ...o, description: text } : o));
    const propose = async (title, rationale, typeId, text) => (await d("POST", "/v1/hypervisor/odk/ontology-proposals", { ontology_ref: made?.id, title, rationale, expected_revision: cur.revision,
      changes: { canonical_object_model: { ...cur.canonical_object_model, object_types: withDesc(typeId, text) } } })).j.ontology_proposal || {};
    const pLoan = await propose("Describe the loan type", "Loans need a description.", "loan", "A loan on the book");
    const pBorrower = await propose("Describe the borrower type", "Borrowers need one too.", "borrower", "A person who holds a loan");
    const pBranch = await propose("Describe the branch type", "Proposed on the same revision.", "branch", "A lending office");
    const proposal = async (id) => (await d("GET", `/v1/hypervisor/odk/ontology-proposals/${id}`)).j.ontology_proposal || {};
    const ontologyNow = async () => (await d("GET", `/v1/hypervisor/odk/domain-ontologies/${made?.id}`)).j.ontology || {};
    const G = { cookie: COOKIE, "content-type": "application/json", referer: `${SERVE}/workspace/ontology/home/proposals` };
    const gql = (operationName, query, variables) => fetch(`${SERVE}/graphql-gateway/api/graphql?q=${operationName}`, { method: "POST", headers: G, body: JSON.stringify({ operationName, query, variables }) }).then((r) => r.json()).catch(() => ({}));
    const refusalOf = (j) => `${j.errors?.[0]?.extensions?.errorName || ""} ${j.errors?.[0]?.message || ""}`;

    const yours = await visit("/workspace/ontology/home/proposals", /Describe the branch type|No proposals|Failed/u);
    ok("the Proposals section lists the caller's ODK proposals (Your proposals: the three they proposed, each Pending approval), not \"No proposals\"",
      ["Describe the loan type", "Describe the borrower type", "Describe the branch type"].every((t) => yours.includes(t)) && (yours.match(/Pending approval/gu) || []).length === 3 && !/No proposals/u.test(yours),
      after(yours, "Sort: Recently created", 260));

    const pagePath = `/workspace/ontology/proposals/${ONT.proposalRidOf(pLoan.id)}`;
    const overview2 = await visit(pagePath, /Ontology changes on this branch.*Edited|An error has occurred|cannot be found/u);
    await pg.getByText("Review changes", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    let review = ""; for (let i = 0; i < 15 && !/Description A loan on the book|An error has occurred/u.test(review); i++) { await pg.waitForTimeout(800); review = await text(); }
    await pg.getByText("History", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    let branchHistory = ""; for (let i = 0; i < 12 && !/Branch history.*Loan Edited|No changes/u.test(branchHistory); i++) { await pg.waitForTimeout(800); branchHistory = await text(); }
    ok("a proposal's page shows its change set from the ODK record: its title, rationale and status, the type it edits and the edit itself, and its history",
      /Describe the loan type 1 task Pending approval/u.test(overview2) && /Loans need a description\./u.test(overview2) && /Ontology changes on this branch.*Loan Edited/u.test(overview2)
        && /Loan .*GENERAL INFORMATION 1 edit Description A loan on the book/u.test(review) && /Branch history.*Describe the loan type Loan Edited/u.test(branchHistory) && !/An error has occurred/u.test(overview2 + review),
      `${after(overview2, "Describe the loan type 1 task", 50)} · ${after(review, "GENERAL INFORMATION", 60)} · ${after(branchHistory, "Branch history", 90)}`);

    // Approve (Review changes) is the daemon's apply: an ODK proposal merges when its review approves it
    await pg.getByText("Review changes", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(2500);
    await pg.getByRole("button", { name: "Approve", exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    let approved = ""; for (let i = 0; i < 15 && !/1 task Completed/u.test(approved); i++) { await pg.waitForTimeout(800); approved = await text(); }
    const loanNow = await proposal(pLoan.id), afterApply = await ontologyNow();
    ok("approving a proposal applies it through the daemon's /apply under the caller's session: the ontology takes the change at the next revision, receipted, and the proposal reads merged",
      loanNow.status === "applied" && loanNow.applied?.resulting_revision === cur.revision + 1 && /^agentgres:\/\/odk-ontology-receipt\//u.test(loanNow.applied?.ontology_receipt_ref || "")
        && afterApply.revision === cur.revision + 1 && afterApply.canonical_object_model?.object_types?.find((o) => o.id === "loan")?.description === "A loan on the book" && /1 task Completed/u.test(approved),
      `${loanNow.status} → revision ${afterApply.revision} · ${loanNow.applied?.ontology_receipt_ref || "no receipt"} · ${after(approved, "Describe the loan type 1 task", 40)}`);

    // the third proposal was made on the revision the first one replaced: the daemon refuses its apply by name
    const reviewDoc = "mutation ReviewApprovalSubRequests($reviewType: ApprovalSubRequestReviewType!, $taskRid: RID!, $subRequestIdAndVersions: [ApprovalSubRequestIdAndVersion!]!) { reviewApprovalSubRequests(reviewType: $reviewType, rid: $taskRid, subRequestIdAndVersions: $subRequestIdAndVersions) { rid status __typename } }";
    const stale = await gql("ReviewApprovalSubRequests", reviewDoc, { reviewType: "APPROVE", taskRid: ONT.proposalRidOf(pBranch.id), subRequestIdAndVersions: [] });
    const branchNow = await proposal(pBranch.id), afterStale = await ontologyNow();
    ok("a stale proposal's approval is refused by the daemon by name (ontology_proposal_stale): nothing is applied and it stays open",
      /ontology_proposal_stale/u.test(refusalOf(stale)) && /has advanced since this proposal was made/u.test(refusalOf(stale)) && branchNow.status === "open" && afterStale.revision === cur.revision + 1,
      `${refusalOf(stale).slice(0, 120)} · ${branchNow.status} · revision ${afterStale.revision}`);

    // Close (the page's trash button, confirmed) is the daemon's withdraw
    await visit(`/workspace/ontology/proposals/${ONT.proposalRidOf(pBorrower.id)}`, /tasks? Pending approval/u);
    await pg.locator("button:has([data-icon=trash])").first().click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(1200);
    await pg.getByRole("button", { name: "Confirm", exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    let closedToast = ""; for (let i = 0; i < 8 && !/Proposal closed|tasks? Closed/u.test(closedToast); i++) { await pg.waitForTimeout(600); closedToast = await text(); }
    // (read again from a fresh load: the page reads the withdrawn record, not the mutation's cached answer)
    const closedPage = await visit(`/workspace/ontology/proposals/${ONT.proposalRidOf(pBorrower.id)}`, /tasks? Closed/u);
    const borrowerNow = await proposal(pBorrower.id), owner2 = ((await d("GET", "/v1/hypervisor/auth/whoami")).j.principal || {}).principal_ref;
    ok("closing a proposal withdraws it through the daemon's /withdraw (by the caller), and it reads closed",
      borrowerNow.status === "withdrawn" && borrowerNow.withdrawn?.withdrawn_by === owner2 && /Describe the borrower type \d+ tasks? Closed/u.test(closedPage) && /Proposal is closed and can no longer be worked on/u.test(closedPage),
      `${borrowerNow.status} by ${borrowerNow.withdrawn?.withdrawn_by === owner2 ? "the caller" : borrowerNow.withdrawn?.withdrawn_by} · ${after(closedPage, "Describe the borrower type", 110)}`);

    // the section's tabs sort the proposals by state
    const tab = async (name, want) => { await visit("/workspace/ontology/home/proposals", /Sort: Recently created/u); await pg.getByRole("tab", { name, exact: true }).click({ timeout: 8000 }).catch(() => {}); let t = ""; for (let i = 0; i < 10 && !want.test(t); i++) { await pg.waitForTimeout(700); t = await text(); } return after(t, "Sort: Recently created", 200); };
    const merged = await tab("Merged proposals", /Describe the loan type/u), closedTab = await tab("Closed proposals", /Describe the borrower type/u), inReview = await tab("In review", /Describe the branch type/u);
    const assigned = await tab("Assigned to you", /Describe the branch type/u);
    ok("the Proposals tabs sort the ODK proposals by state: Merged is the applied one (Completed), Closed the withdrawn one, In review and Assigned to you the open one (the caller owns its ontology, so the daemon reads them as one who may apply it)",
      /Describe the loan type .*Completed/u.test(merged) && !/borrower|branch type/u.test(merged) && /Describe the borrower type .*Closed/u.test(closedTab) && !/loan type|branch type/u.test(closedTab)
        && /Describe the branch type .*Pending approval/u.test(inReview) && !/loan type|borrower/u.test(inReview) && /Describe the branch type .*Pending approval/u.test(assigned) && !/loan type|borrower/u.test(assigned),
      `merged: ${merged.slice(22, 90)} · closed: ${closedTab.slice(22, 90)} · in review: ${inReview.slice(22, 90)} · assigned: ${assigned.slice(22, 60)}`);

    // Create branch opens over the caller's ontology and namespace; creating one is refused by name (no branch is kept)
    await visit("/workspace/ontology/home/proposals", /Sort: Recently created/u);
    await pg.getByRole("button", { name: "Select a branch" }).click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(1500);
    const switcher = await text();
    await pg.getByText("Create new branch", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(3000);
    await pg.getByPlaceholder("A short descriptive name for this branch").fill("Try a branch").catch(() => {});
    await pg.waitForTimeout(1200);
    const dialog = await text();
    await pg.getByRole("button", { name: "Create", exact: true }).click({ timeout: 8000 }).catch(() => {});
    let created = ""; for (let i = 0; i < 10 && !/keeps no ontology branches/u.test(created); i++) { await pg.waitForTimeout(700); created = await text(); }
    const allProposals = (await d("GET", "/v1/hypervisor/odk/ontology-proposals")).j.ontology_proposals || [];
    ok("Create branch opens over the caller's ontology and namespace, the switcher lists no branches, and creating one is refused by name (the Hypervisor keeps no ontology branches); nothing is created",
      /Main Default No branches/u.test(switcher) && /Ontology Loans/u.test(dialog) && /Space local|local Space/u.test(dialog) && !/Failed to load ontologies/u.test(dialog)
        && /The Hypervisor keeps no ontology branches/u.test(created) && allProposals.length === 3,
      `${after(switcher, "Create new branch", 40)} · ${after(dialog, "Ontology", 30)} · ${after(created, "The Hypervisor keeps", 60)} · proposals ${allProposals.length}`);

    // every other write on a proposal is refused by name, and changes nothing
    const disapprove = await gql("ReviewSubRequests", "mutation ReviewSubRequests($reason: String, $reviewType: ApprovalSubRequestReviewType!, $rid: RID!, $subRequestIdAndVersions: [ApprovalSubRequestIdAndVersion!]!) { reviewApprovalSubRequests(reason: $reason, reviewType: $reviewType, rid: $rid, subRequestIdAndVersions: $subRequestIdAndVersions) { rid status __typename } }", { reason: "no", reviewType: "DISAPPROVE", rid: ONT.proposalRidOf(pBranch.id), subRequestIdAndVersions: [] });
    const reviewers = await gql("UpdateReviewersMutation", "mutation UpdateReviewersMutation($principalIdsToAdd: [String!]!, $principalIdsToRemove: [String!]!, $taskRid: RID!) { updateApprovalRequestReviewers(principalIdsToAdd: $principalIdsToAdd, principalIdsToRemove: $principalIdsToRemove, rid: $taskRid) { request { reviewers { id } } } }", { principalIdsToAdd: ["x"], principalIdsToRemove: [], taskRid: ONT.proposalRidOf(pBranch.id) });
    const retitle = await gql("UpdateProposalTitle", "mutation UpdateProposalTitle($rid: RID!, $title: String!) { updateApprovalRequest(rid: $rid, title: $title) { title } }", { rid: ONT.proposalRidOf(pBranch.id), title: "Renamed" });
    const reclose = await gql("CloseProposal", "mutation CloseProposal($rid: RID!) { closeApprovalRequest(rid: $rid) { status } }", { rid: ONT.proposalRidOf(pLoan.id) });
    const restWrite = await fetch(`${SERVE}/approvals/api/task-requests/${ONT.proposalRidOf(pBranch.id)}/reviewers`, { method: "POST", headers: G, body: "{}" }).then(async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) }));
    const untouched = await proposal(pBranch.id);
    ok("rejecting, reviewers, retitling and any approvals write are refused by name, a decided proposal cannot be decided again, and none of it changes the record",
      /OntologyProposalRejectionNotKept/u.test(refusalOf(disapprove)) && /OntologyProposalReviewersNotKept/u.test(refusalOf(reviewers)) && /OntologyProposalNotEditable/u.test(refusalOf(retitle))
        && /OntologyProposalDecided/u.test(refusalOf(reclose)) && restWrite.status === 409 && restWrite.j.errorName === "Hypervisor:OntologyProposalWriteRefused"
        && untouched.status === "open" && untouched.title === "Describe the branch type" && (await proposal(pLoan.id)).status === "applied",
      `${refusalOf(disapprove).split(" ")[0]} · ${refusalOf(reviewers).split(" ")[0]} · ${refusalOf(retitle).split(" ")[0]} · ${refusalOf(reclose).split(" ")[0]} · REST ${restWrite.status} ${restWrite.j.errorName}`);

    ok("the proposal pages reach no mirror beyond the reference's chrome, answer no read with the serve's HTML page, and name every gap they meet",
      [...passthrough].every((p) => CHROME.has(p)) && [...unnamed].every((u) => /\/comments\/api\/comments\/counts/u.test(u)) && htmlAnswers.size === 0
        && [...gqlErrors].every((m) => /keeps no ontology branches/u.test(m)) && pageErrors.every((m) => /keeps no ontology branches/u.test(m)),
      `passthrough ${[...passthrough].filter((p) => !CHROME.has(p)).join(",") || "chrome only"} · unnamed ${[...unnamed].filter((u) => !/comments/u.test(u)).join(",") || "none (comments are the comment lane's own gap)"} · html ${[...htmlAnswers].join(",") || "none"} · gql ${[...gqlErrors].filter((m) => !/keeps no ontology branches/u.test(m)).slice(0, 2).join(" | ") || "only the named refusal"} · page ${pageErrors.filter((m) => !/keeps no ontology branches/u.test(m)).slice(0, 1).join("") || "none"}`);

    // ---- Who may edit, create and save (cut O7): every permission the pages offer is the daemon's reading of the caller
    // (caller_may_change: the ontology's owner, or an administrator of its organization). Each person in a fresh browser (the
    // reference keeps unsaved edits in the browser), each page's reads watched as above.
    const instrument = (page) => {
      const seen = { passthrough: new Set(), unnamed: new Set(), html: new Set(), gql: new Set(), ops: new Set(), pageErrors: [] };
      page.on("pageerror", (e) => seen.pageErrors.push(String(e.message).slice(0, 160)));
      page.on("response", async (r) => {
        const u = new URL(r.url()); const key = `${r.request().method()} ${u.pathname.replace(/ri\.[\w.-]+/gu, "<rid>")}`;
        if (r.headers()["x-ioi-mirror-passthrough"] === "1") seen.passthrough.add(key);
        if (/^\/[a-z][a-z0-9-]*\/api\//u.test(u.pathname) && /text\/html/u.test(r.headers()["content-type"] || "")) seen.html.add(key);
        if (r.status() === 501) { const j = await r.json().catch(() => ({})); if (j.errorName !== "Hypervisor:OntologyReadNotBound") seen.unnamed.add(key); }
        if (/graphql/u.test(u.pathname)) { for (const op of (u.searchParams.get("q") || "").split(",").filter(Boolean)) seen.ops.add(op); const t = await r.text().catch(() => ""); for (const m of t.matchAll(/"message":"([^"]{0,90})/gu)) seen.gql.add(m[1]); }
      });
      return seen;
    };
    const personPage = async (sessionToken) => {
      const c = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
      await c.addCookies([{ name: "ioi_session", value: sessionToken, url: SERVE }]);
      const page = await c.newPage();
      const seen = instrument(page);
      const read = async () => (await page.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
      const go = async (p, until) => { await page.goto(`${SERVE}${p}`, { waitUntil: "domcontentloaded", timeout: 60000 }); let t = ""; for (let i = 0; i < 25; i++) { await page.waitForTimeout(800); t = await read(); if (!until || until.test(t)) break; } return t; };
      const waitText = async (want, n = 15) => { let t = ""; for (let i = 0; i < n; i++) { await page.waitForTimeout(700); t = await read(); if (want.test(t)) break; } return t; };
      const tooltips = () => page.evaluate(() => [...new Set([...document.querySelectorAll("[class*=tooltip]")].map((e) => e.innerText.trim()).filter(Boolean))].join(" | "));
      return { page, seen, read, go, waitText, tooltips };
    };
    const ownerNow = await ontologyNow();
    const M = await personPage(memberLogin.session_token);
    let O = await personPage(boot.session_token);
    const ownerSeen = [];

    // the member: the type and link pages say they may not edit, and New is disabled with the reference's own reason
    const memberType = await M.go("/workspace/ontology/object-type/branch/overview", /You do not have edit permissions to this object type/u);
    const memberLink = await M.go("/workspace/ontology/link-type/held_by/overview", /You do not have edit permissions to this link type/u);
    await M.go("/workspace/ontology/home/discover", /recently modified/u);
    const memberNew = M.page.getByRole("button", { name: "New", exact: true }).first();
    const memberNewDisabled = await memberNew.getAttribute("aria-disabled").catch(() => null);
    await memberNew.hover().catch(() => {});
    await M.page.waitForTimeout(1200);
    const memberTip = await M.tooltips();
    // the owner: the same pages are editable (no read-only banner), and New offers the kinds the ODK model holds
    const ownerType = await O.go("/workspace/ontology/object-type/branch/overview", /Type here…|You do not have edit permissions/u);
    ok("who may edit a type is the daemon's answer: a member who may not change the ontology reads the reference's own \"You do not have edit permissions\" on its type and link pages, and its owner gets the editable page",
      /You do not have edit permissions to this object type/u.test(memberType) && /You do not have edit permissions to this link type/u.test(memberLink)
        && /Type here…/u.test(ownerType) && !/You do not have edit permissions/u.test(ownerType) && memberMay === false && ownerMay === true,
      `member: ${after(memberType, "You do not have edit", 50)} · ${after(memberLink, "You do not have edit", 48)} · owner: ${/Type here…/u.test(ownerType) ? "editable" : "read-only"} · daemon reads member ${memberMay}, owner ${ownerMay}`);

    // the owner edits the type's description: Review changes shows the edit, and the reference's own validation keeps Save to
    // ontology disabled — an ODK type has no backing datasource. Nothing reaches the daemon.
    await O.page.getByText("Type here…").first().click({ timeout: 8000 }).catch(() => {});
    await O.page.waitForTimeout(500);
    await O.page.keyboard.type("A lending office");
    await O.page.keyboard.press("Enter");
    await O.waitText(/1 edit/u, 8);
    await O.page.getByRole("button", { name: "Save", exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    const reviewed = await O.waitText(/Backing datasource is missing|An error occurred while validating/u, 20);
    const saveToOntology = O.page.getByRole("button", { name: /Save to ontology/u }).first();
    const saveDisabled = (await saveToOntology.getAttribute("aria-disabled").catch(() => null)) === "true" || await saveToOntology.isDisabled().catch(() => false);
    const afterTypeEdit = await ontologyNow();
    ok("its owner's edit to a type reaches Review changes (the edit shown), where the reference's own validation lists \"Backing datasource is missing\" and keeps Save to ontology disabled — and the daemon's ontology is untouched",
      /Description A lending office/u.test(reviewed) && /Backing datasource is missing/u.test(reviewed) && saveDisabled && afterTypeEdit.revision === ownerNow.revision
        && !afterTypeEdit.canonical_object_model?.object_types?.find((o) => o.id === "branch")?.description,
      `${after(reviewed, "GENERAL INFORMATION", 110)} · Save to ontology ${saveDisabled ? "disabled" : "ENABLED"} · revision ${ownerNow.revision} → ${afterTypeEdit.revision}`);

    // an action type needs no datasource, so its edit reaches the save itself — refused by name, nothing written. (A fresh
    // browser: the reference keeps the type edit above, unsaved, and would review both together.)
    ownerSeen.push(O.seen); await O.page.context().close();
    O = await personPage(boot.session_token);
    await O.go("/workspace/ontology/home/action-type", /Approve/u);
    await O.page.getByText("Approve", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await O.waitText(/Type here…/u, 15);
    await O.page.getByText("Type here…").first().click({ timeout: 8000 }).catch(() => {});
    await O.page.waitForTimeout(500);
    await O.page.keyboard.type("Approve a loan");
    await O.page.keyboard.press("Enter");
    await O.waitText(/1 edit/u, 8);
    await O.page.getByRole("button", { name: "Save", exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await O.waitText(/Description Approve a loan/u, 15);
    await O.page.getByRole("button", { name: /Save to ontology/u }).first().click({ timeout: 8000 }).catch(() => {});
    await O.waitText(/Save changes to Ontology/u, 8);
    await O.page.getByRole("button", { name: "Save changes", exact: true }).click({ timeout: 8000 }).catch(() => {});
    const refusedSave = await O.waitText(/Hypervisor:OntologyEditNotBound/u, 15);
    const afterActionSave = await ontologyNow();
    ok("an action type's edit (it needs no datasource) reaches Save changes, and the save is refused by name (Hypervisor:OntologyEditNotBound): the daemon's ontology keeps its revision and the action type its description",
      /Failed to save changes to the ontology/u.test(refusedSave) && /Hypervisor:OntologyEditNotBound/u.test(refusedSave) && /Saving from the Ontology Manager is not bound yet/u.test(refusedSave)
        && afterActionSave.revision === ownerNow.revision && !afterActionSave.canonical_object_model?.action_types?.find((a) => a.id === "approve")?.description,
      `${after(refusedSave, "Failed to save changes", 110)} · revision ${ownerNow.revision} → ${afterActionSave.revision}`);

    // New: the owner's menu offers object, link and action types; the kinds the model keeps none of stay disabled; Object type
    // opens the reference's creation wizard, whose first step asks for a backing datasource
    await O.go("/workspace/ontology/home/discover", /recently modified/u);
    const ownerNew = O.page.getByRole("button", { name: "New", exact: true }).first();
    const ownerNewDisabled = await ownerNew.getAttribute("aria-disabled").catch(() => null);
    await ownerNew.click({ timeout: 8000 }).catch(() => {});
    await O.page.waitForTimeout(1500);
    const menu = await O.page.evaluate(() => Object.fromEntries([...document.querySelectorAll(".bp6-menu-item, .bp5-menu-item, .bp4-menu-item")].map((b) => [b.innerText.split("\n")[0].trim(), /disabled/.test(b.className)])));
    await O.page.locator(".bp6-menu-item, .bp5-menu-item, .bp4-menu-item").filter({ hasText: /^Object type/u }).first().click({ timeout: 8000 }).catch(() => {});
    const wizard = await O.waitText(/Object type backing/u, 10);
    const wizardNext = O.page.getByRole("button", { name: "Next", exact: true }).first();
    const nextDisabled = (await wizardNext.getAttribute("aria-disabled").catch(() => null)) === "true" || await wizardNext.isDisabled().catch(() => false);
    ok("New is the daemon's answer too: disabled for the member, whose tooltip is the reference's own \"You do not have permission to create new entities on this ontology.\" (true — the daemon refuses their patch); its owner's menu offers object, link and action types",
      memberNewDisabled === "true" && /You do not have permission to create new entities on this ontology\./u.test(memberTip) && memberPatch.status === 403
        && ownerNewDisabled !== "true" && menu["Object type"] === false && menu["Link type"] === false && menu["Action type"] === false,
      `member: ${memberNewDisabled === "true" ? "disabled" : "ENABLED"} "${memberTip.slice(0, 70)}" · owner: ${ownerNewDisabled === "true" ? "DISABLED" : "enabled"} ${JSON.stringify(menu)}`);
    ok("its owner's New → Object type opens the reference's creation wizard, whose first step asks for the type's backing datasource (Next disabled until one is chosen); the kinds the ODK model keeps none of (shared properties, groups, interfaces) stay disabled",
      /STEP 1 Object type backing/u.test(wizard) && /Continue with an empty datasource/u.test(wizard) && nextDisabled
        && menu["Shared property"] === true && menu.Group === true && menu.Interface === true,
      `${after(wizard, "STEP 1", 60)} · Next ${nextDisabled ? "disabled" : "ENABLED"}`);

    // an object type's Object views: the page environment names no object view editor, so the reference disables the tab with its
    // own reason and reads nothing of objects
    O.seen.ops.clear();
    const views = await O.go("/workspace/ontology/object-type/loan/object-views", /Object views are not enabled|No object selected|Failed to load object view/u);
    await O.page.waitForTimeout(2000);
    const viewReads = [...O.seen.ops].filter((op) => /^(ObjectsQuery|ObjectViewTabQuery|PinnedObjectQuery|ObjectFromUrlParamQuery|FullViewQuery|ObjectRidQuery)$/u.test(op));
    ok("an object type's Object views tab is disabled with the reference's own reason, \"Object views are not enabled\" (the Hypervisor keeps no object views), and reads nothing of objects",
      /Object views are not enabled/u.test(views) && !/No object selected|Failed to load object view/u.test(views) && viewReads.length === 0,
      `${after(views, "Object views are not", 30)} · object reads ${viewReads.join(",") || "none"}`);

    // Ontology configuration → Proceed to migration: the assistant finds nothing it may move into project permissions
    await O.go("/workspace/ontology/home/advanced", /Proceed to migration/u);
    await O.page.getByText("Proceed to migration").first().click({ timeout: 8000 }).catch(() => {});
    await O.waitText(/Ontology projects migration assistant/u, 10);
    await O.page.getByText("Select resources to migrate", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    const recommended = await O.waitText(/No project with recommendations|Failed to load Ontology entities/u, 15);
    await O.page.getByText("Individual resources").first().click({ timeout: 8000 }).catch(() => {});
    const individual = await O.waitText(/Could not find any object types|Loan/u, 10);
    const continueButton = O.page.getByRole("button", { name: /Continue migrating/u }).first();
    const continueDisabled = (await continueButton.getAttribute("aria-disabled").catch(() => null)) === "true" || await continueButton.isDisabled().catch(() => false);
    ok("Proceed to migration opens the reference's migration assistant, which finds nothing it may move into project permissions: no project with recommendations, no migratable resource, Continue migrating 0 resources disabled — the Hypervisor keeps no project permissions for ontology resources",
      O.page.url().endsWith("/workspace/ontology/project-permission-migration") && /Recommended projects 0/u.test(recommended) && /No project with recommendations/u.test(recommended)
        && /Migratable resources only .*Could not find any object types/u.test(individual) && /Continue migrating 0 resources/u.test(individual) && continueDisabled && !/Failed to load Ontology entities/u.test(recommended + individual),
      `${after(recommended, "Recommended projects", 40)} · ${after(individual, "Migratable resources only", 70)} · continue ${continueDisabled ? "disabled" : "ENABLED"}`);

    const personGaps = [M.seen, ...ownerSeen, O.seen];
    const allowedGql = (m) => /is not bound in the Hypervisor adapter yet/u.test(m);
    ok("the permission, edit, save, New, object view and migration pages reach no mirror beyond the reference's chrome, answer no read with the serve's HTML page, and every gap they meet is named",
      personGaps.every((s) => [...s.passthrough].every((p) => CHROME.has(p)) && s.unnamed.size === 0 && s.html.size === 0 && [...s.gql].every(allowedGql) && s.pageErrors.every(allowedGql)),
      personGaps.map((s, i) => `${i ? "owner" : "member"}: passthrough ${[...s.passthrough].filter((p) => !CHROME.has(p)).join(",") || "chrome only"} · unnamed ${[...s.unnamed].join(",") || "none"} · html ${[...s.html].join(",") || "none"} · gql ${[...s.gql].filter((m) => !allowedGql(m)).slice(0, 2).join(" | ") || "named only"} · page ${s.pageErrors.filter((m) => !allowedGql(m)).slice(0, 1).join("") || "none"}`).join(" ‖ "));
    await M.page.context().close(); await O.page.context().close();

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
    const downProposals = await visit("/workspace/ontology/home/proposals", /Sort: Recently created .{8,}|No proposals/u);
    const downProposal = await visit(pagePath, /did not answer|cannot be found|1 task/u);
    ok("with the daemon stopped, the Proposals section and a proposal's page show their error — never \"No proposals\" or a proposal that is not there",
      /Sort: Recently created Failed to load requests\./u.test(downProposals) && !/No proposals/u.test(downProposals)
        && /ProposalDetailQuery: \/v1\/hypervisor\/odk\/ontology-proposals did not answer/u.test(downProposal) && /View all proposals/u.test(downProposal) && !/1 task/u.test(downProposal),
      `${after(downProposals, "Sort: Recently created", 50)} · ${after(downProposal, "ProposalDetailQuery", 90)}`);
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
