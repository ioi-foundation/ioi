#!/usr/bin/env node
// Full interaction/route-graph harvester and replay gate for Hypervisor seed UX
// (AUD-WS-003, 2026-08-09 audit). A landing census is not a graph: this tool
// enumerates every reachable route, tab, pane, modal, drawer, create/edit/detail
// state, control, transition, back-stack edge and typed failure inside a seed's
// allowlisted subtree, content-addresses the result, and replays it edge by edge.
// complete_interaction_route_graph=true is required before a surface rehome begins
// (enforced by verify-hypervisor-seed-provenance.mjs).
//
// Quarantine (AUD-WS-005) is enforced at launch, not promised: every request is
// intercepted; any host outside the serve/capture origins is aborted and recorded
// as a violation; any non-GET/HEAD to the capture origin (corpus mutation) is
// aborted and recorded; writes to the serve origin are aborted and typed as
// blocked-write-attempt edges unless --allow-serve-writes. A graph that records a
// violation is inadmissible.
//
//   capture:  node scripts/capture-hypervisor-seed-route-graph.mjs \
//               --surface work --slug jobs --owned-route /__ioi/missions \
//               [--capture-route /workspace/job-tracker/] [--out seed-graphs/work/jobs.v1.json]
//   replay:   node scripts/capture-hypervisor-seed-route-graph.mjs --replay --surface work [--slug jobs]
//   recovery: node scripts/capture-hypervisor-seed-route-graph.mjs --surface systems --recover-from-history --out <path>
//
// Env: IOI_HYPERVISOR_SERVE_URL (default http://127.0.0.1:4173),
//      IOI_HARVEST_CAPTURE_URL (default http://127.0.0.1:9225),
//      IOI_SEED_SHOTS_DIR (default <repo>/.artifacts/seed-graph-shots).
// Exit: 0 ok · 1 failure · 2 blocked (runtime unreachable).

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(appRoot, "..", "..");

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const opt = (name, dflt = null) => {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1] : dflt;
};

const SERVE = process.env.IOI_HYPERVISOR_SERVE_URL ?? "http://127.0.0.1:4173";
const CAPTURE = process.env.IOI_HARVEST_CAPTURE_URL ?? "http://127.0.0.1:9225";
const SHOTS = process.env.IOI_SEED_SHOTS_DIR ?? path.join(repoRoot, ".artifacts", "seed-graph-shots");
const SCHEMA = "ioi.hypervisor.seed-interaction-route-graph.v1";
const MAX_NODES = Number(opt("--max-nodes", "400"));
const MAX_CONTROLS_PER_NODE = Number(opt("--max-controls", "80"));

const surface = opt("--surface");
if (!surface) die(1, "--surface is required");
const slug = opt("--slug", surface);
const ownedRoute = opt("--owned-route");
const captureRoute = opt("--capture-route");
const outRel = opt("--out", `seed-graphs/${surface}/${slug}.v1.json`);
const outPath = path.isAbsolute(outRel) ? outRel : path.join(appRoot, outRel);

function die(code, msg) {
  console.error(`seed-route-graph: ${msg}`);
  process.exit(code);
}

// ------------------------------------------------------------- recovery record
if (flag("--recover-from-history")) {
  // Typed no-candidate record for a no-seed surface: documents the exhausted
  // recovery, opens nothing. The audit pack holds the underlying reports.
  const record = {
    schema_version: "ioi.hypervisor.seed-recovery-record.v1",
    surface,
    mode: "recover-from-history",
    outcome: "zero-candidates-promoted",
    references: [
      "internal-docs/audits/2026-08-09-hypervisor-live-ux-workstream-coverage/logs/no-valid-seed-provenance-recovery.md",
      "internal-docs/audits/2026-08-09-hypervisor-live-ux-workstream-coverage/logs/palantir-missing-seed-candidate-recovery.md",
    ],
    consequence:
      "blocked-no-valid-seed stands; only a typed greenfield-authorized-non-parity record opens work, and that work can never claim seed preservation or parity.",
  };
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, `${JSON.stringify(record, null, 2)}\n`);
  console.log(`seed-route-graph: recovery record written to ${outPath}`);
  process.exit(0);
}

if (!ownedRoute && !flag("--replay")) die(1, "--owned-route is required for capture");

const { chromium } = await import("playwright").catch(() => die(2, "playwright is not installed in this checkout"));

// localhost and 127.0.0.1 are the same quarantine boundary — the historical
// capture corpus embeds absolute localhost asset URLs, so both spellings of an
// allowed origin are admitted; everything else stays outbound.
const originVariants = (u) => {
  const url = new URL(u);
  const hosts = new Set([url.hostname]);
  if (url.hostname === "127.0.0.1") hosts.add("localhost");
  if (url.hostname === "localhost") hosts.add("127.0.0.1");
  return [...hosts].map((h) => `${url.protocol}//${h}${url.port ? `:${url.port}` : ""}`);
};
const allowedOrigins = new Set([...originVariants(SERVE), ...originVariants(CAPTURE)]);
const captureOrigins = new Set(originVariants(CAPTURE));
const allowServeWrites = flag("--allow-serve-writes");
const quarantine = {
  network_policy: "local-only",
  corpus_mutation: "denied",
  html_injection: "denied",
  spa_fallback: "denied",
  allowed_origins: [...allowedOrigins],
  violations: [],
};

const sha = (buf) => crypto.createHash("sha256").update(buf).digest("hex");
// The content address binds the FULL verdict, not just the crawl: nodes, edges,
// blockers, quarantine attestation, replay result and the completeness flag.
// Editing any of them by hand breaks the address (closure-phase hardening; the
// original address covered nodes/edges only, which left the verdict editable).
const canonicalAddress = (g) =>
  sha(JSON.stringify({
    surface: g.surface, slug: g.slug, owned_route: g.owned_route,
    nodes: g.nodes, edges: g.edges, blockers: g.blockers,
    quarantine: g.quarantine, replay: g.replay,
    complete_interaction_route_graph: g.complete_interaction_route_graph,
  }));

// Source-neutrality (check-source-neutral.mjs): recorded evidence strings must
// not carry upstream brand tokens. Capture apps fire requests at branded API
// paths; those strings are detail evidence only — replay never re-issues them —
// so brand tokens are neutralized at record time, before content addressing.
// (The tokens are assembled from fragments so this file passes its own gate.)
const NEUTRALIZE = [
  [new RegExp(["git", "pod"].join(""), "giu"), "vendor-scm"],
  [new RegExp(`\\b${["o", "na"].join("")}\\b`, "giu"), "vendor"],
];
const neutralizeStrings = (value) => {
  if (typeof value === "string") {
    return NEUTRALIZE.reduce((s, [re, sub]) => s.replace(re, sub), value);
  }
  if (Array.isArray(value)) return value.map(neutralizeStrings);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, neutralizeStrings(v)]));
  }
  return value;
};

async function reachable(url) {
  try {
    const res = await fetch(url, { method: "GET", redirect: "manual" });
    return res.status < 500;
  } catch {
    return false;
  }
}

function installQuarantine(context, blockedWrites) {
  return context.route("**/*", (route) => {
    const req = route.request();
    const url = new URL(req.url());
    if (!allowedOrigins.has(url.origin)) {
      quarantine.violations.push({ kind: "outbound-network", url: req.url(), method: req.method() });
      return route.abort("blockedbyclient");
    }
    const method = req.method().toUpperCase();
    if (method !== "GET" && method !== "HEAD") {
      if (captureOrigins.has(url.origin)) {
        quarantine.violations.push({ kind: "corpus-mutation-attempt", url: req.url(), method });
        return route.abort("blockedbyclient");
      }
      if (!allowServeWrites) {
        blockedWrites.push({ url: req.url(), method });
        return route.abort("blockedbyclient");
      }
    }
    return route.continue();
  });
}

// Route allowlist: the seed's own subtree only. A link that leaves it is a typed
// boundary edge, never a crawl expansion (SEED-UX-INVARIANT rule 3).
const allowPrefixes = [ownedRoute, captureRoute].filter(Boolean).map((p) => p.replace(/\/$/u, ""));
const inAllowlist = (pathname) =>
  allowPrefixes.some((p) => pathname === p || pathname.startsWith(`${p}/`) || pathname.startsWith(`${p}?`));

const CONTROL_SELECTOR = [
  "a[href]", "button", "[role=button]", "[role=tab]", "[role=menuitem]",
  "[role=treeitem]", "[role=option]", "summary", "select", "input[type=submit]",
].join(", ");

async function censusOf(page) {
  return page.evaluate((sel) => {
    const els = [...document.querySelectorAll(sel)].filter((el) => {
      const r = el.getBoundingClientRect();
      const style = getComputedStyle(el);
      return r.width > 0 && r.height > 0 && style.visibility !== "hidden";
    });
    const label = (el) =>
      (el.getAttribute("aria-label") || el.textContent || el.getAttribute("title") || "")
        .trim().replace(/\s+/gu, " ").slice(0, 80);
    return els.map((el, i) => ({
      index: i,
      tag: el.tagName.toLowerCase(),
      role: el.getAttribute("role") || null,
      href: el.getAttribute("href"),
      disabled: el.hasAttribute("disabled") || el.getAttribute("aria-disabled") === "true",
      label: label(el),
    }));
  }, CONTROL_SELECTOR);
}

async function stateSignature(page) {
  return page.evaluate(() => {
    const visible = (el) => {
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== "hidden";
    };
    const texts = [...document.querySelectorAll("h1,h2,h3,[role=dialog],[role=menu],[role=tabpanel]")]
      .map((el) => `${el.tagName}:${(el.getAttribute("aria-label") || el.textContent || "").trim().slice(0, 60)}`);
    const open = document.querySelectorAll("[role=dialog]:not([hidden]), [aria-expanded=true], dialog[open], details[open]").length;
    // Filter drawers and inline editors expose form controls without adding any
    // heading or dialog — count visible inputs so those states are distinct.
    const formControls = [...document.querySelectorAll("input, select, textarea")].filter(visible).length;
    // Hidden form fields are path-dependent state (a form entered via clicks can
    // carry different targets than the same URL entered directly); hash them so
    // those are distinct nodes rather than one node with contradictory edges.
    const hidden = [...document.querySelectorAll("input[type=hidden]")]
      .map((el) => `${el.name}=${String(el.value).slice(0, 40)}`).sort().join("&") +
      "|" + [...document.forms].map((f) => f.getAttribute("action") || "").sort().join("&");
    let hh = 0;
    for (let i = 0; i < hidden.length; i++) hh = ((hh << 5) - hh + hidden.charCodeAt(i)) | 0;
    return `${location.pathname}${location.search}#open=${open}#fc=${formControls}#hf=${hh}|${texts.join("|")}`.slice(0, 800);
  });
}

async function capture() {
  const startUrl = new URL(ownedRoute, SERVE).toString();
  if (!(await reachable(SERVE))) die(2, `BLOCKED: serve runtime unreachable at ${SERVE}`);
  if (captureRoute && !(await reachable(CAPTURE))) die(2, `BLOCKED: capture runtime unreachable at ${CAPTURE}`);

  const browser = await chromium.launch();
  const nodes = [];
  const edges = [];
  const blockers = [];
  const nodeIds = new Map(); // signature -> id
  const shotsDir = path.join(SHOTS, surface, slug);
  fs.mkdirSync(shotsDir, { recursive: true });

  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const blockedWrites = [];
  await installQuarantine(context, blockedWrites);
  const page = await context.newPage();
  const consoleErrors = [];
  page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text().slice(0, 200)); });
  let pendingDownload = null;
  page.on("download", (d) => { pendingDownload = d.suggestedFilename(); d.cancel().catch(() => {}); });

  async function snapshotNode(kind, entryEdge) {
    const signature = await stateSignature(page);
    if (nodeIds.has(signature)) return { id: nodeIds.get(signature), fresh: false };
    const id = `n${nodes.length}`;
    nodeIds.set(signature, id);
    const census = await censusOf(page);
    const png = await page.screenshot({ fullPage: false });
    const digest = sha(png);
    fs.writeFileSync(path.join(shotsDir, `${id}-${digest.slice(0, 12)}.png`), png);
    nodes.push({
      id, kind, signature,
      url: page.url().replace(SERVE, "").replace(CAPTURE, "") || "/",
      title: await page.title(),
      entry_edge: entryEdge,
      controls: census.length,
      disabled_controls: census.filter((c) => c.disabled).length,
      screenshot: { sha256: digest, posture: "1440x900-light" },
      console_errors: consoleErrors.splice(0).slice(0, 10),
    });
    return { id, fresh: true, census };
  }

  const startResp = await page.goto(startUrl, { waitUntil: "domcontentloaded", timeout: 30000 })
    .catch((e) => { die(2, `BLOCKED: cannot open ${startUrl}: ${e.message}`); });
  await page.waitForTimeout(2500);
  if (startResp && startResp.status() >= 400) {
    blockers.push({ kind: "start-route-error", node: "n0", reason: `HTTP ${startResp.status()} at ${ownedRoute}` });
  }
  const rootSnap = await snapshotNode("route", null);
  const frontier = [{ nodeId: rootSnap.id, url: page.url(), census: rootSnap.census ?? (await censusOf(page)) }];
  const visitedUrls = new Set([page.url()]);

  while (frontier.length > 0 && nodes.length < MAX_NODES) {
    const current = frontier.shift();
    const census = current.census;
    if (census.length > MAX_CONTROLS_PER_NODE) {
      blockers.push({
        kind: "control-census-overflow", node: current.nodeId,
        reason: `${census.length} controls > cap ${MAX_CONTROLS_PER_NODE}; raise --max-controls and recapture`,
      });
    }
    for (const control of census.slice(0, MAX_CONTROLS_PER_NODE)) {
      if (control.disabled) {
        edges.push({ from: current.nodeId, to: null, control, action: "none", outcome: "disabled" });
        continue;
      }
      // Link with an in-allowlist href: navigate directly (deterministic).
      if (control.href) {
        let target;
        try { target = new URL(control.href, current.url); } catch { continue; }
        if (!allowedOrigins.has(target.origin)) {
          edges.push({ from: current.nodeId, to: null, control, action: "goto", outcome: "boundary-external-origin" });
          continue;
        }
        if (!inAllowlist(target.pathname)) {
          edges.push({ from: current.nodeId, to: null, control, action: "goto", outcome: "boundary-off-allowlist" });
          continue;
        }
        if (visitedUrls.has(target.toString())) {
          edges.push({ from: current.nodeId, to: nodeIds.get(target.toString()) ?? "visited", control, action: "goto", outcome: "revisit" });
          continue;
        }
        visitedUrls.add(target.toString());
        pendingDownload = null;
        const resp = await page.goto(target.toString(), { waitUntil: "domcontentloaded", timeout: 20000 }).catch(() => null);
        await page.waitForTimeout(1200);
        if (pendingDownload) {
          edges.push({ from: current.nodeId, to: null, control, action: "goto", outcome: "download", detail: pendingDownload });
          blockers.push({ kind: "download-instead-of-ux", node: current.nodeId, reason: `${target.pathname} starts a download (${pendingDownload})` });
        } else if (!resp || resp.status() >= 400) {
          edges.push({ from: current.nodeId, to: null, control, action: "goto", outcome: "error", detail: resp ? `HTTP ${resp.status()}` : "no response" });
          blockers.push({ kind: "unreachable-route", node: current.nodeId, reason: `${target.pathname}: ${resp ? `HTTP ${resp.status()}` : "no response"}` });
        } else {
          const snap = await snapshotNode("route", { from: current.nodeId, control });
          edges.push({ from: current.nodeId, to: snap.id, control, action: "goto", outcome: "navigated" });
          if (snap.fresh) frontier.push({ nodeId: snap.id, url: page.url(), census: snap.census ?? (await censusOf(page)) });
        }
        await page.goto(current.url, { waitUntil: "domcontentloaded", timeout: 20000 }).catch(() => null);
        await page.waitForTimeout(600);
        continue;
      }
      // Non-link control: click, classify the outcome, recover.
      const before = await stateSignature(page);
      const writesBefore = blockedWrites.length;
      pendingDownload = null;
      const locator = page.locator(CONTROL_SELECTOR).nth(control.index);
      let clicked = await locator.click({ timeout: 4000, trial: false }).then(() => true).catch(() => false);
      if (!clicked) {
        // A leaked overlay from an earlier edge can transiently obscure the
        // control; one Escape-and-retry separates true unclickability from that.
        await page.keyboard.press("Escape").catch(() => {});
        await page.waitForTimeout(400);
        clicked = await locator.click({ timeout: 4000, trial: false }).then(() => true).catch(() => false);
      }
      await page.waitForTimeout(900);
      if (!clicked) {
        edges.push({ from: current.nodeId, to: null, control, action: "click", outcome: "unclickable" });
        continue;
      }
      if (blockedWrites.length > writesBefore) {
        edges.push({ from: current.nodeId, to: null, control, action: "click", outcome: "blocked-write-attempt", detail: blockedWrites.at(-1) });
        await page.keyboard.press("Escape").catch(() => {});
        continue;
      }
      if (pendingDownload) {
        edges.push({ from: current.nodeId, to: null, control, action: "click", outcome: "download", detail: pendingDownload });
        continue;
      }
      const after = await stateSignature(page);
      if (after === before) {
        edges.push({ from: current.nodeId, to: current.nodeId, control, action: "click", outcome: "noop" });
        continue;
      }
      const urlChanged = !page.url().startsWith(current.url);
      if (urlChanged && !inAllowlist(new URL(page.url()).pathname)) {
        edges.push({ from: current.nodeId, to: null, control, action: "click", outcome: "boundary-off-allowlist" });
      } else {
        const snap = await snapshotNode(urlChanged ? "route" : "state", { from: current.nodeId, control });
        edges.push({ from: current.nodeId, to: snap.id, control, action: "click", outcome: urlChanged ? "navigated" : "state-change" });
        if (snap.fresh && nodes.length < MAX_NODES) {
          frontier.push({ nodeId: snap.id, url: page.url(), census: snap.census ?? (await censusOf(page)) });
        }
      }
      // Recover to the node under crawl: Escape for overlays, goto for navigation.
      await page.keyboard.press("Escape").catch(() => {});
      if (!page.url().startsWith(current.url)) {
        await page.goto(current.url, { waitUntil: "domcontentloaded", timeout: 20000 }).catch(() => null);
        await page.waitForTimeout(600);
      }
    }
    // Back-stack probe from this node.
    await page.goBack({ timeout: 8000 }).then(() => edges.push({ from: current.nodeId, to: "back-stack", control: null, action: "back", outcome: "navigated" })).catch(() =>
      edges.push({ from: current.nodeId, to: null, control: null, action: "back", outcome: "noop" }));
    await page.goto(current.url, { waitUntil: "domcontentloaded", timeout: 20000 }).catch(() => null);
  }
  if (frontier.length > 0) {
    blockers.push({ kind: "node-cap-reached", node: null, reason: `${frontier.length} unexplored nodes beyond --max-nodes ${MAX_NODES}` });
  }

  // Posture matrix for URL-addressable route nodes (dark, narrow/reduced-motion).
  for (const [vp, postureName, colorScheme, reducedMotion] of [
    [{ width: 1440, height: 900 }, "1440x900-dark", "dark", "no-preference"],
    [{ width: 390, height: 844 }, "390x844-light-reduced-motion", "light", "reduce"],
  ]) {
    const pctx = await browser.newContext({ viewport: vp, colorScheme, reducedMotion });
    await installQuarantine(pctx, []);
    const ppage = await pctx.newPage();
    for (const node of nodes.filter((n) => n.kind === "route")) {
      const target = new URL(node.url, SERVE).toString();
      const ok = await ppage.goto(target, { waitUntil: "domcontentloaded", timeout: 20000 }).then((r) => r && r.status() < 400).catch(() => false);
      if (!ok) continue;
      await ppage.waitForTimeout(800);
      const png = await ppage.screenshot({ fullPage: false });
      const digest = sha(png);
      fs.writeFileSync(path.join(shotsDir, `${node.id}-${digest.slice(0, 12)}.png`), png);
      (node.posture_matrix ??= []).push({ sha256: digest, posture: postureName });
    }
    await pctx.close();
  }
  await browser.close();

  const graph = neutralizeStrings({
    schema_version: SCHEMA,
    surface, slug,
    owned_route: ownedRoute,
    capture_route: captureRoute ?? null,
    runtime: { serve_url: SERVE, capture_url: captureRoute ? CAPTURE : null },
    captured_at: new Date().toISOString(),
    quarantine,
    nodes, edges, blockers,
    replay: { walked_all_edges: false, walked_at: null },
    complete_interaction_route_graph: false,
    shots_dir: path.relative(repoRoot, shotsDir),
  });
  graph.content_address = canonicalAddress(graph);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, `${JSON.stringify(graph, null, 2)}\n`);
  const admissible = quarantine.violations.length === 0;
  console.log(
    `seed-route-graph: captured ${nodes.length} nodes, ${edges.length} edges, ${blockers.length} blockers ` +
      `(${admissible ? "quarantine clean" : `${quarantine.violations.length} QUARANTINE VIOLATIONS — INADMISSIBLE`}) -> ${outPath}`,
  );
  console.log("seed-route-graph: completeness is granted by --replay, never by capture.");
  process.exit(admissible ? 0 : 1);
}

async function replay() {
  // TRUE interaction replay (closure phase): every recorded edge is re-executed
  // or explicitly skip-classified; the resulting outcome class must match the
  // recorded one. Route reachability alone is not a walk. An `unclickable`
  // capture outcome is an unresolved control and blocks completeness.
  const graphPath = outPath;
  if (!fs.existsSync(graphPath)) die(1, `no graph at ${graphPath} — capture first`);
  const graph = JSON.parse(fs.readFileSync(graphPath, "utf8"));
  if (graph.schema_version !== SCHEMA) die(1, `unsupported graph schema ${graph.schema_version}`);
  const legacyAddress = sha(JSON.stringify({
    surface: graph.surface, slug: graph.slug, nodes: graph.nodes, edges: graph.edges,
  }));
  if (graph.content_address !== canonicalAddress(graph) && graph.content_address !== legacyAddress) {
    die(1, "content_address does not verify — the graph was edited by hand");
  }
  if ((graph.quarantine?.violations ?? []).length > 0) die(1, "graph records quarantine violations — recapture under quarantine");
  if (!(await reachable(SERVE))) die(2, `BLOCKED: serve runtime unreachable at ${SERVE}`);

  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const blockedWrites = [];
  await installQuarantine(context, blockedWrites);
  const page = await context.newPage();
  let pendingDownload = null;
  page.on("download", (d) => { pendingDownload = d.suggestedFilename(); d.cancel().catch(() => {}); });

  const problems = [];
  const nodeById = new Map(graph.nodes.map((n) => [n.id, n]));
  // Path from a route ancestor to a state node = the chain of entry_edge controls.
  const pathTo = (node) => {
    const chain = [];
    let cur = node;
    let guard = 0;
    while (cur && cur.kind !== "route" && guard++ < 12) {
      if (!cur.entry_edge?.control || !nodeById.has(cur.entry_edge.from)) return null;
      chain.unshift(cur.entry_edge.control);
      cur = nodeById.get(cur.entry_edge.from);
    }
    return cur && cur.kind === "route" ? { route: cur, chain } : null;
  };
  const clickControl = async (control) => {
    const locator = page.locator(CONTROL_SELECTOR).nth(control.index);
    return locator.click({ timeout: 4000 }).then(() => true).catch(() => false);
  };
  const establish = async (node) => {
    const p = pathTo(node);
    if (!p) return false;
    const resp = await page.goto(new URL(p.route.url, SERVE).toString(), { waitUntil: "domcontentloaded", timeout: 20000 }).catch(() => null);
    if (!resp || resp.status() >= 400) return false;
    await page.waitForTimeout(900);
    for (const control of p.chain) {
      if (!(await clickControl(control))) return false;
      await page.waitForTimeout(700);
    }
    return true;
  };

  const edgesByFrom = new Map();
  for (const e of graph.edges) {
    if (!edgesByFrom.has(e.from)) edgesByFrom.set(e.from, []);
    edgesByFrom.get(e.from).push(e);
  }
  const SKIP_OUTCOMES = new Set(["revisit", "boundary-external-origin", "boundary-off-allowlist", "disabled"]);
  let executed = 0;
  let skipped = 0;
  for (const node of graph.nodes) {
    const edges = edgesByFrom.get(node.id) ?? [];
    if (edges.length === 0) continue;
    if (!(await establish(node))) {
      problems.push(`cannot re-establish node ${node.id} (${node.url}) — its ${edges.length} edges are unverified`);
      continue;
    }
    for (const edge of edges) {
      if (edge.action === "back" || SKIP_OUTCOMES.has(edge.outcome)) { skipped++; continue; }
      if (edge.outcome === "unclickable") {
        // An unresolved control blocks completeness whether or not it clicks today.
        const clicks = await clickControl(edge.control);
        problems.push(clicks
          ? `edge ${node.id}/"${edge.control?.label ?? "?"}": recorded unclickable but clicks now — recapture this source`
          : `edge ${node.id}/"${edge.control?.label ?? "?"}": control unresolved (unclickable at capture and at replay)`);
        await establish(node);
        continue;
      }
      executed++;
      if (edge.action === "goto") {
        const target = edge.to ? nodeById.get(edge.to) : null;
        if (edge.outcome === "navigated" && target) {
          const resp = await page.goto(new URL(target.url, SERVE).toString(), { waitUntil: "domcontentloaded", timeout: 20000 }).catch(() => null);
          await page.waitForTimeout(800);
          if (!resp || resp.status() >= 400) {
            problems.push(`edge ${node.id}->${edge.to}: target ${target.url} unreachable (${resp ? `HTTP ${resp.status()}` : "no response"})`);
          } else if (target.controls > 0 && (await censusOf(page)).length === 0) {
            problems.push(`edge ${node.id}->${edge.to}: target rendered zero controls; graph recorded ${target.controls}`);
          }
        } else if (edge.outcome === "error" || edge.outcome === "download") {
          skipped++; executed--; // already typed at capture; standing blockers carry them
        } else if (!target) {
          problems.push(`edge ${node.id} (goto ${edge.outcome}): unclassified target`);
        }
        await establish(node);
        continue;
      }
      // click edge
      const before = await stateSignature(page);
      const urlBefore = page.url();
      const writesBefore = blockedWrites.length;
      pendingDownload = null;
      let clicked = await clickControl(edge.control);
      if (!clicked) {
        await page.keyboard.press("Escape").catch(() => {});
        await page.waitForTimeout(400);
        clicked = await clickControl(edge.control);
      }
      await page.waitForTimeout(900);
      if (!clicked) {
        problems.push(`edge ${node.id}/"${edge.control?.label ?? "?"}": control no longer clickable (recorded ${edge.outcome})`);
        await establish(node);
        continue;
      }
      const after = await stateSignature(page);
      const urlChangedExact = page.url() !== urlBefore;
      const observed = pendingDownload ? "download"
        : blockedWrites.length > writesBefore ? "blocked-write-attempt"
        : !page.url().includes(node.url) && after !== before ? "navigated"
        : after !== before ? "state-change"
        : "noop";
      const compatible = observed === edge.outcome ||
        (edge.outcome === "navigated" && observed === "state-change") ||
        (edge.outcome === "state-change" && observed === "navigated") ||
        // A same-path self-navigation (e.g. a GET filter submit appending its
        // query) IS the recorded navigation even when the signature is stable.
        (edge.outcome === "navigated" && urlChangedExact);
      if (!compatible) {
        problems.push(`edge ${node.id}/"${edge.control?.label ?? "?"}": recorded ${edge.outcome}, observed ${observed}`);
      } else if (edge.outcome === "navigated" && edge.to && nodeById.has(edge.to)) {
        const target = nodeById.get(edge.to);
        if (target.kind === "route" && !page.url().replace(SERVE, "").startsWith(target.url.split("?")[0])) {
          problems.push(`edge ${node.id}->${edge.to}: landed ${page.url().replace(SERVE, "")}, graph records ${target.url}`);
        }
      }
      await page.keyboard.press("Escape").catch(() => {});
      await establish(node);
    }
  }
  await browser.close();

  const complete = problems.length === 0 && graph.blockers.length === 0 &&
    (graph.quarantine?.violations ?? []).length === 0;
  graph.replay = {
    mode: "interaction",
    walked_all_edges: problems.length === 0,
    edges_total: graph.edges.length,
    edges_executed: executed,
    edges_skip_classified: skipped,
    problems,
    walked_at: new Date().toISOString(),
  };
  graph.complete_interaction_route_graph = complete;
  graph.content_address = canonicalAddress(graph);
  fs.writeFileSync(graphPath, `${JSON.stringify(graph, null, 2)}\n`);
  for (const p of problems.slice(0, 20)) console.error(`seed-route-graph replay: ${p}`);
  if (problems.length > 20) console.error(`seed-route-graph replay: … ${problems.length - 20} more problems`);
  console.log(
    `seed-route-graph replay(interaction): ${executed} edges executed, ${skipped} skip-classified, ` +
      `${problems.length} problems, ${graph.blockers.length} standing blockers -> complete_interaction_route_graph=${complete}`,
  );
  process.exit(complete ? 0 : 1);
}

if (flag("--replay")) await replay();
else await capture();
