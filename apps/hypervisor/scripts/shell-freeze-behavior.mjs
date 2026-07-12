#!/usr/bin/env node
// Shell freeze — BEHAVIORAL layer (phase 0b of the shell-ownership program).
//
// Crawls the live shell and freezes what the code-level manifest cannot: the composed runtime.
// Per route it captures
//   · a normalized DOM fingerprint (tag / testid / sorted classes, recursively) with volatile
//     data-driven subtrees pruned to presence markers, so daemon data changing never reads as
//     shell drift;
//   · the RUNTIME ANIMATION inventory — document.getAnimations() sampled every 100ms from first
//     paint through settle, so transient loading spinners/fades are enumerated even though no
//     final screenshot could ever show them;
//   · same-origin network requests (normalized) and console errors/warnings (environment noise
//     allowlisted);
//   · a screenshot (human reference only — the JSON is the freeze, screenshots are not).
//
// Output: apps/hypervisor/shell-parity/behavior-baseline.json (committed)
//         internal-docs/.../playwright-screenshots/shell-parity/*.png (untracked, reference)
//
// Usage: node apps/hypervisor/scripts/shell-freeze-behavior.mjs [--check] [--base URL]
//   default: (re)write the freeze against the running serve (:4173)
//   --check: recapture and diff against the committed freeze; exit 1 on drift
//   --base:  capture against a different serve origin (used to prove an alternate shell tree
//            composes identically — the vendored-source equivalence gate)

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { chromium } from "playwright";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "..", "shell-parity");
const SHOTS = join(HERE, "..", "..", "..", "internal-docs", "prompts", "hypervisor-application-surface-plans", "playwright-screenshots", "shell-parity");
const CHECK = process.argv.includes("--check");
const baseIdx = process.argv.indexOf("--base");
const BASE = baseIdx > -1 ? process.argv[baseIdx + 1].replace(/\/$/, "") : "http://127.0.0.1:4173";

const ROUTES = ["/ai", "/ai#new-session", "/projects", "/automations", "/settings"];

// Data-driven containers: fingerprint the container, prune its children to a presence marker.
// Daemon truth changing (sessions appearing, runs finishing) must never read as SHELL drift.
const VOLATILE = [
  '[data-testid="recent-agent-executions"]',
  '[data-testid="environments-list"]',
  '[data-testid="changelog-preview"]',
  '[data-testid="nudges"]',
  '[data-testid="projects-list"]', // estate projects come and go; the SHELL around them is the freeze
  "#ioi-home-explorer", // augmentation-owned; frozen by its own done-bar, not the shell freeze
  "#ioi-hb-recent",
];
// Environment noise (offline box: external widget/telemetry DNS failures), not shell behavior.
const CONSOLE_ALLOW = [/usepylon/i, /ERR_NAME_NOT_RESOLVED/i, /posthog/i, /sentry/i, /segment/i, /Failed to load resource/i, /WebSocket/i, /onboarding completion/i, /ConfigCat/i /* flag-eval warnings race the user-object load */, /OrgEventStreamManager|Stream error/ /* event-stream reconnects fire on their own clock */];
const NET_SKIP = [
  /^https?:\/\/(?!127\.0\.0\.1)/i, // external hosts: environment, not shell
  // DATA-CONDITIONAL calls: fired per estate record (per-project role/prebuild lookups, flag
  // refetch) — presence tracks estate data, not shell behavior, so they can't live in the freeze.
  /GroupService\/ListRoleAssignments/, /PrebuildService\/ListPrebuilds/, /feature-flags\/configcat/,
  // Static-asset delivery is the WIRE gate's domain (proven 383/383 there); which lazy chunks a
  // route pulls varies with estate data, so asset fetches don't belong in the behavior freeze.
  /^GET \/static\//,
  // Streaming/long-poll lifecycle (event watch + reconnects) fires on its own clock, not per view.
  /EventService\/WatchEvents/,
];
// Content/data-driven animations track estate data, not shell code — excluded like volatile DOM:
// fadeOut (empty state replaced), animate-in (list items entering), animate-spin (data-load
// spinners). Bespoke shell animations (pulse, brand motion) stay in the freeze, and every
// keyframe DEFINITION stays enumerated in the code-level CSS inventory regardless.
const ANIM_SKIP = [/^CSSAnimation:fadeOut:/, /\.animate-in(:|\.|$)/, /\.animate-spin(:|\.|$)/];

function normalizeUrl(u) {
  try {
    const url = new URL(u, BASE);
    let p = url.pathname
      .replace(/\/details\/[^/]+/g, "/details/:id")
      .replace(/\/env-[a-z0-9-]+/gi, "/:env")
      .replace(/[a-f0-9]{16,}/gi, ":hex")
      .replace(/-[a-zA-Z0-9_-]{8}\.(js|css|woff2?|png|svg)$/, "-:hash.$1")
      // RPC vendor prefix neutralized: the freeze cares about WHICH services/methods the shell
      // calls; prefix-token correctness is the adapter/fallthrough gates' job, and recording the
      // raw token would put a brand string into an authored file (source-neutrality gate).
      .replace(/\/api\/[a-z]+\.v1\./, "/api/:svc.v1.");
    const keys = [...url.searchParams.keys()].sort().join(",");
    return p + (keys ? "?" + keys : "");
  } catch { return String(u); }
}

async function captureRoute(page, route) {
  // Hash routes are same-document views. Land on the base path FIRST (unrecorded) so the
  // recorded capture is always the hash hop itself — identical whether this is the initial
  // sequential crawl or a fresh-browser retry (a direct goto to a hash URL is a full document
  // load and would record the entire asset graph instead of the view change).
  if (route.includes("#")) {
    await page.goto(BASE + route.split("#")[0], { waitUntil: "domcontentloaded", timeout: 45000 });
    await page.waitForLoadState("networkidle", { timeout: 15000 }).catch(() => {});
  }
  const consoleMsgs = [];
  const netReqs = new Set();
  const onConsole = (m) => {
    if (m.type() !== "error" && m.type() !== "warning") return;
    const t = m.text();
    if (CONSOLE_ALLOW.some((re) => re.test(t))) return;
    consoleMsgs.push(t.slice(0, 160));
  };
  const onReq = (r) => {
    const u = r.url();
    const stored = r.method() + " " + normalizeUrl(u);
    // Patterns match either the raw URL (external hosts) or the stored normalized form
    // (method-prefixed paths like `GET /static/...`).
    if (NET_SKIP.some((re) => re.test(u) || re.test(stored))) return;
    netReqs.add(stored);
  };
  page.on("console", onConsole);
  page.on("request", onReq);

  const animations = new Set();
  await page.goto(BASE + route, { waitUntil: "domcontentloaded", timeout: 45000 });
  // Sample transient animations through load — this is where loading spinners live.
  const t0 = Date.now();
  while (Date.now() - t0 < 6000) {
    const running = await page.evaluate(() =>
      document.getAnimations({ subtree: true }).map((a) => {
        const kf = a.effect && a.effect.getKeyframes ? a.effect.getKeyframes() : [];
        const name = (a.animationName) || (a.effect && a.effect.target && a.effect.target.getAttribute && (a.effect.target.getAttribute("data-testid") || "")) || "";
        const target = a.effect && a.effect.target ? (a.effect.target.tagName || "") + "." + String(a.effect.target.className && a.effect.target.className.baseVal !== undefined ? a.effect.target.className.baseVal : a.effect.target.className || "").split(" ").filter(Boolean).slice(0, 2).join(".") : "";
        const timing = a.effect && a.effect.getTiming ? a.effect.getTiming() : {};
        return `${a.constructor.name}:${name}:${target}:${timing.duration || 0}:${timing.iterations === Infinity ? "inf" : timing.iterations || 1}:${kf.length}kf`;
      }),
    ).catch(() => []);
    for (const a of running) if (!ANIM_SKIP.some((re) => re.test(a))) animations.add(a);
    await page.waitForTimeout(100);
  }
  await page.waitForLoadState("networkidle", { timeout: 15000 }).catch(() => {});
  await page.waitForTimeout(1200);

  const dom = await page.evaluate((volatileSelectors) => {
    const isVolatile = (el) => volatileSelectors.some((s) => { try { return el.matches(s); } catch { return false; } });
    // Non-rendered elements are not UI surface — their equivalence is the WIRE gate's job (and
    // the owned tree legitimately loads the same scripts from a different document position).
    const NON_UI = new Set(["SCRIPT", "STYLE", "LINK", "META", "NOSCRIPT", "TEMPLATE"]);
    // Augmentation-injected chrome is EXCLUDED from the shell fingerprint entirely (not just
    // volatile-pruned): its mount races React re-renders by design (observer remount within a
    // tick), and its presence/behavior is asserted functionally by its own done-bars.
    const isInjected = (el) => { const id = el.id || ""; return id === "ioi-ns-advanced-wrap" || id === "ioi-ns-modal" || id === "ioi-apps-modal" || id === "ioi-open-app" || id === "ioi-openapp-rail"; };
    const fp = (el) => {
      const tid = el.getAttribute && el.getAttribute("data-testid");
      const cls = String(el.className && el.className.baseVal !== undefined ? el.className.baseVal : el.className || "").split(/\s+/).filter(Boolean).sort();
      const node = { t: el.tagName.toLowerCase() };
      if (tid) node.id = tid;
      if (cls.length) node.c = cls;
      if (isVolatile(el)) { node.volatile = true; node.hasChildren = el.children.length > 0; return node; }
      const kids = [...el.children].filter((c) => !NON_UI.has(c.tagName) && !isInjected(c)).map(fp);
      if (kids.length) node.k = kids;
      return node;
    };
    return fp(document.body);
  }, VOLATILE);

  page.off("console", onConsole);
  page.off("request", onReq);
  return {
    dom,
    animations: [...animations].sort(),
    network: [...netReqs].sort(),
    console: consoleMsgs.sort(),
  };
}

const b = await chromium.launch();
const page = await b.newPage({ viewport: { width: 1918, height: 936 }, colorScheme: "dark" });
const baseline = { base_note: "captured against the estate serve; volatile subtrees pruned; external-host traffic excluded", routes: {} };
for (const route of ROUTES) {
  baseline.routes[route] = await captureRoute(page, route);
  if (!CHECK && baseIdx === -1) {
    mkdirSync(SHOTS, { recursive: true });
    await page.screenshot({ path: join(SHOTS, route.replace(/[/#]/g, "_") + ".png") }).catch(() => {});
  }
}
await b.close();

const next = JSON.stringify(baseline, null, 1) + "\n";
const baselinePath = join(OUT, "behavior-baseline.json");
if (CHECK || baseIdx > -1) {
  if (!existsSync(baselinePath)) { console.error("no committed behavior baseline"); process.exit(1); }
  const prev = JSON.parse(readFileSync(baselinePath, "utf8"));
  const cur = JSON.parse(next);
  const routeDrift = (route) => {
    const a = prev.routes[route] || {}, c = cur.routes[route] || {};
    return ["dom", "animations", "network", "console"].filter((key) => JSON.stringify(a[key]) !== JSON.stringify(c[key]));
  };
  // Animation sampling is timing-sensitive under load: a drifted route gets recaptured (fresh
  // browser) up to twice before it counts — a REAL regression (lost spinner, changed DOM) fails
  // every retry; a sampler miss under load does not.
  for (let attempt = 0; attempt < 2; attempt++) {
    const drifted = ROUTES.filter((r) => routeDrift(r).length);
    if (!drifted.length) break;
    const b2 = await chromium.launch();
    const p2 = await b2.newPage({ viewport: { width: 1918, height: 936 }, colorScheme: "dark" });
    for (const r of drifted) cur.routes[r] = await captureRoute(p2, r);
    await b2.close();
  }
  let drift = 0;
  for (const route of ROUTES) {
    const a = prev.routes[route] || {}, c = cur.routes[route] || {};
    for (const key of routeDrift(route)) {
      drift++;
      console.error(`DRIFT ${route} :: ${key}`);
      if (key !== "dom") {
        const setA = new Set(a[key] || []), setC = new Set(c[key] || []);
        for (const x of [...setC].filter((v) => !setA.has(v))) console.error(`  + ${x}`);
        for (const x of [...setA].filter((v) => !setC.has(v))) console.error(`  - ${x}`);
      } else {
        console.error(`  (dom fingerprint diverged — sizes ${JSON.stringify(a[key]).length} → ${JSON.stringify(c[key]).length})`);
      }
    }
  }
  if (drift) { console.error(`shell behavior freeze: DRIFT (${drift} sections)`); process.exit(1); }
  console.log(`shell behavior freeze: intact (${ROUTES.length} routes)`);
} else {
  mkdirSync(OUT, { recursive: true });
  writeFileSync(baselinePath, next);
  const totals = ROUTES.map((r) => `${r}: ${baseline.routes[r].animations.length} anims · ${baseline.routes[r].network.length} reqs`).join("  |  ");
  console.log(`froze ${ROUTES.length} routes — ${totals}`);
}
