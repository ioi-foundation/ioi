#!/usr/bin/env node
// Capture the reference's branded, rendered route DOM for verbatim rendering.
//
// The reference (:9228) serves a harvested production snapshot. Its #root is server-
// rendered, but the Ona -> IOI branding is applied at RUNTIME by a client boot-guard
// script that rewrites the logo DOM. So we drive a real browser (Playwright), let the
// boot guard run, then grab #root's *rendered* innerHTML (branding baked in). We strip
// the dead <script> bundles and vendor the result so a route can render it verbatim
// (dangerouslySetInnerHTML) under the CSS we already vendored; behavior is attached by
// delegation.
//
// Usage: node apps/hypervisor/scripts/capture-reference-html.mjs [route ...]
//   default base: http://localhost:9228   (override with REF_BASE)
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const BASE = process.env.REF_BASE || "http://localhost:9228";
const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = join(HERE, "..", "src", "reference", "html");

// route path -> output slug. Dynamic routes capture one representative instance; the
// renderer maps the live :id paths onto these captures.
const ROUTES = {
  "/": "home",
  "/projects": "projects",
  "/projects/019ee100-f64f-7554-946f-405f46528c91": "project-detail",
  "/automations": "automations",
  "/automations/new": "automation-new",
  "/details/019ee1b5-0cdd-72af-81e4-327345446648": "workspace",
  "/insights": "insights",
  "/settings": "settings",
  "/settings/agent-policies": "settings-agent-policies",
  "/settings/billing": "settings-billing",
  "/settings/credit-usage": "settings-credit-usage",
  "/settings/environments": "settings-environments",
  "/settings/manage-organization": "settings-manage-organization",
  "/settings/members": "settings-members",
  "/settings/organization-secrets": "settings-organization-secrets",
  "/settings/org-integrations": "settings-org-integrations",
  "/settings/policies": "settings-policies",
  "/settings/runners": "settings-runners",
  "/settings/scim": "settings-scim",
};

function stripScripts(html) {
  return html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/<script\b[^>]*\/>/gi, "")
    // strip event handlers that would reference the dead bundle's globals
    .replace(/\son[a-z]+="[^"]*"/gi, "");
}

async function capture(page, route, slug) {
  // networkidle never settles (the dead bundle retries chunk loads), so wait for the
  // document + give the boot-guard branding script a beat to rewrite the logo DOM.
  await page.goto(BASE + route, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1500);
  const inner = await page.evaluate(() => {
    const root = document.getElementById("root");
    if (!root) throw new Error("no #root");
    return root.innerHTML;
  });
  const html = stripScripts(inner);
  mkdirSync(OUT_DIR, { recursive: true });
  const out = join(OUT_DIR, `${slug}.html`);
  writeFileSync(out, html, "utf8");
  return { slug, bytes: html.length, out };
}

const wanted = process.argv.slice(2);
const entries = Object.entries(ROUTES).filter(([r, s]) => !wanted.length || wanted.includes(r) || wanted.includes(s));
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
for (const [route, slug] of entries) {
  try {
    const r = await capture(page, route, slug);
    console.log(`OK  ${route.padEnd(14)} -> ${slug}.html (${(r.bytes / 1024).toFixed(1)} KB)`);
  } catch (e) {
    console.log(`ERR ${route.padEnd(14)} ${e.message}`);
    process.exitCode = 1;
  }
}
await browser.close();
