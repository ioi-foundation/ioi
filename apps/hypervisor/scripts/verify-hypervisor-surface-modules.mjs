#!/usr/bin/env node
// Surface-module verifier (functional-runtime wave — the Pipeline extraction + interaction kit).
//
// Proves the module shape PR #57 builds on:
//   1. CONTRACT — surfaces/pipeline/index.mjs exports { meta, load, render, actions }; meta agrees
//      with its surface-registry entry AND its parity-matrix seed (one identity, three records).
//   2. MOUNT — the registry binds the module itself (identity, not a copy), and the module renders
//      OFFLINE against a dead daemon: honest empty lists, the certified shell landmarks intact.
//   3. EXTRACTION HYGIENE — the serve monolith no longer carries the moved code (renderer, global
//      rail, escaper definition); the kit's escHtml is the single escaper definition.
//   4. KIT UNITS — the interaction helpers behave (escaping, stable selection URLs, shells carrying
//      the ids/testids the interaction verifiers will drive, disabled commands naming reasons).
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-surface-modules.mjs
// Exit 0 = all assertions pass; exit 1 = one or more failed.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { SURFACES, boundSurface, surfaceBySlug } from "./surface-registry.mjs";
import * as pipeline from "../surfaces/pipeline/index.mjs";
import { escHtml, parseSelection, selectionQuery, inspectorShell, trayShell, disabledCommand, proofLink, semanticMask } from "../surfaces/kit.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const APP = join(HERE, "..");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

async function run() {
  // 1. Contract + identity agreement.
  ok("pipeline module exports the surface contract", typeof pipeline.load === "function" && typeof pipeline.render === "function" && Array.isArray(pipeline.actions) && pipeline.meta && typeof pipeline.meta === "object");
  const reg = surfaceBySlug("pipeline");
  ok("module meta agrees with the registry entry", !!reg && pipeline.meta.slug === reg.slug && pipeline.meta.route === reg.route && pipeline.meta.verifier === reg.verifier && pipeline.meta.certification === reg.certification);
  const matrix = JSON.parse(readFileSync(join(APP, "harvest-app-parity-matrix.json"), "utf8"));
  const seed = (matrix.seeds || []).find((s) => s.slug === "pipeline");
  ok("module meta agrees with the parity-matrix seed", !!seed && seed.candidate_surface.split("?")[0] === pipeline.meta.route && seed.shell_pixel_certification_artifact === pipeline.meta.certification && seed.shell_pixel_certified === true);
  ok("command table honors the discipline contract: enabled ⇒ route+proof, disabled ⇒ named reason", pipeline.actions.length === 4 && pipeline.actions.every((a) => a.key && a.label && (a.enabled ? (typeof a.route === "string" && typeof a.proof === "string") : (typeof a.reason === "string" && a.reason.length > 20))));
  ok("Build/Schedule/Deploy stay disabled (no authority crossed); Preview is the one enabled read-navigation", pipeline.actions.filter((a) => a.enabled).map((a) => a.key).join(",") === "preview" && pipeline.actions.find((a) => a.key === "build").authority === null);

  // 2. Registry mounts the module itself; offline render keeps the certified shell landmarks.
  const hit = boundSurface("/__ioi/pipeline", "GET");
  ok("registry binds the module (identity, not a copy)", !!hit && hit.impl.render === pipeline.render && hit.impl.load === pipeline.load, hit ? "bound" : "no binding for /__ioi/pipeline");
  const ctx = { url: new URL("http://x/__ioi/pipeline"), daemon: "http://127.0.0.1:1" };
  const model = await pipeline.load(ctx);
  ok("dead daemon loads to honest empty lists", Object.values(model).every((v) => Array.isArray(v) && v.length === 0), `${Object.keys(model).length} list keys`);
  const html = pipeline.render(model, ctx);
  ok("offline render keeps the certified shell landmarks", ["<title>Pipeline Builder</title>", "Pipeline outputs", "pb-shell", "APPLICATIONS"].every((m) => html.includes(m)));
  const selCtx = { url: new URL("http://x/__ioi/pipeline?ontology=does-not-exist"), daemon: "http://127.0.0.1:1" };
  ok("selection param accepted without drift on empty truth", pipeline.render(model, selCtx) === html, "unknown ontology falls back identically");

  // 3. Extraction hygiene — the monolith no longer carries the moved code.
  const serveSrc = readFileSync(join(HERE, "serve-product-ui.mjs"), "utf8");
  ok("serve no longer defines renderPipelineBuilder", !serveSrc.includes("function renderPipelineBuilder"));
  ok("serve no longer defines the global rail", !serveSrc.includes("function ioiGlobalRailHtml") && !serveSrc.includes("const IOI_GRAIL_CSS"));
  ok("serve aliases the kit escaper (no duplicate definition)", serveSrc.includes("const CX_ESC = escHtml") && !serveSrc.includes('replace(/&/g, "&amp;").replace(/</g'));
  ok("registry lists pipeline exactly once", SURFACES.filter((s) => s.slug === "pipeline").length === 1);

  // 4. Interaction kit units.
  ok("escHtml escapes the four metacharacters", escHtml('&<>"') === "&amp;&lt;&gt;&quot;" && escHtml(null) === "" && escHtml(0) === "0");
  const u = new URL("http://x/r?node=mapping&ontology=ont-1&empty=&noise=z");
  const sel = parseSelection(u, ["node", "ontology", "empty", "absent"]);
  ok("parseSelection reads only present, non-empty keys", sel.node === "mapping" && sel.ontology === "ont-1" && !("empty" in sel) && !("absent" in sel) && !("noise" in sel));
  ok("selectionQuery is stable (sorted keys, empties dropped)", selectionQuery("/r", { ontology: "ont-1", node: "mapping", gone: "" }) === "/r?node=mapping&ontology=ont-1" && selectionQuery("/r", {}) === "/r");
  ok("selection roundtrip preserves state", JSON.stringify(parseSelection(new URL("http://x" + selectionQuery("/r", sel)), ["node", "ontology"])) === JSON.stringify(sel));
  ok("selectionQuery encodes values", selectionQuery("/r", { q: "a b&c" }) === "/r?q=a%20b%26c");
  const insp = inspectorShell({ id: "pb-insp", title: 'T<"', subtitle: "s", body: "<b>body</b>", cls: "x" });
  ok("inspectorShell carries id/testid and escapes chrome, not body", insp.includes('id="pb-insp"') && insp.includes('data-testid="ioi-inspector"') && insp.includes("T&lt;&quot;") && insp.includes("<b>body</b>"));
  const tray = trayShell({ id: "pb-tray", title: "Preview", body: "rows" });
  ok("trayShell carries id/testid", tray.includes('id="pb-tray"') && tray.includes('data-testid="ioi-tray"') && tray.includes("Preview"));
  const cmd = disabledCommand({ label: "Deploy", reason: 'needs release gate & lease "x"' });
  ok("disabledCommand is visibly disabled and names its reason", cmd.includes("disabled") && cmd.includes('aria-disabled="true"') && cmd.includes("data-ioi-disabled-reason=") && cmd.includes("&amp;") && cmd.includes("Deploy"));
  const pl = proofLink({ href: '/__ioi/run-timeline/r?a=1&b=2', label: "timeline", external: true });
  ok("proofLink escapes href and marks external", pl.includes('href="/__ioi/run-timeline/r?a=1&amp;b=2"') && pl.includes('rel="noopener"') && pl.includes('data-testid="ioi-proof-link"'));
  ok("semanticMask tags the region by id", semanticMask("rows", "<tr></tr>") === '<span data-ioi-sem-mask="rows"><tr></tr></span>');
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("surface-modules: OK");
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
