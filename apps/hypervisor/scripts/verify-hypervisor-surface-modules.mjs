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
import * as ontologyManager from "../surfaces/ontology-manager/index.mjs";
import * as objectExplorer from "../surfaces/object-explorer/index.mjs";
import { escHtml, parseSelection, selectionQuery, inspectorShell, trayShell, disabledCommand, proofLink, semanticMask } from "../surfaces/kit.mjs";
import { ONTOLOGY_CONTEXT_KEYS, parseOntologyContext, ontologyContextQuery, managerLink, explorerLink, objectTypeLink, objectSetLink, managerResourceLink, sourcesLink, provenanceReceiptLink, semanticBreadcrumb, semanticInspectorShell, disabledSemanticAction, formatRef } from "../surfaces/ontology-context.mjs";

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
  ok("command table honors the discipline contract: enabled ⇒ route+proof, disabled ⇒ named reason", pipeline.commands.length === 4 && pipeline.commands.every((a) => a.key && a.label && (a.enabled ? (typeof a.route === "string" && typeof a.proof === "string") : (typeof a.reason === "string" && a.reason.length > 20))));
  ok("Preview + Build are the enabled navigations (#67: Build = the governed workflow entry); Schedule/Deploy stay disabled named gaps", pipeline.commands.filter((a) => a.enabled).map((a) => a.key).join(",") === "preview,build" && !!pipeline.commands.find((a) => a.key === "build").authority && pipeline.commands.filter((a) => !a.enabled).map((a) => a.key).join(",") === "schedule,deploy");
  ok("the governed Build workflow declares its runtime mutation descriptors (#67: 8 stages, each authority+receipt bound, grants field-bounded)", pipeline.actions.length === 8 && pipeline.actions.every((a) => a.id && a.method === "POST" && a.route && a.authority && a.authority.plane && a.receipt && Array.isArray(a.fields)) && pipeline.actions.filter((a) => (a.fields || []).includes("wallet_approval_grant")).every((a) => a.fieldMax >= 4096) && typeof pipeline.handleAction === "function");

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
  // 5. ONTOLOGY MODULES (the #59 extraction) — same contract, same hygiene, both certified ports.
  const ONTOLOGY_MODULES = [
    { mod: ontologyManager, slug: "schema", route: "/__ioi/ontology/manager", title: "<title>Ontology Manager</title>", marks: ["Discover", "Object types", "og-grail"] },
    { mod: objectExplorer, slug: "explorer", route: "/__ioi/ontology/explorer", title: "<title>Object Explorer</title>", marks: ["Object type", "og-grail"] },
  ];
  for (const { mod, slug, route, title, marks } of ONTOLOGY_MODULES) {
    ok(`${slug}: module exports the surface contract`, typeof mod.load === "function" && typeof mod.render === "function" && Array.isArray(mod.actions) && mod.meta && mod.meta.slug === slug);
    const reg2 = surfaceBySlug(slug);
    ok(`${slug}: module meta agrees with the registry entry`, !!reg2 && mod.meta.route === reg2.route && mod.meta.verifier === reg2.verifier && mod.meta.certification === reg2.certification);
    const seed2 = (matrix.seeds || []).find((s) => s.slug === slug);
    ok(`${slug}: module meta agrees with the parity-matrix seed`, !!seed2 && seed2.candidate_surface.split("?")[0] === mod.meta.route && seed2.shell_pixel_certification_artifact === mod.meta.certification && seed2.shell_pixel_certified === true);
    const hit2 = boundSurface(route, "GET");
    ok(`${slug}: registry binds the module (identity, not a copy)`, !!hit2 && hit2.impl.render === mod.render && hit2.impl.load === mod.load);
    const ctx2 = { url: new URL(`http://x${route}`), daemon: "http://127.0.0.1:1" };
    const model2 = await mod.load(ctx2);
    const html2 = mod.render(model2, ctx2);
    ok(`${slug}: offline dead-daemon render keeps the certified shell landmarks`, [title, ...marks].every((m) => html2.includes(m)));
  }
  ok("serve no longer defines the ontology port renderers", !serveSrc.includes("function renderOntologyManagerPort") && !serveSrc.includes("function renderObjectExplorerPort"));
  ok("the odk substrate's own manager renderer STAYS in serve (not the certified port)", serveSrc.includes("function renderOntologyManager("));

  // 6. ONTOLOGY CONTEXT KIT — the semantic-layer primitives (unwired; PR60-62 wire them).
  const cu = new URL("http://x/r?ontology=ont-1&objectType=loan&objectSet=&pane=types&noise=z");
  const octx = parseOntologyContext(cu);
  ok("parseOntologyContext reads only known, non-empty keys", octx.ontology === "ont-1" && octx.objectType === "loan" && octx.pane === "types" && !("objectSet" in octx) && !("noise" in octx) && ONTOLOGY_CONTEXT_KEYS.length === 14 && ["definitionKind", "definitionId", "dataSource", "connectorMapping", "policyView", "ontologyProjection", "materializingRun", "receipt"].every((k) => ONTOLOGY_CONTEXT_KEYS.includes(k)));
  // #64 cross-plane keys: roundtrip-stable, unknown keys dropped, oversized values dropped.
  const xctx = parseOntologyContext(new URL("http://x/r?dataSource=ds_1&connectorMapping=cm_1&receipt=agentgres%3A%2F%2Fx%2Fr1&rogue=z"));
  ok("cross-plane context roundtrips (known keys only, canonical order)", xctx.dataSource === "ds_1" && xctx.connectorMapping === "cm_1" && xctx.receipt === "agentgres://x/r1" && !("rogue" in xctx) && ontologyContextQuery("/r", xctx) === "/r?connectorMapping=cm_1&dataSource=ds_1&receipt=agentgres%3A%2F%2Fx%2Fr1");
  ok("oversized context values are DROPPED (never truncated into a different identity)", !("ontology" in parseOntologyContext(new URL(`http://x/r?ontology=${"a".repeat(300)}`))));
  ok("link builders fail closed on missing owning ids", managerResourceLink("", "connector-mapping", "x") === null && managerResourceLink("o", "bogus-kind", "x") === null && sourcesLink("") === null && provenanceReceiptLink("") === null);
  const rt = ontologyContextQuery("/r", octx);
  ok("ontologyContextQuery is canonical (sorted keys, empties dropped) and roundtrips", rt === "/r?objectType=loan&ontology=ont-1&pane=types" && JSON.stringify(parseOntologyContext(new URL(`http://x${rt}`))) === JSON.stringify(octx));
  ok("ontologyContextQuery ignores unknown keys", ontologyContextQuery("/r", { ontology: "a", rogue: "x" }) === "/r?ontology=a");
  ok("surface link helpers target the owning routes", managerLink({ ontology: "a" }) === "/__ioi/ontology/manager?ontology=a" && explorerLink({ ontology: "a" }) === "/__ioi/ontology/explorer?ontology=a" && objectTypeLink("a", "loan") === "/__ioi/ontology/explorer?objectType=loan&ontology=a" && objectSetLink("a", "set-1") === "/__ioi/ontology/explorer?objectSet=set-1&ontology=a");
  const crumb = semanticBreadcrumb([{ label: "ont<1", href: "/__ioi/ontology/manager?ontology=a" }, { label: "Loan" }]);
  ok("semanticBreadcrumb links owned segments, escapes labels, carries the testid", crumb.includes('data-testid="ioi-sem-breadcrumb"') && crumb.includes("ont&lt;1") && crumb.includes('href="/__ioi/ontology/manager?ontology=a"') && crumb.includes('<span class="ioi-sem-crumb">Loan</span>') && crumb.includes(" → "));
  ok("semanticInspectorShell is the kit inspector with the semantic marker", semanticInspectorShell({ id: "x", title: "T", body: "b" }).includes("ioi-sem-inspector") && semanticInspectorShell({ id: "x", title: "T", body: "b" }).includes('data-testid="ioi-inspector"'));
  ok("disabledSemanticAction names its reason", disabledSemanticAction({ label: "Edit type", reason: "no ODK patch authority wired on this surface yet" }).includes("data-ioi-disabled-reason=") && disabledSemanticAction({ label: "E", reason: "r" }).includes("ioi-sem-action"));
  ok("formatRef escapes and marks refs", formatRef('ref<"&>') === '<code class="ioi-ref">ref&lt;&quot;&amp;&gt;</code>' && formatRef(null) === '<code class="ioi-ref"></code>');

  // 7. Interaction kit units.
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
