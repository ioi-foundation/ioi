#!/usr/bin/env node
// Editor-target open-posture done-bar verifier.
//
// Asserts the editor-target registry carries PROBED open posture per target (host truth, never
// fabricated): the owned Native Workbench as a first-class in-shell target, the daemon-hosted
// browser IDE openable only when the pinned runtime really exists on disk, external electron
// hosts as adapter targets probed by launch binary — each with its lease/revocation contract
// named. Then asserts the consumers stay honest: the SPA editor list offers ONLY openable
// targets (no dropdown lies), and the owned Workbench surface renders the full registry with
// disabled-with-reason rows and per-environment open affordances gated on posture.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-editor-target-posture.mjs

import fs from "node:fs";

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SHELL = (process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

async function run() {
  // 1. Registry posture.
  const r = await fetch(`${DAEMON}/v1/hypervisor/editor-targets`).then((x) => x.json());
  const targets = r.targets || [];
  const byId = (id) => targets.find((t) => t.target_id === id);
  ok("registry schema + openable projection", r.schema_version === "ioi.hypervisor.editor-targets.v1" && Array.isArray(r.openable_targets), `${targets.length} targets`);

  const native = byId("workbench-native");
  ok("native workbench is a first-class registry target", !!native && native.status === "active");
  ok("native workbench posture: in-shell, openable, routed", native?.open_posture?.open_kind === "in_shell_surface" && native?.open_posture?.openable === true && native?.open_posture?.open_route === "/__ioi/workbench");
  ok("native workbench names its lease posture", /daemon/.test(native?.open_posture?.lease_posture || ""));

  const vb = byId("vscode-browser");
  ok("browser IDE posture kind + probe evidence", vb?.open_posture?.open_kind === "daemon_hosted_browser_ide" && typeof vb?.open_posture?.probe?.evidence?.pinned_runtime_present === "boolean");
  ok("browser IDE names the capability-lease contract", /capability_lease_ref/.test(vb?.open_posture?.lease_posture || ""));
  // Openable must equal REAL runtime presence on disk (host truth, no fabrication).
  const binPath = vb?.open_posture?.probe?.evidence?.runtime_bin || "";
  const reallyPresent = binPath ? fs.existsSync(binPath) : false;
  ok("browser IDE openable == pinned runtime really on disk", vb?.open_posture?.openable === reallyPresent, `${vb?.open_posture?.openable} vs disk ${reallyPresent}`);

  const externals = targets.filter((t) => t.open_posture?.open_kind === "external_host_adapter");
  ok("external hosts probed by launch binary with honest evidence", externals.length >= 1 && externals.every((t) => t.open_posture.probe?.evidence?.required_binary !== undefined), externals.map((t) => `${t.target_id}:${t.open_posture.openable}`).join(" "));
  ok("external hosts claim no runtime truth (launch-plan admission named)", externals.every((t) => /launch-plan admission/.test(t.open_posture.lease_posture || "")));
  ok("openable_targets consistent with per-target posture", (r.openable_targets || []).every((id) => byId(id)?.open_posture?.openable === true) && targets.filter((t) => t.open_posture?.openable === true).every((t) => r.openable_targets.includes(t.target_id)));

  // 2. SPA editor list offers ONLY openable targets (no dropdown lies).
  const le = await fetch(`${SHELL}/api/ioi.v1.EditorService/ListEditors`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }).then((x) => x.json()).catch(() => ({}));
  const editors = le.editors || [];
  const openableSet = new Set(r.openable_targets || []);
  ok("SPA editor list ⊆ openable targets", editors.length >= 1 && editors.every((e) => openableSet.has(e.id)), editors.map((e) => e.id).join(","));
  ok("SPA list excludes the native surface (the console IS it)", editors.every((e) => e.id !== "workbench-native"));
  ok("browser IDE offered iff openable", editors.some((e) => e.id === "vscode-browser") === (vb?.open_posture?.openable === true));

  // 3. Owned Workbench surface renders the registry honestly.
  const html = await fetch(`${SHELL}/__ioi/workbench`).then((x) => x.text());
  ok("workbench renders the editor-target registry panel", /id="editor-targets"/.test(html) && /Native Workbench \(in-shell\)/.test(html));
  ok("workbench names open kind + lease posture per target", /in-shell surface/.test(html) && /daemon-hosted browser IDE/.test(html) && /external host adapter/.test(html) && /capability_lease_ref/.test(html));
  const externalNotOpenable = externals.find((t) => t.open_posture.openable !== true);
  if (externalNotOpenable) {
    ok("unavailable target rendered disabled WITH reason (not hidden)", /not openable — /.test(html));
  } else {
    ok("unavailable-target rendering lane skipped honestly (all externals openable on this host)", true);
  }
  if (vb?.open_posture?.openable) {
    ok("per-environment browser-IDE open affordance present when openable", /\/__ioi\/editor\/open\?environmentId=/.test(html));
  } else {
    ok("per-environment browser-IDE affordance honestly absent (runtime missing)", /VS Code Browser unavailable/.test(html) || !/\/__ioi\/editor\/open\?environmentId=/.test(html));
  }

  // 4. The open lane stays fail-closed on bad input.
  const bad = await fetch(`${SHELL}/__ioi/editor/open`, { redirect: "manual" });
  ok("open lane fail-closed without an environment", bad.status === 400);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`editor-target posture readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
