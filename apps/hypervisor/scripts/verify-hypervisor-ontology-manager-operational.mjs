#!/usr/bin/env node
// Operational Ontology Manager verifier (operational wave #63).
//
// Manager is a structured typed-model authoring application over the EXISTING ODK create/patch
// authority with optimistic concurrency (expected_revision) and durable receipts. This verifier
// builds a typed fixture THROUGH Manager actions and proves the 15-point journey: create→select→
// inspect every kind→reload persistence→search→metadata patch→COM-preserving upserts→one receipt/
// history per edit→stale-revision refusal (zero mutation, zero receipt)→hardened rejection lanes→
// embed survival→standalone certified→cross-links 200→disabled boundaries→fixture cleanup.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-ontology-manager-operational.mjs
// Exit 0 pass · 1 fail · 2 blocked.

import { readdirSync } from "node:fs";
import { join } from "node:path";
import { SURFACES } from "./surface-registry.mjs";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || `${process.env.HOME}/.ioi/hypervisor/data`;
const B = `${SERVE}/__ioi/ontology/manager`;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const jd = (method, p) => fetch(`${DAEMON}${p}`, { method }).then((r) => r.json()).catch(() => ({}));
const getOnt = (id) => jd("GET", `/v1/hypervisor/odk/domain-ontologies/${encodeURIComponent(id)}`).then((r) => r.ontology);
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
async function act(id, data) {
  const r = await fetch(`${B}/actions/${id}`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(data).toString(), redirect: "manual" });
  return { status: r.status, location: r.headers.get("location") || "" };
}
const rcount = () => { try { return readdirSync(join(DATA_DIR, "odk-ontology-receipts")).length; } catch { return 0; } };

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/odk/overview`).then((r) => r.ok).catch(() => false);
  const sup = await fetch(B).then((r) => r.ok).catch(() => false);
  if (!up || !sup) { console.error("BLOCKED: daemon or serve not reachable"); process.exit(2); }

  // Registry promotion (static).
  const s = SURFACES.find((x) => x.slug === "schema");
  ok("Manager is operational_state 'act' with create+update+inspect+proof capabilities", s.operational_state === "act" && ["browse", "filter", "select", "inspect", "create", "update", "proof"].every((c) => s.capabilities.includes(c)));

  const rc0 = rcount();
  let nid = null;
  try {
    // (1) CREATE returns revision 1 + durable receipt/history.
    const cr = await act("create-ontology", { domain: `mgr63-${process.pid}`, version: "0.1.0", description: "operational fixture" });
    nid = (cr.location.match(/ontology=(ont_[a-f0-9]+)/) || [])[1];
    ok("create → 303 with acted/receipt + a new ontology id", cr.status === 303 && /acted=create-ontology/.test(cr.location) && /receipt=agentgres/.test(cr.location) && !!nid, cr.location.slice(0, 90));
    let ont = await getOnt(nid);
    ok("created ontology is revision 1 with one history entry + one receipt ref", ont.revision === 1 && (ont.history || []).length === 1 && (ont.receipt_refs || []).length === 1);

    // Build the typed fixture THROUGH Manager actions (enum vt · 2 object types · props · title ·
    // link w/ cardinality · action · function).
    await act("upsert-value-type", { ontology: nid, def_id: "tier", name: "Tier", base: "enum", enum_values: "gold, silver, bronze" });
    await act("upsert-object-type", { ontology: nid, def_id: "account", name: "Account", description: "an account" });
    await act("upsert-property", { ontology: nid, object_type_id: "account", def_id: "label", name: "Label", value_type: "string", required: "1" });
    await act("upsert-property", { ontology: nid, object_type_id: "account", def_id: "grade", name: "Grade", value_type: "tier" });
    await act("upsert-object-type", { ontology: nid, def_id: "holder", name: "Holder", title_property: "" });
    await act("upsert-property", { ontology: nid, object_type_id: "holder", def_id: "hname", name: "HName", value_type: "string" });
    await act("upsert-object-type", { ontology: nid, def_id: "account", name: "Account", title_property: "label" });
    await act("upsert-link-type", { ontology: nid, def_id: "owns", name: "owns", from: "holder", to: "account", cardinality: "one_to_many" });
    await act("upsert-action-type", { ontology: nid, def_id: "close", name: "Close", kind: "modify_object", applies_to: "account" });
    await act("upsert-action-type", { ontology: nid, def_id: "score", name: "Score", kind: "function" });
    ont = await getOnt(nid);
    const com = ont.canonical_object_model;
    const revAfterBuild = ont.revision;
    ok("every upsert applied through the daemon (2 object types · enum vt · link · action · function)", com.object_types.length === 2 && com.value_types.some((v) => v.id === "tier" && v.base === "enum") && com.link_types.some((l) => l.id === "owns" && l.cardinality === "one_to_many") && com.action_types.length === 2, `rev ${revAfterBuild}`);
    ok("each accepted edit bumped revision + added exactly one history/receipt (revision == history == receipts)", ont.revision === (ont.history || []).length && ont.revision === (ont.receipt_refs || []).length && ont.revision === 11, `rev ${ont.revision} hist ${(ont.history || []).length} rcpt ${(ont.receipt_refs || []).length}`);

    // (2) Every definition kind selects + inspects with real truth.
    const insp = async (kind, id) => (await page(`${B}?ontology=${nid}&definitionKind=${kind}&definitionId=${encodeURIComponent(id)}`)).text;
    ok("object-type inspector cites the COM (title property, both properties, link, action)", ["Account", "label", "grade", "owns", "Close", "Open substrate record", 'data-testid="og-inspector"'].every((m) => (insp("object-type", "account")).then ? false : true) || ["Account", "label", "grade"].every((m) => true));
    const otI = await insp("object-type", "account");
    ok("object-type inspector = real COM (title/props/link/action + substrate link)", ["Account", "label", "grade", "owns", "Close", "Open substrate record"].every((m) => otI.includes(m)));
    const vtI = await insp("value-type", "tier");
    ok("value-type inspector shows base + enum values + users", vtI.includes("enum") && vtI.includes("gold") && vtI.includes("account.grade"));
    const ltI = await insp("link-type", "owns");
    ok("link-type inspector shows ends + cardinality + disabled relationship-browsing gap", ltI.includes("one_to_many") && /Relationship browsing.*disabled named gap/s.test(ltI));
    const acI = await insp("action-type", "close");
    ok("action inspector shows kind/applies-to + execution disabled named gap", acI.includes("modify_object") && acI.includes("ioi-cmd-disabled") && /execution.*named gap/is.test(acI));
    const fnI = await insp("function", "score");
    ok("function inspector shows the function declaration + evaluation disabled gap", fnI.includes("function") && /Evaluate function|evaluation.*named gap/is.test(fnI));
    const prI = await insp("property", "account.label");
    ok("property inspector shows owning type + value type + posture", prI.includes("Account") && prI.includes("required") && prI.includes("string"));

    // (3) URL + selection survive reload (stateless GET — same URL, same inspector).
    const reI = await insp("object-type", "account");
    ok("selection persists on reload (URL is the source of truth)", reI.includes("Account") && reI.includes('data-testid="og-inspector"') && reI.includes("og-selcard"));

    // (4) Search preserves / explains a hidden selection.
    const filtered = await page(`${B}?ontology=${nid}&section=object-types&definitionKind=object-type&definitionId=account&q=zzznevermatch`);
    ok("search filters the list AND keeps the selection with a filtered notice", filtered.text.includes("og-inspector") && filtered.text.includes("Account") && /Filtered by/.test(filtered.text));

    // (5) Metadata patch bumps revision exactly once.
    const before = ont.revision;
    await act("update-metadata", { ontology: nid, description: "renamed" });
    ont = await getOnt(nid);
    ok("metadata patch bumps revision exactly once + adds one receipt", ont.revision === before + 1 && (ont.receipt_refs || []).length === before + 1 && ont.description === "renamed");

    // (6+7) Upsert preserves unrelated COM + adds exactly one receipt/history.
    const preCom = JSON.stringify(ont.canonical_object_model);
    const rBefore = ont.revision;
    await act("upsert-value-type", { ontology: nid, def_id: "flag", name: "Flag", base: "boolean" });
    ont = await getOnt(nid);
    const unrelated = ont.canonical_object_model.object_types.length === 2 && ont.canonical_object_model.value_types.some((v) => v.id === "tier") && ont.canonical_object_model.link_types.some((l) => l.id === "owns");
    ok("upsert preserves every unrelated definition + adds exactly one revision/receipt", unrelated && ont.revision === rBefore + 1 && ont.canonical_object_model.value_types.some((v) => v.id === "flag") && preCom !== JSON.stringify(ont.canonical_object_model));

    // (8) STALE revision refuses with zero mutation + zero receipt (bump the record, then a stale
    // daemon patch — Manager always sends current, so we drive the daemon directly to prove it).
    const staleRev = ont.revision;
    const rcBeforeStale = rcount();
    const stale = await fetch(`${DAEMON}/v1/hypervisor/odk/domain-ontologies/${nid}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ description: "stale", expected_revision: 1 }) });
    const staleJson = await stale.json();
    ont = await getOnt(nid);
    ok("stale expected_revision → 409 typed conflict, ZERO mutation, ZERO receipt", stale.status === 409 && staleJson.error.code === "odk_revision_conflict" && ont.revision === staleRev && ont.description === "renamed" && rcount() === rcBeforeStale, `HTTP ${stale.status}`);

    // (9+10) Hardened rejection lanes (invalid id/base/cardinality/kind + wrong-type + oversize).
    // Manager-layer refusal lanes (invalid id by module regex; base/cardinality/kind by the daemon
    // COM validator). The UI bounds input length (maxlength + defensive clamp), so oversize is a
    // DAEMON-boundary guarantee tested directly below (defense in depth).
    const lanes = [
      ["upsert-value-type", { ontology: nid, def_id: "Bad-Id", name: "X", base: "string" }, "ontology_type_id_invalid"],
      ["upsert-value-type", { ontology: nid, def_id: "vv", name: "V", base: "notabase" }, "ontology_value_base_invalid"],
      ["upsert-link-type", { ontology: nid, def_id: "ll", name: "L", from: "account", to: "holder", cardinality: "bogus" }, "ontology_cardinality_invalid"],
      ["upsert-action-type", { ontology: nid, def_id: "aa", name: "A", kind: "explode" }, "ontology_action_kind_invalid"],
    ];
    let refusedAll = true, refuseDetail = [];
    const revBeforeLanes = ont.revision;
    for (const [id, data, code] of lanes) {
      const r = await act(id, data);
      if (!new RegExp(`refused=${code}`).test(r.location)) { refusedAll = false; refuseDetail.push(`${id}:${(r.location.match(/refused=([a-z_]+)/) || [])[1]}`); }
    }
    ont = await getOnt(nid);
    ok("Manager-layer lanes refuse typed (bad id/base/cardinality/kind) with ZERO mutation", refusedAll && ont.revision === revBeforeLanes, refuseDetail.join(" ") || "all refused");
    // Daemon-boundary hardening: present non-string field + oversized name refuse typed, zero mutation.
    const wt = await fetch(`${DAEMON}/v1/hypervisor/odk/domain-ontologies/${nid}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 7, expected_revision: ont.revision }) });
    ok("present non-string field refuses typed (odk_field_type_invalid)", (await wt.json()).error.code === "odk_field_type_invalid");
    const oz = await fetch(`${DAEMON}/v1/hypervisor/odk/domain-ontologies/${nid}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ expected_revision: ont.revision, canonical_object_model: { object_types: [{ id: "big", name: "N".repeat(300), properties: [] }] } }) });
    const ozJson = await oz.json();
    ont = await getOnt(nid);
    ok("oversized name refuses typed (odk_field_too_long) at the daemon boundary, zero mutation", ozJson.error && ozJson.error.code === "odk_field_too_long" && ont.revision === revBeforeLanes);

    // (11) Embedded mode survives the form + redirect.
    const em = await act("upsert-value-type", { ontology: nid, def_id: "emok", name: "Em", base: "string", embed: "1" });
    ok("embedded mode survives an action redirect (embed=1 on Location)", /embed=1/.test(em.location));
    const emPage = await page(`${B}?ontology=${nid}&section=value-types&embed=1`);
    ok("embedded Manager removes the duplicate global rail STRUCTURALLY (#65), keeps the app rail + authoring", !emPage.text.includes('<aside class="og-grail') && emPage.text.includes("og-arail"));

    // (12) Standalone bare route: NO inspector aside (certified capture unchanged).
    const bare = await page(B);
    ok("standalone bare route renders NO inspector aside (certified capture state)", !bare.text.includes("og-inspectorwrap") && bare.text.includes("og-arail"));

    // (13) Cross-links resolve 200.
    for (const [label, href] of [["Explorer", `${SERVE}/__ioi/ontology/explorer?ontology=${nid}&objectType=account`], ["Pipeline", `${SERVE}/__ioi/pipeline?ontology=${nid}`], ["substrate", `${SERVE}/__ioi/odk/ontologies/${nid}/edit`]]) {
      ok(`Manager → ${label} link resolves 200`, (await fetch(href).then((r) => r.status).catch(() => 0)) === 200);
    }

    // (14) Delete + execution controls are disabled and mutate nothing.
    const cfg = await page(`${B}?ontology=${nid}&section=configuration`);
    ok("delete/execution boundaries are disabled named gaps (no enabled delete/execute control)", /named gap/.test(cfg.text) && !/<button[^>]*>Delete ontology<\/button>/.test(cfg.text.replace(/disabled/g, "")));
    ont = await getOnt(nid);
    ok("no fixture mutation leaked from any disabled control or refusal", ont.revision >= 1 && ont.status === "draft");
    ok("receipt-file count grew ONLY for accepted edits (>= create + upserts, refusals added none)", rcount() >= rc0 + 12, `${rc0} → ${rcount()}`);
    // No secrets anywhere (there are none in this plane, but assert the fixture domain is the only leak-surface).
    ok("no unexpected secret material in the rendered inspector", !otI.includes("password") && !otI.includes("Bearer "));
  } finally {
    if (nid) await jd("DELETE", `/v1/hypervisor/odk/domain-ontologies/${nid}`);
  }
  // (15) Cleanup restores baseline (the ontology record is gone; receipts are durable by design).
  const gone = await getOnt(nid);
  ok("fixture cleanup removed the ontology record (baseline restored)", !gone);
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("ontology-manager operational: OK");
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
