#!/usr/bin/env node
// P2 builder-story readiness verifier — three grafts exercised over REAL created objects:
//   H. Data-recipe handoff chain on the ODK recipe detail — every stage's posture from the
//      record's own fields; validation rendered as a NAMED GAP, never a green check.
//   I. Pipeline view on the automation detail (09-pipeline-builder grammar, read-only) —
//      trigger → declared steps → latest-run outcome, from the spec and run records.
//   J. Domain Blueprint candidates on Domain Apps — a projection over real ODK manifests with
//      the missing-object gap NAMED; bound-app-candidate math cross-checked.
// Creates ontology → recipe (with sources/mappings/views) → manifest → automation, verifies the
// rendered chains, and cleans everything up.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-p2-builder.mjs

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, path, body) {
  const r = await fetch(`${DAEMON}${path}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => null) };
}
const sGet = (p) => fetch(`${SERVE}${p}`).then(async (r) => ({ status: r.status, text: await r.text() }));

const made = { ont: null, recipe: null, manifest: null, auto: null, project: null };
async function cleanup() {
  if (made.auto) await fetch(`${SERVE}/__ioi/automations/${made.auto}/delete`, { method: "POST", redirect: "manual" }).catch(() => {});
  if (made.project) await jd("DELETE", `/v1/hypervisor/projects/${encodeURIComponent("project:" + made.project)}`); // full ref — bare ids soft-miss the projection
  if (made.manifest) await jd("DELETE", `/v1/hypervisor/odk/manifests/${made.manifest}`);
  if (made.recipe) await jd("DELETE", `/v1/hypervisor/odk/data-recipes/${made.recipe}`);
  if (made.ont) await jd("DELETE", `/v1/hypervisor/odk/domain-ontologies/${made.ont}`);
}

async function run() {
  // Substrate: ontology → recipe with an explicit partial chain → manifest bundling the recipe.
  const ont = await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "verify-p2-builder", canonical_object_model: { objects: ["Doc"], actions: [], states: ["draft"], roles: [], events: [] } });
  made.ont = ont.j?.ontology?.id || ont.j?.domain_ontology?.id;
  const ontRef = ont.j?.ontology?.ref || ont.j?.domain_ontology?.ref;
  ok("ontology created", ont.status === 201 && !!ontRef, ontRef);
  const rec = await jd("POST", "/v1/hypervisor/odk/data-recipes", {
    name: "verify-p2-recipe", ontology_ref: ontRef, output_kind: "ontology_objects",
    source_refs: ["s3://verify/sample.csv"], connector_mappings: [{ connector: "conn_x", table: "docs" }],
    policy_bound_views: [], projection_refs: ["projection://verify-p2"],
  });
  made.recipe = rec.j?.recipe?.id || rec.j?.data_recipe?.id;
  const recRef = rec.j?.recipe?.ref || rec.j?.data_recipe?.ref;
  ok("recipe created with partial chain", rec.status === 201 && !!made.recipe, made.recipe);

  // H. Handoff chain rendering — posture per field, validation a named gap.
  const rd = await sGet(`/__ioi/odk/data-recipes/${encodeURIComponent(made.recipe)}`);
  ok("recipe detail renders the handoff chain", rd.status === 200 && rd.text.includes('id="recipe-handoff-chain"'));
  ok("chain stages present in order", ["Source sample", "Connector mapping", "Policy-bound view", "Object mapping", "Validation", "Lineage", "Emission"].every((s) => rd.text.includes(s)));
  ok("populated stages read from the record", rd.text.includes("1 source ref") && rd.text.includes("1 embedded") && rd.text.includes("bound to ontology"));
  ok("empty stage honest (policy views)", rd.text.includes("none declared"));
  ok("validation is a NAMED GAP, never faked", rd.text.includes("named gap — lands with execution"));
  ok("lineage honest before manifest", rd.text.includes("not yet in a manifest"));

  const mf = await jd("POST", "/v1/hypervisor/odk/manifests", { name: "verify-p2-manifest", ontology_refs: [ontRef], recipe_refs: [recRef] });
  made.manifest = mf.j?.manifest?.id;
  ok("manifest created bundling the recipe", mf.status === 201 && !!made.manifest, made.manifest);
  const rd2 = await sGet(`/__ioi/odk/data-recipes/${encodeURIComponent(made.recipe)}`);
  ok("lineage stage flips with manifest membership", rd2.text.includes("in 1 manifest"));

  // J. Blueprint candidates projection.
  const da = await sGet("/__ioi/domain-apps");
  ok("blueprint candidates section renders", da.status === 200 && da.text.includes('id="dapps-blueprint-candidates"'));
  ok("missing-object gap NAMED", da.text.includes("no persisted DomainBlueprint object exists yet"));
  ok("manifest projected as candidate with closure counts", da.text.includes("verify-p2-manifest") && da.text.includes("1 recipes"));
  ok("no bound app candidate said honestly", da.text.includes("no app candidate bound"));

  // I. Pipeline view over a real automation with declared steps (automations are project-first).
  const pj = await jd("POST", "/v1/hypervisor/projects", { project_name: "verify-p2-pipeline", repository_url: "https://example.local/verify/verify-p2-pipeline.git" });
  made.project = "verify-p2-pipeline";
  ok("project created (automations are project-first)", pj.status === 200 || pj.status === 201, made.project);
  const au = await jd("POST", "/v1/hypervisor/automations", { name: "verify-p2-pipeline", trigger_kind: "manual", project_ref: "project:verify-p2-pipeline", steps: [{ kind: "shell", command: "echo one" }, { kind: "shell", command: "echo two" }] });
  made.auto = au.j?.automation?.automation_id || au.j?.automation_id;
  ok("automation created with declared steps", (au.status === 200 || au.status === 201) && !!made.auto, made.auto || JSON.stringify(au.j).slice(0, 80));
  if (made.auto) {
    const ad = await sGet(`/__ioi/automations/${encodeURIComponent(made.auto)}`);
    ok("pipeline view renders on the automation", ad.status === 200 && ad.text.includes('id="auto-pipeline"'));
    ok("trigger and steps as pipeline nodes", ad.text.includes("trigger · manual") && ad.text.includes("1 · shell") && ad.text.includes("2 · shell"));
    ok("no-runs state honest", ad.text.includes("no runs yet"));
    ok("canvas honesty stated", ad.text.includes("the authoring canvas is a later cut"));
  }
}

run().then(async () => {
  await cleanup();
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("p2-builder readiness: OK");
}).catch(async (e) => { await cleanup(); console.error("verifier crashed:", e); process.exit(1); });
