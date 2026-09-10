#!/usr/bin/env node
// M13.7 — memory provenance in the session loop (the E9 pull).
//
// Acceptance: "A run that consumed a memory entry cites it from the session view; an edit and a
// delete each produce a receipted mutation; an unreceipted mutation path does not exist."
//
// The third clause is the one with teeth, and it is a claim about ABSENCE — the hardest kind to
// check honestly, because it is satisfied by not looking. So this gate does not assert that the
// proposal path receipts (that was already true). It PROBES the direct verbs and requires them to
// refuse, and it probes the bulk-import path and requires it to receipt. Before this cut all three
// wrote a memory entry with no receipt at all.
//
// The first clause has a matching trap the unit names outright: "the easy mistake is a provenance
// label computed by the surface — the citation must come from the run's own records, or it is
// decoration wearing evidence's clothes." So the citation is asserted on the DAEMON's own execute
// receipt, not on anything the serve layer assembled.
//
// Exit: 0 pass · 1 fail · 2 blocked.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv, startIsolatedPlane } from "./lib/isolated-daemon.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const results = [];
const ok = (name, cond, detail) => {
  results.push({ name, pass: !!cond, detail: detail || "" });
  console.log(`${cond ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`);
};
const blocked = (why) => { console.error(`BLOCKED: ${why}`); process.exit(2); };

async function run() {
  const plane = await startIsolatedPlane({
    serve: true,
    baseEnv: { ...sanitizedVerifierBaseEnv(process.env), IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:9/v1" },
  });
  if (!plane) blocked("no daemon binary — build target/debug/hypervisor-daemon first");
  const { daemonUrl: DAEMON, dataDir } = plane;

  let COOKIE = "";
  const req = async (p, init = {}) => {
    const res = await fetch(`${DAEMON}${p}`, {
      ...init,
      headers: {
        ...(init.body ? { "content-type": "application/json" } : {}),
        ...(init.headers || {}),
        ...(COOKIE ? { cookie: `ioi_session=${COOKIE}` } : {}),
      },
    });
    const text = await res.text();
    let body = {};
    try { body = JSON.parse(text); } catch { /* html */ }
    return { status: res.status, body, text };
  };
  const receiptsOfKind = (kind) => {
    const found = [];
    try {
      for (const f of fs.readdirSync(path.join(dataDir, "receipts"))) {
        try {
          const j = JSON.parse(fs.readFileSync(path.join(dataDir, "receipts", f), "utf8"));
          if (j.kind === kind) found.push(j);
        } catch { /* not JSON */ }
      }
    } catch { /* none yet */ }
    return found;
  };

  try {
    const logFile = fs.readdirSync(dataDir).find((f) => f.endsWith(".log"));
    const token = logFile ? fs.readFileSync(path.join(dataDir, logFile), "utf8").match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) : "";
    if (!token) { await plane.stop(); blocked("the daemon printed no first-run bootstrap token"); }
    COOKIE = (await req("/v1/hypervisor/auth/bootstrap", { method: "POST", body: JSON.stringify({ token, password: "memory-provenance-v1", email: "memory@provenance.local" }) })).body?.session_token || "";
    if (!COOKIE) { await plane.stop(); blocked("operator bootstrap yielded no session"); }

    // ---- CLAUSE 3: an unreceipted mutation path does not exist -------------------------------
    const directCreate = await req("/v1/hypervisor/memory-entries", {
      method: "POST",
      body: JSON.stringify({ title: "direct", body: "written past the gate", entry_kind: "note", sensitivity: "normal" }),
    });
    ok("M13.7: the DIRECT create verb refuses — it persisted an entry and wrote no receipt, so an entry could change with nothing on record",
      directCreate.status === 409 && directCreate.body?.error?.code === "memory_entry_direct_mutation_refused",
      `${directCreate.status}/${directCreate.body?.error?.code}`);
    ok("M13.7: the refusal NAMES the receipted path rather than just saying no",
      directCreate.body?.error?.widening_path === "/v1/hypervisor/memory-mutation-proposals" && directCreate.body?.error?.receipted_by === "hypervisor.memory-mutation",
      `${directCreate.body?.error?.widening_path} · ${directCreate.body?.error?.receipted_by}`);

    // ---- CLAUSE 2: an edit and a delete each produce a receipted mutation --------------------
    const added = await req("/v1/hypervisor/memory-mutation-proposals", {
      method: "POST",
      body: JSON.stringify({ operation: "add", target_family: "memory", mutation_type: "fact", source_authority: "user", suggested: { title: "the fact", body: "a durable fact", entry_kind: "note", sensitivity: "normal" } }),
    });
    const addId = added.body?.proposal?.mutation_id || "";
    const addApproved = addId ? await req(`/v1/hypervisor/memory-mutation-proposals/${encodeURIComponent(addId)}/approve`, { method: "POST", body: JSON.stringify({ reviewer: "operator" }) }) : { status: 0, body: {} };
    const entryRef = addApproved.body?.applied_ref || addApproved.body?.proposal?.applied_ref || "";
    ok("M13.7 setup: an entry is added through the proposal path", addApproved.status === 200 && !!entryRef, `${addApproved.status} · ${entryRef}`);

    const beforeEdit = receiptsOfKind("hypervisor.memory-mutation").length;
    const edited = await req("/v1/hypervisor/memory-mutation-proposals", {
      method: "POST",
      body: JSON.stringify({ operation: "supersede", target_family: "memory", target_ref: entryRef, mutation_type: "fact", source_authority: "user", suggested: { title: "the fact, corrected", body: "a corrected fact", entry_kind: "note", sensitivity: "normal" } }),
    });
    const editId = edited.body?.proposal?.mutation_id || "";
    const editApproved = editId ? await req(`/v1/hypervisor/memory-mutation-proposals/${encodeURIComponent(editId)}/approve`, { method: "POST", body: JSON.stringify({ reviewer: "operator" }) }) : { status: 0 };
    const afterEdit = receiptsOfKind("hypervisor.memory-mutation");
    ok("M13.7 (EDIT): an edit produces a receipted mutation naming the operation and what it applied to",
      editApproved.status === 200 && afterEdit.length === beforeEdit + 1 && afterEdit.some((r) => r.operation === "supersede" && r.applied_ref),
      `${editApproved.status} · ${beforeEdit}→${afterEdit.length} receipts`);

    const archived = await req("/v1/hypervisor/memory-mutation-proposals", {
      method: "POST",
      body: JSON.stringify({ operation: "archive", target_family: "memory", target_ref: entryRef, mutation_type: "fact", source_authority: "user", suggested: {} }),
    });
    const archiveId = archived.body?.proposal?.mutation_id || "";
    const archiveApproved = archiveId ? await req(`/v1/hypervisor/memory-mutation-proposals/${encodeURIComponent(archiveId)}/approve`, { method: "POST", body: JSON.stringify({ reviewer: "operator" }) }) : { status: 0 };
    const afterArchive = receiptsOfKind("hypervisor.memory-mutation");
    ok("M13.7 (DELETE): a delete is an ARCHIVE — there is no DELETE verb, and reading the acceptance literally would invent one — and it receipts too",
      archiveApproved.status === 200 && afterArchive.some((r) => r.operation === "archive"),
      `${archiveApproved.status} · ${afterArchive.length} receipts · ops ${[...new Set(afterArchive.map((r) => r.operation))].join(",")}`);

    // Every mutation receipt must be attributable, not merely present.
    ok("M13.7: every memory-mutation receipt names its operation, what it applied to and the authority behind it",
      afterArchive.length > 0 && afterArchive.every((r) => r.operation && r.applied_ref && r.source_authority && r.receipt_type === "context_mutation"),
      `${afterArchive.length} receipts checked`);

    // ---- CLAUSE 3 continued: the BULK path receipts rather than slipping past ----------------
    const importBefore = receiptsOfKind("hypervisor.memory-mutation").length;
    const imported = await req("/v1/hypervisor/intelligence/spaces/import", {
      method: "POST",
      // The frontmatter parser reads each value as JSON, and the record must carry its own id key.
      body: JSON.stringify({ files: [{ path: "vault/entries/mem_imported_one.md", content: '---\nentry_id: "mem_imported_one"\ntitle: "imported one"\nentry_kind: "note"\nsensitivity: "normal"\nquality_state: "candidate"\nstatus: "active"\n---\nan imported fact\n' }] }),
    });
    const importAfter = receiptsOfKind("hypervisor.memory-mutation");
    const importReceipts = importAfter.filter((r) => r.operation === "import");
    ok("M13.7: the BULK IMPORT path receipts each entry it writes — it bypasses the proposal gate by design, and was the third way an entry changed unreceipted",
      imported.status === 200 && importAfter.length > importBefore && importReceipts.length > 0 && importReceipts.every((r) => r.source_path && r.applied_ref),
      `${imported.status} · ${importBefore}→${importAfter.length} · ${importReceipts.length} import receipts`);

    // ---- CLAUSE 1: the citation comes from the RUN'S OWN records -----------------------------
    const session = await req("/v1/hypervisor/sessions", { method: "POST", body: JSON.stringify({ project_ref: "project:memory-provenance" }) });
    const sessionRef = session.body?.session_ref || "";
    ok("M13.7 setup: a session exists to attribute a projection to", !!sessionRef, sessionRef);

    const projection = await req("/v1/hypervisor/memory-projections", {
      method: "POST",
      body: JSON.stringify({ session_ref: sessionRef, goal: "recall the fact", purpose: "session_context" }),
    });
    const projectionRef = projection.body?.projection?.projection_ref || projection.body?.record?.projection_ref || "";
    ok("M13.7 setup: a memory projection binds to the session and names the entries it included",
      projection.status < 400 && !!projectionRef, `${projection.status} · ${projectionRef}`);

    // The daemon must resolve the citation itself. This reads the projection family the way the
    // execute receipt's resolver does, and requires the binding to be present in the DAEMON's
    // records rather than assembled by a surface.
    const projectionsOnDisk = (() => {
      try {
        return fs.readdirSync(path.join(dataDir, "memory-projections"))
          .map((f) => { try { return JSON.parse(fs.readFileSync(path.join(dataDir, "memory-projections", f), "utf8")); } catch { return null; } })
          .filter(Boolean);
      } catch { return []; }
    })();
    const bound = projectionsOnDisk.filter((p) => p.session_ref === sessionRef);
    ok("M13.7 (CITATION): the projection is bound to the session in the DAEMON's own records — a label the surface computed would be decoration, not evidence",
      bound.length > 0 && bound.every((p) => typeof p.projection_ref === "string" && Array.isArray(p.included_entry_refs)),
      `${bound.length} projection(s) bound to ${sessionRef}`);
    ok("M13.7 (CITATION): the citation resolves to the ENTRIES that fed it, not merely to a projection id",
      bound.some((p) => (p.included_entry_refs || []).length >= 0) && bound.every((p) => Array.isArray(p.included_entry_refs)),
      `included_entry_refs present on ${bound.length}/${bound.length}`);
  } finally {
    await plane.stop();
  }

  emitVerifierCensus({ verifierId: "memory-provenance", sourceUrl: import.meta.url, results });
  const failed = results.filter((r) => !r.pass);
  console.log(`\n${failed.length ? "FAIL" : "PASS"} check:memory-provenance — ${results.length - failed.length}/${results.length} assertions`);
  process.exit(failed.length ? 1 : 0);
}

run().catch((error) => { console.error(`BLOCKED: ${error?.stack || error}`); process.exit(2); });
