#!/usr/bin/env node
// Feedback & Annotations readiness verifier — the NEW daemon plane + queue surface:
// consent is a GATE, not a label. Creates an entry with never_train consent, proves conversion
// fails closed with the named code (daemon) and the refusal surfaces verbatim (serve), raises
// consent as a recorded change, converts with a named candidate ref, asserts queue truths and
// terminal immutability, and cleans up.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-feedback.mjs

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, path, body) {
  const r = await fetch(`${DAEMON}${path}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => null) };
}
const sGet = (p) => fetch(`${SERVE}${p}`).then(async (r) => ({ status: r.status, text: await r.text() }));
async function sForm(path, fields) {
  const r = await fetch(`${SERVE}${path}`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields).toString(), redirect: "manual" });
  return { status: r.status, location: r.headers.get("location") || "" };
}

let id = null;
async function run() {
  // 1. Create with never_train (the fail-safe default posture).
  const c = await jd("POST", "/v1/hypervisor/feedback-entries", { subject_ref: "authority-action://verify-feedback", entry_kind: "feedback", body: "verifier: harness chose the wrong venue", consent: "never_train" });
  id = c.j?.feedback_entry?.id;
  ok("entry created with never_train consent", c.status === 201 && !!id, id);

  // 2. Validation fails closed with named codes.
  const noSubj = await jd("POST", "/v1/hypervisor/feedback-entries", { body: "x" });
  ok("subject required (named code)", noSubj.status === 400 && noSubj.j?.error?.code === "feedback_subject_required");
  const noBody = await jd("POST", "/v1/hypervisor/feedback-entries", { subject_ref: "authority-action://x" });
  ok("body required (named code)", noBody.status === 400 && noBody.j?.error?.code === "feedback_body_required");
  const badConsent = await jd("POST", "/v1/hypervisor/feedback-entries", { subject_ref: "authority-action://x", body: "x", consent: "sure_whatever" });
  ok("consent ladder enforced (named code)", badConsent.status === 400 && badConsent.j?.error?.code === "feedback_consent_invalid");

  // 3. Conversion under never_train FAILS CLOSED — daemon and surface.
  const conv1 = await jd("PATCH", `/v1/hypervisor/feedback-entries/${id}`, { transition: "convert", converted_to_ref: "eval://verify" });
  ok("never_train conversion refused (daemon)", conv1.status === 400 && conv1.j?.error?.code === "feedback_consent_forbids_training");
  const conv1s = await sForm(`/__ioi/feedback/${id}/transition`, { transition: "convert", converted_to_ref: "eval://verify" });
  ok("refusal surfaces on the queue (redirect carries it)", conv1s.location.includes("refused="));
  const flashed = await sGet(conv1s.location.startsWith("/") ? conv1s.location : "/__ioi/feedback");
  ok("refusal shown verbatim, not softened", flashed.text.includes("never_train") && flashed.text.includes("Refused:"));

  // 4. Raise consent (a recorded change), then convert with the named candidate ref.
  const up = await jd("PATCH", `/v1/hypervisor/feedback-entries/${id}`, { consent: "redacted_opt_in" });
  ok("consent raise recorded", up.status === 200 && up.j?.feedback_entry?.consent === "redacted_opt_in");
  const conv2 = await jd("PATCH", `/v1/hypervisor/feedback-entries/${id}`, { transition: "convert", converted_to_ref: "eval://verify-feedback-suite" });
  ok("conversion succeeds with consent + named ref", conv2.status === 200 && conv2.j?.feedback_entry?.status === "converted" && conv2.j?.feedback_entry?.converted_to_ref === "eval://verify-feedback-suite");

  // 5. Terminal entries are receipts.
  const mut = await jd("PATCH", `/v1/hypervisor/feedback-entries/${id}`, { body: "rewrite history" });
  ok("terminal immutability (named code)", mut.status === 400 && mut.j?.error?.code === "feedback_terminal_immutable");

  // 6. Queue renders the truths.
  const page = await sGet("/__ioi/feedback");
  ok("queue renders 200 with chips + consent ladder form", page.status === 200 && page.text.includes('id="fb-chips"') && page.text.includes("never_train fails conversion closed"));
  ok("converted entry cites its candidate ref", page.text.includes("eval://verify-feedback-suite"));
  ok("consent pill on the row", page.text.includes("redacted_opt_in"));
  ok("Operations hands off to the queue", (await sGet("/__ioi/operations")).text.includes('href="/__ioi/feedback"'));
}

run().then(async () => {
  if (id) await jd("DELETE", `/v1/hypervisor/feedback-entries/${id}`);
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("feedback readiness: OK");
}).catch(async (e) => {
  if (id) await jd("DELETE", `/v1/hypervisor/feedback-entries/${id}`);
  console.error("verifier crashed:", e);
  process.exit(1);
});
