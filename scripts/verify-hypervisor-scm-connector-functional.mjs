#!/usr/bin/env node
// Done-bar for the reference SCM connector — the wallet-authorized PUBLICATION CROSSING, as
// rebuilt against the registered contract
// `schema://ioi/components/connectors-tools/scm-publication-effect/v1`.
//
// WHAT THIS BAR USED TO CERTIFY (and no longer does). The previous version of this file asserted
// that `POST /v1/hypervisor/environments/{id}/scm/publish` with a body of only
// `{connector_id, title}` returned 200 `ok:true` with a real host mutation. That is precisely the
// unbound-destination / unbound-proposal / whole-workspace / `push --force` path the rebuilt
// contract makes UNREPRESENTABLE, so the old assertions were pinned to the defect. They are
// replaced, not weakened: every property that still holds (fail-closed-without-authority, the real
// effect landing in a bare remote, durable persistence, sealed-credential lease posture) is kept
// and strengthened.
//
// WHAT IT CERTIFIES NOW. Publication requires an ADMITTED destination binding (never caller text),
// a BOUND proposal with an exact enumerated file set, and an expected-head compare-and-swap; it
// emits publication and review-request as separately receipted sub-effects with `overall_outcome`
// DERIVED from both. This bar drives a LOCAL bare repo as the admitted remote (real git, no
// external credentials) and proves, end to end:
//   admit binding + proposal → unauthorized publish fails closed with a challenge SCOPED TO THE
//   EXACT DESTINATION → caller-supplied remote / force / whole-workspace / replay assertions each
//   refuse BY NAME → a stale expected head refuses by name and the remote head is unchanged →
//   an authorized publish lands EXACTLY the declared file set (an undeclared workspace file never
//   crosses) as a fast-forward from the observed base → the effect's content commitment, file-set
//   digest, and idempotency key all recompute → a rejected review request is reported as its own
//   outcome and NEVER as overall success, with TWO distinct receipts → an exact replay converges
//   with no second crossing → the sealed credential-lease posture holds.
// Boundary: daemon EXECUTES the crossing · wallet AUTHORIZES it · agentgres RECORDS the effect.
//
// Model-free (no Ollama). Usage: node scripts/verify-hypervisor-scm-connector-functional.mjs [--json]
import { mintApprovalGrant } from "./lib/mint-approval-grant.mjs";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || `${os.homedir()}/.ioi/hypervisor/data`;
const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "scm-connector", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const j = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); return { status: r.status, body: await r.json().catch(() => ({})) }; };

// --- canonical (JCS) digests, recomputed independently of the daemon -------------------------
const jcs = (value) => {
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value === undefined ? null : value);
};
const jcsHash = (value) => `sha256:${crypto.createHash("sha256").update(jcs(value)).digest("hex")}`;
const sha256 = (buf) => `sha256:${crypto.createHash("sha256").update(buf).digest("hex")}`;
// The one honest overall outcome for a pair of sub-effect outcomes — the same table the contract
// derives from. The caller NEVER supplies this; the bar recomputes it to prove it is derived.
const deriveOverall = (publication, review) => ({
  "published|opened": "published_with_review_request",
  "published|not_requested": "published_review_request_not_requested",
  "published|failed": "review_request_failed",
  "partially_applied|not_attempted": "partially_applied",
  "refused|refused": "refused",
  "refused|not_attempted": "refused",
}[`${publication}|${review}`] ?? null);

const git = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
const tryGit = (args) => { try { return git(args); } catch { return null; } };

if (!JSON_OUT) console.log("SCM publication e2e — the contract-bound, wallet-authorized publish crossing");

try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

// Every run owns a fresh repository identity: the publication plane is durable and estate-wide, so
// a shared identity would converge onto a PRIOR run's effects instead of proving this one.
const NONCE = crypto.randomBytes(4).toString("hex");
const REPO = `ioi/done-bar-${NONCE}`;
const cleanup = [];

// --- the admitted remote: a local bare repo with a real base ref -----------------------------
const root = fs.mkdtempSync(`${os.tmpdir()}/ioi-scm-`);
cleanup.push(root);
const bare = `${root}/remote.git`;
git(["init", "-q", "--bare", bare]);
const seed = `${root}/seed`;
fs.mkdirSync(seed);
git(["-C", seed, "init", "-q"]);
fs.writeFileSync(`${seed}/README.md`, "base\n");
git(["-C", seed, "add", "README.md"]);
git(["-C", seed, "-c", "user.email=bar@ioi.local", "-c", "user.name=bar", "commit", "-qm", "base one"]);
const staleBaseSha = git(["-C", seed, "rev-parse", "HEAD"]);
fs.writeFileSync(`${seed}/README.md`, "base moved on\n");
git(["-C", seed, "add", "README.md"]);
git(["-C", seed, "-c", "user.email=bar@ioi.local", "-c", "user.name=bar", "commit", "-qm", "base two"]);
const baseSha = git(["-C", seed, "rev-parse", "HEAD"]);
git(["-C", seed, "push", "-q", bare, "HEAD:refs/heads/integration"]);

// --- register the local connector ------------------------------------------------------------
const reg = await j("POST", "/v1/hypervisor/scm-connectors", { kind: "git", remote_url: `file://${bare}`, name: `done-bar-local-${NONCE}` });
const connectorId = reg.body?.connector?.connector_id;
ok(reg.body?.ok && !!connectorId, "register a local (file://) SCM connector", reg.body?.connector?.auth_posture);
ok(reg.body?.connector?.auth_posture === "local-none", "local connector needs no credentials (auth_posture local-none)");

// --- ADMIT the destination binding: the ONLY thing a publication may resolve a remote from -----
const bindingRef = `scm-destination-binding://${REPO}/revision/0001`;
const bindingBody = {
  destination_binding_ref: bindingRef,
  connector_ref: `connector://${connectorId}`,
  connector_revision_hash: sha256(JSON.stringify(reg.body?.connector ?? {})),
  repository_ref: `repository://${REPO}`,
  base_ref: `scm-ref://${REPO}/heads/integration`,
  target_ref_namespace: `scm-ref://${REPO}/heads/`,
  remote_url: `file://${bare}`,
  admission_receipt_ref: `receipt://${REPO}/scm-publication/admission/0001`,
};
const bindAdmit = await j("POST", "/v1/hypervisor/scm-destination-bindings", bindingBody);
const binding = bindAdmit.body?.destination_binding;
ok(bindAdmit.status === 200 && bindAdmit.body?.ok === true, "admit an SCM destination binding (200)", `status ${bindAdmit.status}`);
{
  const { destination_binding_hash: declared, ...material } = binding ?? {};
  ok(!!declared && declared === jcsHash({ ...material, domain: "ioi.hypervisor.scm-destination-binding-jcs-sha256.v1" }),
    "the admitted binding's revision hash RECOMPUTES over its whole record", (declared || "").slice(0, 20));
}
const bindingList = await j("GET", "/v1/hypervisor/scm-destination-bindings");
ok(bindingList.body?.ok && (bindingList.body?.destination_bindings || []).some((b) => b.destination_binding_ref === bindingRef),
  "the admitted binding is durable and enumerable");

// --- environment with a real change ------------------------------------------------------------
const env = await j("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0" } });
const envId = env.body?.environment?.id;
await j("POST", `/v1/hypervisor/environments/${envId}/start`);
const ws = (await j("GET", `/v1/hypervisor/environments/${envId}`)).body?.environment?.status?.workspace_root;
ok(!!ws, "environment started with a workspace", envId);
if (!ws) blocked("environment did not provision a workspace");
const declaredBytes = "shipped via the publication crossing\n";
fs.writeFileSync(`${ws}/published-feature.txt`, declaredBytes);
// An UNDECLARED file that sits in the same workspace. The old route staged it with `git add -A`;
// nothing in the rebuilt plane can carry it, and the remote tree proves that below.
fs.writeFileSync(`${ws}/never-declared.txt`, "this must never reach the remote\n");

// --- ADMIT the proposal: an enumerated file set, never a workspace snapshot --------------------
const proposalRef = `proposal://${REPO}/change/0001`;
const workRunRef = `work-run://${REPO}/0001`;
const propAdmit = await j("POST", "/v1/hypervisor/scm-publication-proposals", {
  proposal_ref: proposalRef,
  base_revision_id: `scm-revision:${baseSha}`,
  files: [{ path: "published-feature.txt", change_kind: "added", content_digest: sha256(declaredBytes), proposal_ref: proposalRef }],
  work_run_ref: workRunRef,
});
const proposal = propAdmit.body?.proposal;
ok(propAdmit.status === 200 && propAdmit.body?.ok === true, "admit a proposal-bound change set (200)", `status ${propAdmit.status}`);
ok(proposal?.change_set_kind === "proposal_bound_file_set", "the admitted proposal declares the one admitted change-set kind", proposal?.change_set_kind);
ok(proposal?.proposal_hash === jcsHash({
  domain: "ioi.hypervisor.scm-publication-proposal-jcs-sha256.v1",
  proposal_ref: proposal?.proposal_ref ?? null,
  change_set_kind: proposal?.change_set_kind ?? null,
  base_revision_id: proposal?.base_revision_id ?? null,
  files: proposal?.files ?? null,
}), "the proposal's content commitment RECOMPUTES over the declared set");

const PUBLISH = `/v1/hypervisor/environments/${envId}/scm/publish`;
const submission = { destination_binding_ref: bindingRef, proposal_ref: proposalRef, work_run_ref: workRunRef, target_ref_name: "proposal-0001", title: "Ship the rebuilt publication route" };
const targetRef = (leaf) => `refs/heads/${leaf}`;

// =============================================================================================
// 1) The OLD body shape, and every unbound shape, fail closed
// =============================================================================================
const oldShape = await j("POST", PUBLISH, { connector_id: connectorId, title: "Ship feature" });
ok(oldShape.status === 409 && oldShape.body?.ok === false && oldShape.body?.fail_closed === true,
  "the OLD `{connector_id,title}` body is no longer a publication (409, fail-closed)", `status ${oldShape.status}`);
ok(/admitted destination binding/.test(oldShape.body?.message || ""),
  "the refusal names what a publication requires (an admitted binding + a bound proposal)");

const unknownBinding = await j("POST", PUBLISH, { ...submission, destination_binding_ref: `scm-destination-binding://${REPO}/revision/never-admitted` });
ok(unknownBinding.status === 404 && unknownBinding.body?.reason === "scm_publication_binding_not_admitted",
  "an unadmitted destination binding fails closed BY NAME (scm_publication_binding_not_admitted)", `status ${unknownBinding.status}`);
const unknownProposal = await j("POST", PUBLISH, { ...submission, proposal_ref: `proposal://${REPO}/change/never-bound` });
ok(unknownProposal.status === 404 && unknownProposal.body?.reason === "scm_publication_proposal_not_found",
  "an unbound proposal fails closed BY NAME (scm_publication_proposal_not_found)", `status ${unknownProposal.status}`);

// =============================================================================================
// 2) UNAUTHORIZED publish fails closed with a challenge SCOPED TO THE EXACT DESTINATION
// =============================================================================================
const unauth = await j("POST", PUBLISH, submission);
ok(unauth.status === 403 && unauth.body?.reason === "scm_publish_authority_required", "unauthorized publish FAILS CLOSED (403, authority required)", `status ${unauth.status}`);
const policyHash = unauth.body?.approval?.policy_hash;
const requestHash = unauth.body?.approval?.request_hash;
ok(!!policyHash && !!requestHash, "challenge exposes daemon-derived policy_hash + request_hash");
ok(unauth.body?.host_mutation === false, "the challenge claims NO host mutation");
ok(JSON.stringify(unauth.body?.resource_refs) === JSON.stringify([bindingRef, envId]),
  "the challenge is SCOPED TO THE ADMITTED DESTINATION (resource_refs = binding + environment, never caller remote text)",
  JSON.stringify(unauth.body?.resource_refs));
{
  const scopes = unauth.body?.required_scopes || [];
  ok(scopes.length === 2 && scopes.includes("scope:scm.publication.advance-target-ref") && scopes.includes("scope:scm.publication.open-review-request"),
    "the crossing demands the publication scope family (advance-target-ref + open-review-request)", JSON.stringify(scopes));
  ok(!scopes.some((s) => s === "scm_push" || s === "remote_publish"),
    "no legacy publish scope survives (the family is disjoint from every other)");
}

let grant = null;
try { grant = mintApprovalGrant({ policyHash, requestHash }); } catch (e) { blocked(`grant minter unavailable: ${e?.message || e}`); }

// A grant bound to THIS destination authorizes nothing at another destination.
const otherBindingRef = `scm-destination-binding://${REPO}/revision/0002`;
await j("POST", "/v1/hypervisor/scm-destination-bindings", { ...bindingBody, destination_binding_ref: otherBindingRef, admission_receipt_ref: `receipt://${REPO}/scm-publication/admission/0002` });
const misdirected = await j("POST", PUBLISH, { ...submission, destination_binding_ref: otherBindingRef, wallet_approval_grant: grant });
ok(misdirected.status === 403 && misdirected.body?.reason === "scm_publish_authority_required",
  "a grant for one destination does NOT authorize another destination (403)", `status ${misdirected.status}`);

// =============================================================================================
// 3) Caller shapes the contract makes unrepresentable — each refuses BY NAME
// =============================================================================================
const namedRefusal = async (body, dimension, label) => {
  const r = await j("POST", PUBLISH, { ...submission, ...body, wallet_approval_grant: grant });
  ok(r.status === 409 && r.body?.reason === "scm_publication_refused" && String(r.body?.message || "").startsWith(`${dimension}:`),
    label, `${r.status} ${String(r.body?.message || r.body?.reason).slice(0, 90)}`);
};
await namedRefusal({ remote_url: `file://${root}/attacker.git` }, "unbound_destination",
  "a caller-supplied remote refuses BY NAME (unbound_destination) — free text never names a remote");
await namedRefusal({ force: true }, "remote_overwrite_requested",
  "a forced overwrite refuses BY NAME (remote_overwrite_requested)");
await namedRefusal({ remote_update_mode: "force_push" }, "remote_overwrite_requested",
  "a non-admitted remote update mode refuses BY NAME (remote_overwrite_requested)");
await namedRefusal({ change_set_kind: "whole_workspace_snapshot" }, "whole_workspace_change_set",
  "a whole-workspace stage refuses BY NAME (whole_workspace_change_set)");
await namedRefusal({ submission_disposition: "converged_replay" }, "replay_without_prior_effect",
  "a caller-asserted replay refuses BY NAME (replay_without_prior_effect) — the disposition is derived");
ok(tryGit(["--git-dir", bare, "rev-parse", targetRef("proposal-0001")]) === null,
  "REAL EFFECT: after every refusal the remote still has NO target ref (nothing crossed)");

// =============================================================================================
// 4) A stale expected head refuses BY NAME and never overwrites
// =============================================================================================
const staleProposalRef = `proposal://${REPO}/change/stale`;
fs.writeFileSync(`${ws}/stale-feature.txt`, "stale\n");
await j("POST", "/v1/hypervisor/scm-publication-proposals", {
  proposal_ref: staleProposalRef,
  base_revision_id: `scm-revision:${staleBaseSha}`,
  files: [{ path: "stale-feature.txt", change_kind: "added", content_digest: sha256("stale\n"), proposal_ref: staleProposalRef }],
  work_run_ref: `work-run://${REPO}/stale`,
});
const staleSubmission = { destination_binding_ref: bindingRef, proposal_ref: staleProposalRef, work_run_ref: `work-run://${REPO}/stale`, target_ref_name: "stale-0001", title: "stale" };
const staleChallenge = await j("POST", PUBLISH, staleSubmission);
const staleGrant = mintApprovalGrant({ policyHash: staleChallenge.body?.approval?.policy_hash, requestHash: staleChallenge.body?.approval?.request_hash });
const stale = await j("POST", PUBLISH, { ...staleSubmission, wallet_approval_grant: staleGrant });
ok(stale.status === 409 && stale.body?.reason === "scm_publication_refused" && String(stale.body?.message || "").startsWith("stale_expected_head:"),
  "a stale expected head refuses BY NAME (stale_expected_head) instead of overwriting", String(stale.body?.message || "").slice(0, 90));
ok(/never overwritten/.test(stale.body?.message || ""), "the refusal states the disposition: refuse, never overwrite");
ok(tryGit(["--git-dir", bare, "rev-parse", "refs/heads/integration"]) === baseSha,
  "REAL EFFECT: the remote BASE head is unchanged after the stale refusal");
ok(tryGit(["--git-dir", bare, "rev-parse", targetRef("stale-0001")]) === null,
  "REAL EFFECT: the stale publication created no target ref on the remote");

// =============================================================================================
// 5) The authorized publication: a derived outcome and a real, bounded effect
// =============================================================================================
const auth = await j("POST", PUBLISH, {
  ...submission,
  wallet_approval_grant: grant,
  // A caller CLAIM of the overall outcome. It is derived server-side and this claim is inert.
  overall_outcome: "published_with_review_request",
});
const effect = auth.body?.publication_effect || {};
const receipts = auth.body?.receipts || [];
ok(auth.status === 200 && auth.body?.ok === true, "authorized publish succeeds (200)", `status ${auth.status}`);
ok(auth.body?.overall_outcome === "published_review_request_not_requested" && effect.overall_outcome === auth.body?.overall_outcome,
  "the effect carries the derived overall outcome", auth.body?.overall_outcome);
ok(auth.body?.overall_outcome === deriveOverall(effect?.effects?.publication?.outcome, effect?.effects?.review_request?.outcome),
  "the overall outcome is DERIVED from the two sub-effects, not asserted by the caller");
ok(auth.body?.overall_outcome !== "published_with_review_request", "the caller's claimed overall outcome is inert");
ok(auth.body?.converged === false, "a first admission is not a replay (converged:false)");
ok(effect.schema_version === "ioi.scm-publication-effect.v1", "the effect declares the registered schema version", effect.schema_version);

ok(effect?.destination?.resolution === "admitted_connector_binding" && effect?.destination?.destination_binding_ref === bindingRef,
  "the destination resolved from the ADMITTED binding", effect?.destination?.resolution);
ok(effect?.destination?.destination_binding_hash === binding?.destination_binding_hash,
  "the effect pins the exact binding REVISION it resolved through");
ok(effect?.destination?.target_ref === `scm-ref://${REPO}/heads/proposal-0001`,
  "the target ref lies inside the binding's namespace", effect?.destination?.target_ref);
ok(effect?.remote_cas?.mechanism === "expected_head_compare_and_swap"
  && effect?.remote_cas?.remote_update_mode === "expected_head_advance_or_refuse"
  && effect?.remote_cas?.stale_head_disposition === "refuse_never_overwrite",
  "the compare-and-swap declares the single admitted mechanism, update mode, and stale disposition");
ok(effect?.remote_cas?.target_ref_precondition === "must_not_exist" && effect?.remote_cas?.expected_target_head === null,
  "a new target ref advances under a must-not-exist precondition");
ok(effect?.remote_cas?.expected_base_head === `scm-revision:${baseSha}` && effect?.remote_cas?.expected_base_head === effect?.change_set?.base_revision_id,
  "the expected base head is the exact revision the change set was computed onto");
ok(effect?.remote_cas?.resulting_target_head === effect?.change_set?.resulting_revision_id,
  "the resulting remote head equals the resulting revision of the published change set");
ok(JSON.stringify(effect?.nonclaims) === JSON.stringify(["grants_no_authority", "no_remote_acceptance_beyond_receipt_evidence", "asserts_no_review_approval"]),
  "the effect carries the three declared nonclaims verbatim");

// The three registered commitments, recomputed here from the effect's own material.
{
  const { publication_effect_hash: declared, ...rest } = effect;
  const material = { domain: "ioi.scm-publication-effect-commitment-jcs-sha256.v1" };
  for (const field of ["schema_version", "publication_effect_id", "work_subject", "authority", "destination", "change_set", "remote_cas", "idempotency", "effects", "overall_outcome", "nonclaims", "committed_at"]) material[field] = rest[field] ?? null;
  ok(!!declared && declared === jcsHash(material), "the effect's CONTENT COMMITMENT recomputes over every committed field", (declared || "").slice(0, 20));
}
ok(effect?.change_set?.file_set_digest === jcsHash({
  domain: "ioi.scm-publication-effect-file-set-jcs-sha256.v1",
  proposal_ref: effect?.work_subject?.proposal_ref ?? null,
  proposal_content_commitment: effect?.change_set?.proposal_content_commitment ?? null,
  base_revision_id: effect?.change_set?.base_revision_id ?? null,
  files: effect?.change_set?.files ?? null,
}), "the FILE-SET DIGEST recomputes over the bound proposal, base revision, and enumerated rows");
ok(effect?.idempotency?.idempotency_key === jcsHash({
  domain: "ioi.scm-publication-effect-idempotency-jcs-sha256.v1",
  proposal_ref: effect?.work_subject?.proposal_ref ?? null,
  proposal_hash: effect?.work_subject?.proposal_hash ?? null,
  destination_binding_ref: effect?.destination?.destination_binding_ref ?? null,
  destination_binding_hash: effect?.destination?.destination_binding_hash ?? null,
  repository_ref: effect?.destination?.repository_ref ?? null,
  target_ref: effect?.destination?.target_ref ?? null,
  target_ref_precondition: effect?.remote_cas?.target_ref_precondition ?? null,
  expected_target_head: effect?.remote_cas?.expected_target_head ?? null,
  file_set_digest: effect?.change_set?.file_set_digest ?? null,
}), "the IDEMPOTENCY KEY recomputes over the bound destination, target precondition, and file set");
ok(effect?.change_set?.proposal_content_commitment === effect?.work_subject?.proposal_hash
  && effect?.change_set?.proposal_content_commitment === proposal?.proposal_hash,
  "the published change set carries the exact commitment of the proposal it was computed from");
ok((effect?.change_set?.files || []).every((row) => row.proposal_ref === proposalRef),
  "every published file row is attributed to the one bound proposal");

// --- REAL EFFECT: what actually landed in the bare remote -------------------------------------
const landedSha = tryGit(["--git-dir", bare, "rev-parse", targetRef("proposal-0001")]);
const tree = tryGit(["--git-dir", bare, "ls-tree", "-r", "--name-only", targetRef("proposal-0001")]) || "";
const landedParent = tryGit(["--git-dir", bare, "rev-parse", `${targetRef("proposal-0001")}^`]);
ok(!!landedSha && `scm-revision:${landedSha}` === effect?.change_set?.resulting_revision_id,
  "REAL EFFECT: the target ref landed in the remote at exactly the effect's resulting revision", (landedSha || "").slice(0, 12));
ok(tree.includes("published-feature.txt"), "REAL EFFECT: the DECLARED file is in the remote tree");
ok(!tree.includes("never-declared.txt"),
  "REAL EFFECT: an UNDECLARED workspace file NEVER reached the remote (no whole-workspace stage)");
ok(landedParent === baseSha,
  "REAL EFFECT: the landed commit is a fast-forward from the OBSERVED base head (no overwrite)", (landedParent || "").slice(0, 12));

// --- the receipted sub-effects -----------------------------------------------------------------
ok(receipts.length === 1 && receipts[0]?.effect_kind === "scm_publication",
  "a publication with no review request emits exactly its own receipt", `receipts ${receipts.length}`);
ok(receipts[0]?.outcome === "published" && receipts[0]?.host_mutation === true,
  "the publication receipt reports a real host mutation");
ok(receipts[0]?.publication_effect_id === effect?.publication_effect_id && receipts[0]?.publication_effect_hash === effect?.publication_effect_hash,
  "the receipt binds the exact effect it receipts (id + content commitment)");
ok(receipts[0]?.idempotency_key === effect?.idempotency?.idempotency_key, "the receipt binds the effect's idempotency key");
ok(Array.isArray(effect?.authority?.authority_grant_refs) && effect.authority.authority_grant_refs.some((g) => g.startsWith("grant://")),
  "the effect carries the wallet grant ref (authority proof)", (effect?.authority?.authority_grant_refs || [])[0]?.slice(0, 48));
ok(typeof effect?.authority?.capability_lease_ref === "string" && effect.authority.capability_lease_ref.startsWith("lease://"),
  "the effect names the capability lease the crossing was issued under", effect?.authority?.capability_lease_ref);

// --- durable: the plane rebuilds the effect byte-for-byte ---------------------------------------
const effectList = await j("GET", "/v1/hypervisor/scm-publication-effects");
const stored = (effectList.body?.publication_effects || []).find((e) => e.publication_effect_id === effect.publication_effect_id);
ok(effectList.status === 200 && !!stored, "the committed effect is durable and enumerable");
ok(JSON.stringify(stored) === JSON.stringify(effect), "the durable effect is byte-identical to the reported effect");

// =============================================================================================
// 6) A rejected review request is its OWN outcome — never overall success
// =============================================================================================
const reviewProposalRef = `proposal://${REPO}/change/review`;
const reviewBytes = "opened for review\n";
fs.writeFileSync(`${ws}/review-feature.txt`, reviewBytes);
await j("POST", "/v1/hypervisor/scm-publication-proposals", {
  proposal_ref: reviewProposalRef,
  base_revision_id: `scm-revision:${baseSha}`,
  files: [{ path: "review-feature.txt", change_kind: "added", content_digest: sha256(reviewBytes), proposal_ref: reviewProposalRef }],
  work_run_ref: `work-run://${REPO}/review`,
});
const reviewSubmission = { destination_binding_ref: bindingRef, proposal_ref: reviewProposalRef, work_run_ref: `work-run://${REPO}/review`, target_ref_name: "review-0001", title: "review", open_review_request: true };
const reviewChallenge = await j("POST", PUBLISH, reviewSubmission);
const reviewGrant = mintApprovalGrant({ policyHash: reviewChallenge.body?.approval?.policy_hash, requestHash: reviewChallenge.body?.approval?.request_hash });
const review = await j("POST", PUBLISH, { ...reviewSubmission, wallet_approval_grant: reviewGrant });
const reviewEffect = review.body?.publication_effect || {};
const reviewReceipts = review.body?.receipts || [];
ok(review.status === 409 && review.body?.ok === false,
  "a publication whose review request the remote rejects is NOT reported as success (409, ok:false)", `status ${review.status}`);
ok(review.body?.overall_outcome === "review_request_failed", "the overall outcome names the review-request failure", review.body?.overall_outcome);
ok(review.body?.overall_outcome === deriveOverall(reviewEffect?.effects?.publication?.outcome, reviewEffect?.effects?.review_request?.outcome),
  "the failed-review overall outcome is DERIVED from the two sub-effects");
ok(reviewReceipts.length === 2, "the crossing emits TWO receipts — one per sub-effect", `receipts ${reviewReceipts.length}`);
ok(reviewReceipts[0]?.receipt_ref && reviewReceipts[1]?.receipt_ref && reviewReceipts[0].receipt_ref !== reviewReceipts[1].receipt_ref,
  "the two receipts are DISTINCT — one receipt never stands for both sub-effects");
{
  const pubReceipt = reviewReceipts.find((r) => r.effect_kind === "scm_publication");
  const revReceipt = reviewReceipts.find((r) => r.effect_kind === "scm_review_request");
  ok(pubReceipt?.outcome === "published" && pubReceipt?.host_mutation === true,
    "the publication sub-effect is receipted as published with a real host mutation");
  ok(revReceipt?.outcome === "failed" && revReceipt?.refusal_code === "review-request-rejected-by-remote",
    "the review-request sub-effect is receipted as failed with its NAMED refusal code", revReceipt?.refusal_code);
  ok(revReceipt?.host_mutation === false, "the failed review request claims no host mutation");
}
ok(tryGit(["--git-dir", bare, "rev-parse", targetRef("review-0001")]) === (reviewEffect?.change_set?.resulting_revision_id || "").replace("scm-revision:", ""),
  "REAL EFFECT: the publication landed even though the overall outcome is a failure — each sub-effect is reported honestly");

// =============================================================================================
// 7) Replay convergence — an exact resubmission crosses ONCE
// =============================================================================================
// (a) A refused publication: the workspace bytes left the proposal, so nothing crosses at all.
const driftProposalRef = `proposal://${REPO}/change/drift`;
fs.writeFileSync(`${ws}/drift-feature.txt`, "something else entirely\n");
await j("POST", "/v1/hypervisor/scm-publication-proposals", {
  proposal_ref: driftProposalRef,
  base_revision_id: `scm-revision:${baseSha}`,
  files: [{ path: "drift-feature.txt", change_kind: "added", content_digest: sha256("the bytes the proposal committed to\n"), proposal_ref: driftProposalRef }],
  work_run_ref: `work-run://${REPO}/drift`,
});
const driftSubmission = { destination_binding_ref: bindingRef, proposal_ref: driftProposalRef, work_run_ref: `work-run://${REPO}/drift`, target_ref_name: "drift-0001", title: "drift" };
const driftChallenge = await j("POST", PUBLISH, driftSubmission);
const driftGrant = mintApprovalGrant({ policyHash: driftChallenge.body?.approval?.policy_hash, requestHash: driftChallenge.body?.approval?.request_hash });
const drift = await j("POST", PUBLISH, { ...driftSubmission, wallet_approval_grant: driftGrant });
const driftEffect = drift.body?.publication_effect || {};
ok(drift.status === 409 && drift.body?.overall_outcome === "refused",
  "workspace bytes that left the proposal are an honest REFUSAL, not a success", `${drift.status} ${drift.body?.overall_outcome}`);
ok(driftEffect?.effects?.publication?.refusal_code === "change-set-content-digest-mismatch",
  "the refusal carries its NAMED code (change-set-content-digest-mismatch)", driftEffect?.effects?.publication?.refusal_code);
ok(driftEffect?.change_set?.resulting_revision_id === null && driftEffect?.remote_cas?.resulting_target_head === null,
  "a refused publication names no resulting revision and no resulting head");
ok(tryGit(["--git-dir", bare, "rev-parse", targetRef("drift-0001")]) === null,
  "REAL EFFECT: drifted bytes never reached the remote");

const driftReplay = await j("POST", PUBLISH, { ...driftSubmission, wallet_approval_grant: driftGrant });
const driftReplayEffect = driftReplay.body?.publication_effect || {};
ok(driftReplay.body?.converged === true && driftReplayEffect?.idempotency?.submission_disposition === "converged_replay",
  "an EXACT replay CONVERGES onto the prior effect (converged_replay)", driftReplayEffect?.idempotency?.submission_disposition);
ok(driftReplayEffect?.idempotency?.idempotency_key === driftEffect?.idempotency?.idempotency_key,
  "the replay carries the SAME idempotency key as the admission it converges onto");
ok(driftReplayEffect?.idempotency?.prior_effect_ref === driftEffect?.publication_effect_id
  && driftReplayEffect?.idempotency?.prior_effect_hash === driftEffect?.publication_effect_hash,
  "the replay names the prior effect and pins its content commitment");
ok(driftReplayEffect?.effects?.publication?.receipt_ref === driftEffect?.effects?.publication?.receipt_ref,
  "the replay mints NO second receipt — it restates the prior one");
ok(tryGit(["--git-dir", bare, "rev-parse", targetRef("drift-0001")]) === null,
  "REAL EFFECT: the replay performed NO second crossing");

// (b) An ADMITTED publication: restore the exact observed precondition the effect was computed
// against, then resubmit. The estate must converge onto the prior effect rather than push again.
// NOTE on what this does and does not claim. The registered idempotency key recomputes over the
// target-ref PRECONDITION and the expected head, so a resubmission made after the target head has
// moved is, by the contract's own definition, different material and a different submission — it
// is admitted afresh rather than converged. This bar therefore proves convergence where the
// contract promises it (an unchanged observed precondition) and deliberately does NOT certify any
// behaviour for a resubmission whose observation has moved on.
git(["--git-dir", bare, "update-ref", "-d", targetRef("review-0001")]);
const publishedReplay = await j("POST", PUBLISH, { ...reviewSubmission, wallet_approval_grant: reviewGrant });
const publishedReplayEffect = publishedReplay.body?.publication_effect || {};
ok(publishedReplay.body?.converged === true && publishedReplayEffect?.idempotency?.prior_effect_ref === reviewEffect?.publication_effect_id,
  "an exact replay of an ADMITTED publication converges onto that effect", publishedReplayEffect?.idempotency?.submission_disposition);
ok(publishedReplayEffect?.effects?.publication?.receipt_ref === reviewEffect?.effects?.publication?.receipt_ref
  && publishedReplayEffect?.effects?.review_request?.receipt_ref === reviewEffect?.effects?.review_request?.receipt_ref,
  "the converged replay restates BOTH prior sub-effect receipts and mints neither anew");
ok(tryGit(["--git-dir", bare, "rev-parse", targetRef("review-0001")]) === null,
  "REAL EFFECT: the converged replay performed NO second crossing (the remote was not re-pushed)");

// =============================================================================================
// 8) Sealed credential-lease posture on a credential-backed destination
// =============================================================================================
// A connector's identity is derived from its remote, so each run names its own remotes: a
// persistent estate must not hand this run a credential some earlier run bound.
const hosted = await j("POST", "/v1/hypervisor/scm-connectors", { kind: "git", remote_url: `https://git.example.com/ioi/example-${NONCE}.git` });
ok((hosted.body?.connector?.auth_posture || "").startsWith("token-lease"), "hosted connector declares a token-lease posture", hosted.body?.connector?.auth_posture);

// A credential-REQUIRED destination, exercised locally: the remote is an https URL that no host
// answers, so the crossing can be driven to the credential gate and the remote boundary without an
// external account. github.com itself stays fail-closed (the real review-API path needs an
// operator-supplied token + repo).
const HOSTED_REMOTE = `https://127.0.0.1:1/ioi/hosted-${NONCE}.git`;
const credConn = await j("POST", "/v1/hypervisor/scm-connectors", { kind: "git", remote_url: HOSTED_REMOTE, requires_credential: true, name: `local-cred-${NONCE}` });
const credId = credConn.body?.connector?.connector_id;
ok(credConn.body?.connector?.requires_credential === true && credConn.body?.connector?.auth_posture === "token-lease:unbound", "credential-required connector starts unbound");
const credBindingRef = `scm-destination-binding://${REPO}/revision/hosted`;
await j("POST", "/v1/hypervisor/scm-destination-bindings", {
  destination_binding_ref: credBindingRef,
  connector_ref: `connector://${credId}`,
  connector_revision_hash: sha256(JSON.stringify(credConn.body?.connector ?? {})),
  repository_ref: `repository://${REPO}`,
  base_ref: `scm-ref://${REPO}/heads/integration`,
  target_ref_namespace: `scm-ref://${REPO}/heads/`,
  remote_url: HOSTED_REMOTE,
  admission_receipt_ref: `receipt://${REPO}/scm-publication/admission/hosted`,
});
const credSubmission = { destination_binding_ref: credBindingRef, proposal_ref: proposalRef, work_run_ref: workRunRef, target_ref_name: "hosted-0001", title: "hosted" };

const preBind = await j("POST", PUBLISH, credSubmission);
ok(preBind.status === 428 && preBind.body?.reason === "scm_credential_required",
  "a credential-required destination FAILS CLOSED before any authority (428)", `status ${preBind.status}`);
ok(preBind.body?.host_mutation === false, "no host mutation is attempted while the credential is unbound");

const TOKEN = `ghp_DUMMY_done_bar_token_${NONCE}`;
const bind = await j("POST", `/v1/hypervisor/scm-connectors/${credId}/credential`, { token: TOKEN });
ok(bind.body?.ok && bind.body?.auth_posture === "token-lease:bound", "binding a credential flips auth_posture → token-lease:bound");
ok(!("token" in (bind.body || {})), "bind response does NOT echo the token");
const listAfter = JSON.stringify((await j("GET", "/v1/hypervisor/scm-connectors")).body?.connectors || []);
ok(!listAfter.includes(TOKEN), "connector listing NEVER exposes the bound token");

let credFile = "";
try { credFile = fs.readFileSync(`${DATA_DIR}/scm-credentials/${credId}.json`, "utf8"); } catch { /* */ }
ok(credFile && !credFile.includes(TOKEN), "HARDENING: no plaintext token in the at-rest credential record");
let credJson = {}; try { credJson = JSON.parse(credFile); } catch { /* */ }
ok(credJson.sealed === true && typeof credJson.sealed_token === "string" && credJson.sealed_token.length > 0, "HARDENING: credential is sealed (sealed_token present)", credJson.key_source);
ok(!("token" in credJson), "HARDENING: at-rest record has no plaintext `token` field");

const credUnauth = await j("POST", PUBLISH, credSubmission);
ok(credUnauth.status === 403 && credUnauth.body?.reason === "scm_publish_authority_required",
  "after binding, the crossing STILL requires the wallet grant (403)", `status ${credUnauth.status}`);
const cGrant = mintApprovalGrant({ policyHash: credUnauth.body?.approval?.policy_hash, requestHash: credUnauth.body?.approval?.request_hash });
const credPub = await j("POST", PUBLISH, { ...credSubmission, wallet_approval_grant: cGrant });
ok(credPub.status === 502 && credPub.body?.reason === "scm_publication_remote_unobservable",
  "with the credential resolved and the grant verified, an UNOBSERVABLE remote head fails closed (502) — it never becomes an unconditional advance",
  `status ${credPub.status}`);
ok(credPub.body?.fail_closed === true, "the unobservable-remote refusal is explicitly fail-closed");
{
  const leases = (await j("GET", "/v1/hypervisor/capability-leases")).body?.leases || [];
  const credLease = leases.find((l) => l.backing_provider === `scm:connector:${credId}`);
  ok(!!credLease, "the credentialed crossing issued a lease backed by the sealed connector credential", credLease?.lease_id);
  ok(typeof credLease?.credential_source === "string" && credLease.credential_source.length > 0,
    "the lease records the credential source (the sealed token was opened)", credLease?.credential_source);
  ok(!JSON.stringify(credLease || {}).includes(TOKEN), "the issued lease carries NO secret material (use-only)");
}

const revoke = await j("DELETE", `/v1/hypervisor/scm-connectors/${credId}/credential`);
ok(revoke.status === 200 && revoke.body?.ok === true && revoke.body?.revoked === true, "revoke deletes the sealed credential (revoked:true)", `status ${revoke.status}`);
ok(revoke.body?.auth_posture === "token-lease:unbound", "revoke flips the connector back to unbound");
const afterRevoke = (await j("GET", "/v1/hypervisor/scm-connectors")).body?.connectors?.find((c) => c.connector_id === credId);
ok(afterRevoke?.auth_posture === "token-lease:unbound", "connector reads unbound after revoke");
const postRevokePub = await j("POST", PUBLISH, { ...credSubmission, wallet_approval_grant: cGrant });
ok(postRevokePub.status === 428 && postRevokePub.body?.reason === "scm_credential_required", "publish AFTER revoke FAILS CLOSED (428, credential required)", `status ${postRevokePub.status}`);
ok(postRevokePub.body?.host_mutation === false, "no host mutation attempted after revoke");
const reRevoke = await j("DELETE", `/v1/hypervisor/scm-connectors/${credId}/credential`);
ok(reRevoke.body?.ok === true && reRevoke.body?.revoked === false, "revoke is idempotent (second revoke → revoked:false)");

// abandon-pull-request (close PR + delete branch via the sealed token) is a governed crossing too —
// fails closed without a wallet grant, on a scope disjoint from the publication family.
const abandonNoGrant = await j("POST", `/v1/hypervisor/scm-connectors/${connectorId}/abandon-pull-request`, { pull_request_url: "https://github.com/x/y/pull/1", delete_branch: false });
ok(abandonNoGrant.status === 403 && abandonNoGrant.body?.reason === "scm_abandon_authority_required", "abandon-pull-request FAILS CLOSED without a wallet grant (403)", `status ${abandonNoGrant.status}`);
ok(!(abandonNoGrant.body?.required_scopes || []).some((s) => String(s).startsWith("scope:scm.publication")),
  "an abandon grant is never a publication grant (disjoint scope families)");

for (const path of cleanup) { try { fs.rmSync(path, { recursive: true, force: true }); } catch { /* */ } }

const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "scm-connector", verdict, failures, checks: checks.length, envId, connectorId, bindingRef, proposalRef }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
