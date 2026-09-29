// A parked effect's own approval page (R-240): every state from the daemon's record alone, the operator's forms shown
// only to whom the daemon would let decide, a refused decision in the daemon's own words, and a daemon that did not answer
// named as such — never an empty or guessed page. Also the one decision-body parser every approval surface shares.
import test from "node:test";
import assert from "node:assert/strict";
import * as P from "./authority-challenge-page.mjs";
import { operatorPassphraseField } from "./lib/approval-card-facets.mjs";
import { operatorDecisionFrom } from "./lib/wallet-authority.mjs";

const NOW = Date.parse("2026-09-28T12:00:00Z");
const ID = "wac_" + "0123456789abcdef".repeat(2);
const HASH = (c) => "sha256:" + c.repeat(64);
const record = (extra = {}) => ({
  schema_version: "ioi.hypervisor.wallet-approval-challenge.v1", challenge_id: ID, approval_ref: `wallet-approval-challenge://${ID}`, state: "pending",
  target_scope: "scope:hypervisor.live-route.session-execute", policy_hash: HASH("a"), request_hash: HASH("b"), audience: "c".repeat(64),
  subject_ref: "session:s1", operation: "session-execute", requester_ref: "user://op",
  published_preimage: { effect: { session_ref: "session:s1", workspace_root: "/w", intent: "create a file", scopes: ["workspace_write"] },
    policy_preimage: { domain: "hypervisor.session.execute.policy.v1" }, request_preimage: { domain: "hypervisor.session.execute.request.v1", intent: "create a file", scopes: ["workspace_write"] } },
  created_at: "2026-09-28T11:00:00Z", last_parked_at: "2026-09-28T11:00:00Z", expires_at_ms: NOW + 3_600_000, decision: null, grant_ref: null, grant_expires_at_ms: null,
  consumed_at: null, consumed_by: null, decision_route: `/v1/hypervisor/authority/challenges/${ID}/decision`, decidable: true, ...extra,
});
const read = (c) => ({ ok: true, status: 200, body: { ok: true, challenge: c } });
const OPERATOR = { ok: true, authenticated: true, principal: { principal_ref: "user://op", name: "Ada Operator", role: "admin" } };
const MEMBER = { ok: true, authenticated: true, principal: { principal_ref: "user://mo", name: "Mo Member", role: "member" } };
const FIELD = operatorPassphraseField();
const page = (c, who = OPERATOR, extra = {}) => P.renderChallengePage({ id: ID, read: read(c), who, nowMs: NOW, passphraseField: FIELD, ...extra });

test("the page route and the list are one prefix; a challenge's page path is its id", () => {
  assert.equal(P.challengePagePath(ID), `/__ioi/authority/challenges/${ID}`);
  assert.equal(P.CHALLENGE_PAGE_ROUTE.exec(`/__ioi/authority/challenges/${ID}`)[1], ID);
  assert.deepEqual(P.CHALLENGE_DECISION_PAGE_ROUTE.exec(`/__ioi/authority/challenges/${ID}/approve`).slice(1), [ID, "approve"]);
  assert.equal(P.CHALLENGE_DECISION_PAGE_ROUTE.test(`/__ioi/authority/challenges/${ID}/grant`), false, "only approve and deny are decisions");
});

test("a pending challenge, for the operator: what it does, the exact coordinates a grant would bind, who asked and when — and the Approve (passphrase) and Deny (reason) forms", () => {
  const r = page(record());
  assert.equal(r.status, 200);
  assert.match(r.inner, /data-ioi-challenge-state="pending">Waiting for the operator/u);
  assert.match(r.inner, /<span data-ioi-challenge-intent>create a file<\/span>/u);
  for (const [attr, value] of [["target-scope", "scope:hypervisor.live-route.session-execute"], ["policy-hash", HASH("a")], ["request-hash", HASH("b")], ["audience", "c".repeat(64)]]) {
    assert.match(r.inner, new RegExp(`data-ioi-challenge-${attr}>${value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}<`, "u"), attr);
  }
  assert.match(r.inner, /data-ioi-challenge-requester>Ada Operator <code>user:\/\/op<\/code>/u);
  assert.match(r.inner, /data-ioi-challenge-expires>2026-09-28T13:00:00.000Z/u);
  assert.match(r.inner, /in 60 min/u);
  assert.match(r.inner, /<pre data-ioi-challenge-preimage>/u, "the exact bytes the hashes commit to");
  assert.ok(r.inner.includes(`action="/__ioi/authority/challenges/${ID}/approve" data-ioi-challenge-decision="approve">${FIELD} <button class="act" type="submit"`), "the approve form carries the one shared passphrase field");
  assert.ok(r.inner.includes(`action="/__ioi/authority/challenges/${ID}/deny" data-ioi-challenge-decision="deny"><input name="reason"`), "the deny form carries a reason");
  assert.doesNotMatch(r.inner, /data-ioi-disabled-reason/u, "a daemon that can decide leaves nothing disabled");
  assert.match(r.inner, /data-ioi-field-hint/u, "a missing passphrase is said on the page, not only in a browser bubble");
});

test("the forms are shown only to whom the daemon lets decide: a member, an impersonated administrator and a signed-out reader each see why, and no form", () => {
  for (const [who, marker, words] of [
    [MEMBER, "not-operator", /You are signed in as Mo Member/u],
    [{ ...OPERATOR, principal: { ...OPERATOR.principal, is_impersonated: true } }, "not-operator", /an impersonated session cannot decide one/u],
    [{ ok: true, authenticated: false, principal: OPERATOR.principal }, "signed-out", /Sign in<\/a> as the operator/u],
  ]) {
    const r = page(record(), who);
    assert.match(r.inner, new RegExp(`data-ioi-challenge-decide="${marker}"`, "u"));
    assert.match(r.inner, words);
    assert.doesNotMatch(r.inner, /<form|data-ioi-operator-passphrase/u, marker);
  }
});

test("a daemon with no deployment authority: Approve is disabled with its reason, Deny still offered (it needs no key)", () => {
  const r = page(record({ decidable: false }));
  assert.match(r.inner, /<button class="act" type="submit" disabled aria-disabled="true" data-ioi-disabled-reason="This daemon has no deployment authority to approve with/u);
  assert.doesNotMatch(r.inner, /data-ioi-operator-passphrase/u, "no passphrase is asked for what cannot be approved");
  assert.match(r.inner, /data-ioi-challenge-decision="deny"><input name="reason"/u);
  assert.match(r.inner, /data-ioi-challenge-no-decider/u);
});

test("each decided or closed state reads from the record, with no form: expired, approved (not yet run), grant expired, being run, completed, denied, and a state the page does not know", () => {
  const decision = (d, extra = {}) => ({ decision: { decision: d, decided_by: "user://op", decided_at: "2026-09-28T11:30:00Z", ...extra } });
  const cases = [
    [record({ expires_at_ms: NOW - 1 }), "expired", /Closed — expired undecided/u, /the daemon refuses a decision on it and has dropped it from its inbox\. Re-running the effect parks it again/u],
    [record({ state: "approved", grant_ref: "grant://g1", grant_expires_at_ms: NOW + 900_000, ...decision("approve") }), "approved", /Approved — grant minted, not yet run/u, /data-ioi-challenge-grant-ref>grant:\/\/g1</u],
    [record({ state: "approved", grant_ref: "grant://g1", grant_expires_at_ms: NOW - 1, ...decision("approve") }), "grant_expired", /the grant expired unused/u, /approval_ref_expired/u],
    [record({ state: "consuming", grant_ref: "grant://g1", ...decision("approve") }), "consuming", /Approved — being run now/u, /presenting its one-use grant/u],
    [record({ state: "consumed", grant_ref: "grant://g1", consumed_at: "2026-09-28T11:40:00Z", consumed_by: "authority-admission-intents/x", ...decision("approve") }), "completed", /Completed — the effect ran once/u, /data-ioi-challenge-consumed-by>authority-admission-intents\/x</u],
    [record({ state: "denied", ...decision("deny", { reason: "not this effect" }) }), "denied", /data-ioi-challenge-state="denied">Denied/u, /data-ioi-challenge-reason>not this effect</u],
    [record({ state: "mystery" }), "unknown", /State mystery/u, /nothing is inferred from it/u],
  ];
  for (const [c, key, label, detail] of cases) {
    const r = page(c);
    assert.equal(r.status, 200, key);
    assert.match(r.inner, new RegExp(`data-ioi-challenge-state="${key}"`, "u"), key);
    assert.match(r.inner, label, key);
    assert.match(r.inner, detail, key);
    assert.doesNotMatch(r.inner, /<form/u, `${key}: nothing to decide`);
  }
  assert.match(page(cases[1][0]).inner, /data-ioi-challenge-decided>approve by Ada Operator <code>user:\/\/op<\/code> at 2026-09-28T11:30:00Z/u);
});

test("a refused decision is the daemon's words verbatim, at its status, above the record re-read — and the relay's own two refusals are not blamed on the daemon", () => {
  const refusal = { decision: "approve", status: 502, code: "authority_approve_refused", message: "the deployment authority refused to approve: Error: target scope scope:autonomous_system.genesis_admit is outside the deployment approver's allowlist (scope:hypervisor.live-route.*)" };
  const r = page(record({ target_scope: "scope:autonomous_system.genesis_admit" }), OPERATOR, { refusal });
  assert.equal(r.status, 502);
  assert.match(r.inner, /data-ioi-challenge-refusal="authority_approve_refused"/u);
  assert.ok(r.inner.includes(`The daemon refused this approval (HTTP 502): <code>authority_approve_refused</code> — <span data-ioi-challenge-refusal-message>${refusal.message}</span>`), "verbatim");
  assert.match(r.inner, /The daemon's record of this challenge is unchanged — it reads as below/u);
  assert.match(r.inner, /data-ioi-challenge-state="pending"/u, "the record, re-read, still waits");
  const unreachable = page(record(), OPERATOR, { refusal: { decision: "deny", status: 502, code: "challenge_decision_unreachable", message: "fetch failed" } });
  assert.match(unreachable.inner, /The daemon did not answer this denial \(HTTP 502\)/u);
  const empty = page(record(), OPERATOR, { refusal: { decision: "approve", status: 400, code: "operator_passphrase_required", message: "approving needs the operator passphrase" } });
  assert.match(empty.inner, /This approval was not sent to the daemon \(HTTP 400\)/u);
  const html = page(record(), OPERATOR, { refusal: { decision: "approve", status: 403, code: "x", message: "<img src=x onerror=alert(1)>" } });
  assert.doesNotMatch(html.inner, /<img/u, "a refusal message is text");
});

test("a read that produced no challenge: the daemon stopped is degraded (503, nothing shown), a signed-out reader is sent to sign in, and a refused id carries the daemon's words", () => {
  const down = P.renderChallengePage({ id: ID, read: { ok: false, status: 503, body: { error: { code: "daemon_unavailable" } } }, who: null, nowMs: NOW, passphraseField: FIELD });
  assert.equal(down.status, 503);
  assert.match(down.inner, /data-ioi-challenge-degraded data-error-code="daemon_unavailable">The daemon is not answering/u);
  assert.doesNotMatch(down.inner, /<form|data-ioi-challenge-state/u);
  const out = P.renderChallengePage({ id: ID, read: { ok: false, status: 401, body: { ok: false, code: "hypervisor.authentication_required", message: "an authenticated session is required" } }, who: null, nowMs: NOW });
  assert.equal(out.status, 401);
  assert.match(out.inner, new RegExp(`href="/__ioi/login\\?next=${encodeURIComponent(P.challengePagePath(ID)).replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}"`, "u"));
  const missing = P.renderChallengePage({ id: ID, read: { ok: false, status: 404, body: { ok: false, error: { code: "challenge_not_found", message: "no parked challenge has this id" } } }, who: OPERATOR, nowMs: NOW });
  assert.equal(missing.status, 404);
  assert.match(missing.inner, /data-error-code="challenge_not_found">The daemon did not return this parked effect \(HTTP 404\): <code>challenge_not_found<\/code> — no parked challenge has this id/u);
});

test("the list: every parked challenge linking to its page with its state and requester, the waiting count, an honest empty, and a degraded daemon", () => {
  const list = P.renderChallengeList({ read: { ok: true, status: 200, body: { challenges: [record(), record({ challenge_id: "wac_" + "f".repeat(32), state: "denied" })] } }, who: OPERATOR, nowMs: NOW });
  assert.equal(list.status, 200);
  assert.match(list.inner, new RegExp(`<tr data-ioi-challenge-row="${ID}"><td><a href="/__ioi/authority/challenges/${ID}">session-execute on session:s1</a>`, "u"));
  assert.match(list.inner, /data-ioi-challenge-count="1">1 waiting for the operator · 2 in all/u);
  assert.match(P.renderChallengeList({ read: { ok: true, status: 200, body: { challenges: [] } }, who: OPERATOR }).inner, /data-ioi-challenge-count="0">No effect is parked/u);
  assert.equal(P.renderChallengeList({ read: { ok: false, status: 503, body: { error: { code: "daemon_unavailable" } } }, who: null }).status, 503);
});

test("what a reader typed is text: an intent carrying markup is escaped everywhere it shows", () => {
  const evil = record({ published_preimage: { request_preimage: { intent: "<script>alert(1)</script>" } }, subject_ref: "<b>s</b>" });
  const r = page(evil);
  assert.doesNotMatch(r.inner, /<script>alert|<b>s<\/b>/u);
});

test("the one decision-body parser: a form or a JSON call, a same-origin return path only, and the request buffer zeroed once the passphrase is read", () => {
  const form = Buffer.from("reason=not+now&operator_passphrase=s3cret-pass&return_to=%2Fwork%2Fsessions");
  assert.deepEqual(operatorDecisionFrom(form, "application/x-www-form-urlencoded"), { isForm: true, reason: "not now", operatorPassphrase: "s3cret-pass", returnTo: "/work/sessions" });
  assert.ok(form.every((b) => b === 0), "the buffer that carried the passphrase is wiped");
  assert.equal(operatorDecisionFrom(Buffer.from("return_to=https%3A%2F%2Fevil.example"), "application/x-www-form-urlencoded").returnTo, "", "an off-site return path is dropped");
  assert.deepEqual(operatorDecisionFrom(Buffer.from(JSON.stringify({ reason: "ok", operator_passphrase: "p" })), "application/json"), { isForm: false, reason: "ok", operatorPassphrase: "p", returnTo: "" });
  assert.deepEqual(operatorDecisionFrom(Buffer.from("not json"), "application/json"), { isForm: false, reason: "", operatorPassphrase: "", returnTo: "" });
  assert.equal(FIELD, '<input type="password" name="operator_passphrase" autocomplete="off" required placeholder="operator passphrase" aria-label="Operator passphrase" data-ioi-operator-passphrase>', "the approval cards' own field, byte for byte");
});
