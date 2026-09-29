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
    [record({ state: "approved", grant_ref: "grant://g1", grant_expires_at_ms: NOW - 1, ...decision("approve") }), "grant_expired", /Approved — grant expired unused; the action must be asked again/u, /approval_ref_expired\): the action must be asked again[^<]*and none has been parked yet/u],
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

// ---- R-240, challenge states + re-ask: what the decision-durability states and an expired grant read as ------------------

const DECIDING = { attempt_id: "dec_1", process: "dp_live", decided_by: "user://op", reason: "", started_at: "2026-09-28T11:58:00Z", started_at_ms: NOW - 120_000, child_pid: 4242 };
const UNKNOWN = { reason: "authority_record_unreadable", message: "the authority's record for this request hash could not be read (offline); nothing is concluded until it can be", since: "2026-09-28T11:50:00Z", checked_at: "2026-09-28T11:55:00Z",
  attempt: { attempt_id: "dec_0", process: "dp_gone", decided_by: "user://op", started_at: "2026-09-28T11:49:00Z" } };
const disabledReasonOf = (html, label) => new RegExp(`<button class="act[^"]*" type="button" disabled aria-disabled="true" data-ioi-disabled-reason="([^"]+)"[^>]*>${label}</button>`, "u").exec(html)?.[1] || null;

test("Deciding: an approve being recorded reads from the record's marker — who started it and when — with Approve and Deny disabled by that reason (the unified gap contract), no passphrase asked, and the page re-reading itself by its own GET address", () => {
  const r = page(record({ deciding: DECIDING }));
  assert.equal(r.status, 200);
  assert.match(r.inner, /data-ioi-challenge-state="deciding">Deciding — started 2026-09-28T11:58:00Z by Ada Operator</u);
  assert.match(r.inner, /data-ioi-challenge-deciding-since>2026-09-28T11:58:00Z</u);
  assert.match(r.inner, /data-ioi-challenge-deciding-by>Ada Operator <code>user:\/\/op<\/code></u);
  for (const label of ["Approve", "Deny"]) {
    const why = disabledReasonOf(r.inner, label);
    assert.ok(why && /already running \(started 2026-09-28T11:58:00Z by Ada Operator\)/u.test(why) && /refuses another decision until it settles/u.test(why), `${label}: ${why}`);
  }
  assert.doesNotMatch(r.inner, /<form|data-ioi-operator-passphrase/u, "nothing can be sent while it runs");
  assert.match(r.inner, /data-ioi-challenge-decide="deciding"/u);
  assert.ok(r.inner.includes(`<a href="/__ioi/authority/challenges/${ID}" data-ioi-challenge-reload>`), "a Reload link to the page itself");
  assert.ok(r.inner.includes(`location.replace("/__ioi/authority/challenges/${ID}")`), "the auto-refresh loads the GET address, never re-posts");
  assert.doesNotMatch(page(record()).inner, /location\.replace/u, "a plain pending page does not refresh itself");
  // deciding outranks an expiry: the daemon settles the approve whatever the ask's window
  assert.match(page(record({ deciding: DECIDING, expires_at_ms: NOW - 1 })).inner, /data-ioi-challenge-state="deciding"/u);
  // a member sees who is deciding, and still no form
  const m = page(record({ deciding: DECIDING }), MEMBER);
  assert.match(m.inner, /data-ioi-challenge-state="deciding"/u);
  assert.match(m.inner, /data-ioi-challenge-decide="not-operator"/u);
});

test("a 202 is Still deciding, never a refusal: the daemon's code and words, the record below re-read, a reload link — and the page's status is the daemon's 202", () => {
  const still = { decision: "approve", status: 202, code: "challenge_decision_still_running", message: "the deployment authority is still approving after 270000 ms; the decision continues in the daemon and settles the challenge on its own — re-read it for the outcome" };
  const r = page(record({ deciding: DECIDING }), OPERATOR, { refusal: still });
  assert.equal(r.status, 202);
  assert.match(r.inner, /role="status" data-ioi-challenge-still-deciding/u);
  assert.match(r.inner, /Still deciding — the daemon accepted this approval/u);
  assert.ok(r.inner.includes(`<code>challenge_decision_still_running</code> — <span data-ioi-challenge-refusal-message>${still.message}</span>`), "in the daemon's words");
  assert.doesNotMatch(r.inner, /data-ioi-challenge-refusal=|role="alert"|The daemon refused/u, "not rendered as a refusal");
  assert.match(r.inner, /data-ioi-challenge-state="deciding"/u, "the record, re-read, is being decided");
  // a concurrent decision's 409 IS a refusal, in the daemon's words
  const busy = page(record({ deciding: DECIDING }), OPERATOR, { refusal: { decision: "deny", status: 409, code: "challenge_decision_in_progress", message: "a decision on this challenge is already running" } });
  assert.match(busy.inner, /data-ioi-challenge-refusal="challenge_decision_in_progress"/u);
});

test("Outcome unknown: the daemon's named reason and message, Approve disabled by that name, Deny open with its reason field — and an expired one reads Closed with the unknown outcome named", () => {
  const r = page(record({ outcome_unknown: UNKNOWN }));
  assert.equal(r.status, 200);
  assert.match(r.inner, /data-ioi-challenge-state="outcome_unknown">Outcome unknown — authority_record_unreadable</u);
  assert.match(r.inner, /<code data-ioi-challenge-unknown-reason>authority_record_unreadable<\/code> — <span data-ioi-challenge-unknown-message>the authority's record for this request hash could not be read \(offline\)/u);
  assert.match(r.inner, /since 2026-09-28T11:50:00Z, last checked 2026-09-28T11:55:00Z/u);
  const why = disabledReasonOf(r.inner, "Approve");
  assert.ok(why && why.includes("(authority_record_unreadable)") && /runs nothing on a guess/u.test(why) && /Deny stays open/u.test(why), why);
  assert.doesNotMatch(r.inner, /data-ioi-operator-passphrase/u, "no passphrase is asked for an approve the daemon refuses");
  assert.ok(r.inner.includes(`action="/__ioi/authority/challenges/${ID}/deny" data-ioi-challenge-decision="deny"><input name="reason"`), "Deny stays open");
  assert.match(r.inner, /<button class="act ghost" type="submit" data-busy="Denying…">Deny<\/button>/u);
  const closed = page(record({ outcome_unknown: UNKNOWN, expires_at_ms: NOW - 1 }));
  assert.match(closed.inner, /data-ioi-challenge-state="expired"/u);
  assert.match(closed.inner, /outcome was still unknown when it closed \(<code>authority_record_unreadable<\/code>\)/u);
  assert.doesNotMatch(closed.inner, /<form/u);
});

test("the interrupted history entry: an approve a stopped daemon left with nothing recorded reads Interrupted in the history, with who started it and what the authority held", () => {
  const history = [
    { state: "expired", decision: null, closed_at: "2026-09-27T12:00:00Z" },
    { state: "interrupted", decision: null, closed_at: "2026-09-28T11:40:00Z", reconciliation: { authority_record: "absent", note: "…", attempt: { attempt_id: "dec_0", decided_by: "user://op", started_at: "2026-09-28T11:30:00Z" } } },
  ];
  const r = page(record({ history }));
  assert.match(r.inner, /<h2>Earlier asks and interrupted decisions<\/h2>/u);
  assert.match(r.inner, /<tr data-ioi-challenge-history="interrupted"><td>Interrupted<\/td><td>2026-09-28T11:40:00Z<\/td><td>none — the daemon stopped mid-approve \(started 2026-09-28T11:30:00Z by Ada Operator <code>user:\/\/op<\/code>\); the authority recorded nothing for this request hash, so the operator decides afresh<\/td><\/tr>/u);
  assert.match(r.inner, /<tr data-ioi-challenge-history="expired"><td>Expired undecided<\/td>/u);
  assert.match(page(record({ history: [history[0]] })).inner, /<h2>Earlier asks for this exact effect<\/h2>/u);
  // a decision adopted from the authority's record, and a denial made while the outcome was unknown, are named too
  const adopted = page(record({ state: "approved", grant_ref: "grant://g", grant_expires_at_ms: NOW + 60_000, decision: { decision: "approve", decided_by: "user://op", decided_at: "2026-09-28T11:45:00Z", reconciled_from: "authority_record" } }));
  assert.match(adopted.inner, /data-ioi-challenge-reconciled>adopted from the authority's own record \(authority_record\)/u);
  const denied = page(record({ state: "denied", decision: { decision: "deny", decided_by: "user://op", decided_at: "2026-09-28T11:45:00Z", outcome_unknown_at_denial: UNKNOWN } }));
  assert.match(denied.inner, /data-ioi-challenge-denied-while-unknown>an interrupted approval's outcome was unknown \(<code>authority_record_unreadable<\/code>\)/u);
});

test("an expired grant links to the successor its re-ask parked, and the successor names the ask it supersedes and the nonce its new request hash binds", () => {
  const NEXT = "wac_" + "fedcba9876543210".repeat(2);
  const old = page(record({ state: "approved", grant_ref: "grant://g1", grant_expires_at_ms: NOW - 1, superseded_by: NEXT, decision: { decision: "approve", decided_by: "user://op", decided_at: "2026-09-28T11:00:00Z" } }));
  assert.match(old.inner, /data-ioi-challenge-state="grant_expired"/u);
  assert.ok(old.inner.includes(`and has: <span data-ioi-challenge-superseded-by><a href="/__ioi/authority/challenges/${NEXT}">the new challenge</a> (<code>${NEXT}</code>)</span>.`), "links to the successor");
  assert.doesNotMatch(old.inner, /<form/u, "an expired approval is never decided again");
  const next = page(record({ challenge_id: NEXT, approval_ref: `wallet-approval-challenge://${NEXT}`, request_hash: HASH("d"), base_request_hash: HASH("b"), ask_nonce: "0f".repeat(16), supersedes: ID }));
  assert.match(next.inner, /data-ioi-challenge-state="pending"/u);
  assert.ok(next.inner.includes(`data-ioi-challenge-supersedes="${ID}">This asks the effect again: its earlier approval (<a href="/__ioi/authority/challenges/${ID}">${ID}</a>) expired unused`), "names what it supersedes");
  assert.match(next.inner, new RegExp(`data-ioi-challenge-request-hash>${HASH("d")}</code> <span class="meta">\\(a re-ask: the effect's own request hash <code data-ioi-challenge-base-request-hash>${HASH("b")}</code> \\(hypervisor\\.session\\.execute\\.request\\.v1\\) under the single-use nonce <code>${"0f".repeat(16)}</code>\\)`, "u"));
  assert.match(next.inner, /data-ioi-challenge-decision="approve">/u, "the successor is decided as a new ask");
});

test("the list names every new state in its pill, from the same record reading as the page", () => {
  const list = P.renderChallengeList({ read: { ok: true, status: 200, body: { challenges: [
    record({ deciding: DECIDING }), record({ challenge_id: "wac_" + "1".repeat(32), outcome_unknown: UNKNOWN }),
    record({ challenge_id: "wac_" + "2".repeat(32), state: "approved", grant_expires_at_ms: NOW - 1 }),
  ] } }, who: OPERATOR, nowMs: NOW });
  assert.match(list.inner, /data-ioi-challenge-state="deciding">Deciding — started 2026-09-28T11:58:00Z by Ada Operator</u);
  assert.match(list.inner, /data-ioi-challenge-state="outcome_unknown">Outcome unknown — authority_record_unreadable</u);
  assert.match(list.inner, /data-ioi-challenge-state="grant_expired">Approved — grant expired unused; the action must be asked again</u);
  assert.match(list.inner, /data-ioi-challenge-count="0">0 waiting for the operator · 3 in all/u, "none of them waits on the operator's approve");
});
