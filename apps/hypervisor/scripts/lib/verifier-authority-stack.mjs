// verifier-authority-stack — a verifier's own isolated stack whose daemon takes its grants from a sealed
// deployment-local wallet.network authority of the verifier's own (R-240, provider adapters on an authority stack,
// 2026-09-29).
//
// Two contracts moved under the provider verifiers: a provider-ops write names its owner and an idempotency key (400
// mutation_owner_ref_required otherwise), and a grant-gated provider or storage crossing needs a configured authority
// principal — a test-signer grant (scripts/lib/mint-approval-grant.mjs) is no authority any more (501
// provider_operation_authority_required). 1c3ec65eb met both for the filecoin custody verifier; this is that code once,
// for every verifier that crosses:
//
//   - authorityVerifierStack({ label }) brings up a sealed authority node in a temp state dir (a passphrase unique to the
//     run, never in a file or an argument), then verifierStack({ serve, fresh }) with the node's daemon/serve env and the
//     test signer off. stop() stops the stack, then the node (its shutdown file, then its process), then removes the
//     state dir — only the dir this helper created.
//   - owned(body) names the owner (the operator's org://) and an idempotency key on a write: one logical op, one key —
//     the challenged call and its granted retry carry the same body, so the same key.
//   - approve(refused) is the operator's act on a parked crossing: the daemon's decision route runs the authority's
//     `approve` with the passphrase and answers the approval_ref the retry names (null when nothing parked). A decision
//     the daemon refuses is kept in decisionRefusals (e.g. 409 challenge_consumed, when an identical crossing re-parks a
//     challenge an earlier retry consumed — a daemon finding, reported, never worked around).
//   - crossing(route, body) is the product's own ask: the ungranted call; on a 403 that parked a challenge, the
//     operator's approval; then the retry naming the approval_ref (wallet_approval_grant). Any other answer returns as is.
//
// Exit 2 (BLOCKED): no authority binary, or the node never became ready (and the daemon-binary refusals verifierStack
// makes). IOI_WALLET_AUTHORITY_BINARY overrides the node binary; a sealed bring-up starts a chain, so it takes minutes.

import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { refuseOwnerPath, verifierStack } from "./verifier-stack.mjs";
import { DEFAULT_BINARY, OPERATOR_PASS_ENV, startLocalAuthority } from "./wallet-network-local-authority.mjs";

const blocked = (why) => { console.error(`BLOCKED: ${why}`); process.exit(2); };

export async function authorityVerifierStack({ label, serve = true, fresh = true, env = {}, serveEnv = {} } = {}) {
  if (!/^[a-z0-9][a-z0-9-]*$/u.test(String(label || ""))) throw new Error("authorityVerifierStack needs a label (lowercase, dashes)");
  const binary = process.env.IOI_WALLET_AUTHORITY_BINARY || DEFAULT_BINARY;
  if (!existsSync(binary)) blocked(`no wallet-network authority binary (${binary}) — cargo build -p ioi-cli --bin wallet-network-local-authority`);
  const operatorPass = `${label}-${randomBytes(12).toString("hex")}`;
  const stateDir = mkdtempSync(path.join(refuseOwnerPath(tmpdir(), "temp root"), `ioi-${label}-authority-`));
  // the ambient passphrase never reaches this process's children; the node takes the run's own, once, at bring-up
  delete process.env[OPERATOR_PASS_ENV];
  let authority = null;
  const dropAuthority = async () => {
    try { await authority?.stop(); } catch { /* gone */ }
    try { rmSync(stateDir, { recursive: true, force: true }); } catch { /* keep */ }
  };
  let stack = null;
  let stopped = false;
  const stopAll = async () => {
    if (stopped) return;
    stopped = true;
    try { await stack?.stop(); } finally { await dropAuthority(); }
  };
  // A run killed from outside (a timeout's SIGTERM, ^C) exits without running 'exit' handlers: stop the stack and the
  // node first — from the node's bring-up on — or its chain keeps burning CPU after the verifier is gone.
  for (const signal of ["SIGTERM", "SIGINT"]) process.once(signal, () => { stopAll().finally(() => process.exit(128 + (signal === "SIGTERM" ? 15 : 2))); });
  try {
    authority = await startLocalAuthority({ stateDir, principalRef: `domain://${label}`, binary, operatorPass, log: () => {} });
  } catch (error) {
    await dropAuthority();
    blocked(`the local authority node never became ready: ${String(error.message).split("\n")[0]}`);
  }
  try {
    stack = await verifierStack({ serve, fresh, env: { ...authority.daemonEnv, IOI_WALLET_TEST_SIGNER: "", ...env }, serveEnv: { ...authority.serveEnv, ...serveEnv } });
  } catch (error) {
    await dropAuthority();
    throw error;
  }
  const daemonUrl = stack.daemonUrl;
  const post = async (route, body) => {
    const r = await fetch(`${daemonUrl}${route}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    return { status: r.status, j: await r.json().catch(() => ({})) };
  };
  let seq = 0;
  const decisionRefusals = [];
  const approvals = [];
  async function approve(refused, reason = `${label} verifier`) {
    const id = refused?.j?.approval_challenge?.challenge_id;
    if (!id) return null;
    const decided = await post(`/v1/hypervisor/authority/challenges/${encodeURIComponent(id)}/decision`, { decision: "approve", reason, operator_passphrase: operatorPass });
    if (decided.j?.approval_ref && decided.status === 200) { approvals.push(id); return decided.j.approval_ref; }
    decisionRefusals.push({ challenge_id: id, op: refused.j?.op || refused.j?.approval_challenge?.operation || null, status: decided.status, code: decided.j?.error?.code || decided.j?.code || null });
    return null;
  }
  return {
    stack,
    daemonUrl,
    serveUrl: stack.serveUrl,
    owner: stack.owner,
    authority,
    /** The decision refusals the daemon answered (status + code), in order. */
    decisionRefusals,
    /** How many crossings the operator approved. */
    get approvedCount() { return approvals.length; },
    /** A write that names its owner and an idempotency key (the key given, else a fresh one for this run). */
    owned(body, key = null) {
      return { owner_ref: stack.owner, idempotency_key: key || `${label}-${++seq}`, ...body };
    },
    approve,
    /** The product's own ask: the ungranted call, the operator's approval of what it parked, the retry naming it. */
    async crossing(route, body, reason) {
      const first = await post(route, body);
      if (first.status !== 403) return first;
      const grant = await approve(first, reason);
      if (!grant) return first;
      return post(route, { ...body, wallet_approval_grant: grant });
    },
    stop: stopAll,
  };
}
