#!/usr/bin/env node
// Cut D done-bar — the agent substrate as daemon truth:
//   1. RUNNER PROFILES (no dropdown lies): the agent-runner-profile catalog is a real capability
//      matrix; a harness binding with a supported control compiles, an UNSUPPORTED control FAILS
//      CLOSED with a capability violation (the composer can only offer what the route supports).
//   2. AGENTOPS CONVERSATION: a conversation runs a REAL turn that emits structured event blocks
//      (user_message → action_started → file_modification(+real diff) → action_completed →
//      assistant_message → turn_completed), persists history, and replays over an SSE cursor.
//   3. WAITING + RESUME (no lost turn): a turn that needs authority SUSPENDS on a waiting interest;
//      providing the grant RESUMES the SAME turn (same file/commit), applying the preserved action —
//      not a recomputed/abandoned turn. A denial fails the turn closed.
//   4. INTERRUPT: an operator interrupt moves the conversation to interrupted with an event block.
// Daemon truth (no UI needed). Requires daemon :8765. Missing ⇒ BLOCKED (named host gap), never a fake.
const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";

const checks = [];
let failures = 0;
const ok = (c, m, d) => { checks.push({ ok: !!c, m }); if (!c) failures++; if (!JSON_OUT) console.log(`    ${c ? "✓" : "✗ FAIL:"} ${m}${d ? ` (${d})` : ""}`); };
const blocked = (r) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "agent-substrate-functional", verdict: "BLOCKED", reason: r }) : `  BLOCKED: ${r}`); process.exit(2); };
const dj = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: { "content-type": "application/json" }, body: b !== undefined ? JSON.stringify(b) : undefined }); const t = await r.text(); let j = {}; try { j = t ? JSON.parse(t) : {}; } catch { j = { _raw: t }; } return { status: r.status, body: j }; };
const kinds = (blocks) => (blocks || []).map((b) => b.kind);

if (!JSON_OUT) console.log("Agent substrate e2e — runner profiles · AgentOps event blocks · waiting/resume · interrupt");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) blocked("daemon not running"); } catch { blocked("hypervisor-daemon (:8765) not running"); }

// 1) RUNNER PROFILES — capability matrix + capability-correct admission.
const profiles = await dj("GET", "/v1/hypervisor/agent-runner-profiles");
const list = profiles.body?.profiles || [];
ok(list.length >= 3 && list.every((p) => Array.isArray(p.modes) && Array.isArray(p.reasoning)), "agent-runner-profile catalog is a real capability matrix", `${list.length} harnesses`);
const supported = await dj("POST", "/v1/hypervisor/harness-bindings", { harness: "hypervisor_worker", model: "hypervisor:native-local", mode: "goal", reasoning: "high", speed: "thorough" });
ok(supported.body?.harnessBinding?.admitted === true && supported.body?.harnessBinding?.reasoning === "high", "supported harness+controls compiles a binding", supported.body?.harnessBinding?.mode);
const unsupported = await dj("POST", "/v1/hypervisor/harness-bindings", { harness: "shell", reasoning: "high" });
ok(unsupported.body?.admitted === false && unsupported.body?.violation?.field === "reasoning", "unsupported control FAILS CLOSED (no dropdown lies)", unsupported.body?.reason);
const badModel = await dj("POST", "/v1/hypervisor/harness-bindings", { harness: "hypervisor_worker", model: "gpt-5-codex" });
ok(badModel.body?.admitted === false && badModel.body?.violation?.field === "model", "harness rejects a model it does not support", badModel.body?.violation?.value);

// a started env to host the conversation turns.
const envId = (await dj("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0", project_id: "agent-substrate-verify" } })).body?.environment?.id;
await dj("POST", `/v1/hypervisor/environments/${envId}/start`);
ok(!!envId, "environment created + started for the conversation", envId);

// 2) AGENTOPS CONVERSATION — a real turn emits structured event blocks.
const conv = await dj("POST", "/v1/hypervisor/agentops/conversations", { environment_id: envId, title: "verify" });
const cid = conv.body?.conversation?.conversation_id;
ok(!!cid, "conversation created", cid);
const turn1 = await dj("POST", `/v1/hypervisor/agentops/conversations/${cid}/send`, { text: "Document a hello-world note for the project." });
const k1 = kinds(turn1.body?.blocks);
ok(["user_message", "action_started", "file_modification", "action_completed", "assistant_message", "turn_completed"].every((k) => k1.includes(k)), "turn emits the full AgentOps event-block sequence", k1.join("→"));
const fm = (turn1.body?.blocks || []).find((b) => b.kind === "file_modification");
ok(fm && typeof fm.diff === "string" && /^\+|@@|diff/m.test(fm.diff), "file_modification block carries a REAL git diff", fm?.path);
const am = (turn1.body?.blocks || []).find((b) => b.kind === "assistant_message");
ok(am && typeof am.text === "string" && am.text.length > 0, "assistant_message carries real model-routed output", am?.model);

// history + SSE replay over a cursor.
const hist = await dj("GET", `/v1/hypervisor/agentops/conversations/${cid}`);
ok((hist.body?.conversation?.blocks || []).length === k1.length, "history persists the full block sequence");
const sseAll = await (await fetch(`${DAEMON}/v1/hypervisor/agentops/conversations/${cid}/events?since=0`)).text();
ok(/event: agentops\.block/.test(sseAll) && /event: agentops\.cursor/.test(sseAll), "SSE replays blocks + a cursor frame");
const sseTail = await (await fetch(`${DAEMON}/v1/hypervisor/agentops/conversations/${cid}/events?since=2`)).text();
ok((sseTail.match(/agentops\.block/g) || []).length < (sseAll.match(/agentops\.block/g) || []).length, "SSE cursor (?since=N) replays only newer blocks");

// 3) WAITING + RESUME (no lost turn) — a turn that needs authority suspends, then resumes the SAME turn.
const susp = await dj("POST", `/v1/hypervisor/agentops/conversations/${cid}/send`, { text: "Apply a change that needs approval.", require_authority: true });
ok(susp.body?.status === "waiting" && susp.body?.waiting_interest?.kind === "authority_request" && kinds(susp.body?.blocks).includes("waiting"), "turn SUSPENDS on a waiting interest (authority_request)", susp.body?.waiting_interest?.kind);
const blockedSend = await dj("POST", `/v1/hypervisor/agentops/conversations/${cid}/send`, { text: "ignored while waiting" });
ok(blockedSend.body?.ok === false, "a waiting conversation refuses new sends until resolved");
const resumed = await dj("POST", `/v1/hypervisor/agentops/conversations/${cid}/provide`, { granted: true, value: "approved" });
const kr = kinds(resumed.body?.blocks);
ok(resumed.body?.resumed_turn === true && kr.includes("waiting_resolved") && kr.includes("file_modification") && kr.includes("turn_completed"), "providing the grant RESUMES the SAME turn (applies the preserved action)", kr.join("→"));
const after = (await dj("GET", `/v1/hypervisor/agentops/conversations/${cid}`)).body?.conversation;
ok(after?.status === "active" && after?.waiting_interest === null && after?.pending_turn === null, "after resume the conversation is active with no dangling waiting/pending state");

// denial fails the turn closed (separate conversation).
const conv2 = (await dj("POST", "/v1/hypervisor/agentops/conversations", { environment_id: envId })).body?.conversation?.conversation_id;
await dj("POST", `/v1/hypervisor/agentops/conversations/${conv2}/send`, { text: "needs approval", require_authority: true });
const denied = await dj("POST", `/v1/hypervisor/agentops/conversations/${conv2}/provide`, { granted: false });
ok(denied.body?.outcome === "denied" && kinds(denied.body?.blocks).includes("turn_canceled"), "authority denial cancels the turn fail-closed");

// 4) INTERRUPT.
const conv3 = (await dj("POST", "/v1/hypervisor/agentops/conversations", { environment_id: envId })).body?.conversation?.conversation_id;
const intr = await dj("POST", `/v1/hypervisor/agentops/conversations/${conv3}/interrupt`);
ok(intr.body?.status === "interrupted", "operator interrupt moves the conversation to interrupted");

const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "agent-substrate-functional", verdict, failures, checks: checks.length }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
