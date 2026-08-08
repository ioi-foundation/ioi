#!/usr/bin/env node
// INV-37 evidence-provenance gate for daemon route handlers.
//
// INV-37 (docs/architecture/foundations/invariants.md): admission evidence is
// RESOLVED by the server, never ASSERTED by the caller. Thirteen hand-fixed
// violations landed in one week before this gate existed — reviewer identity
// copied from caller input (e7deb8ca4, c639bba45), authorization running after
// the record read (bc73b5b20), tenant scope re-derived instead of carried from
// the admitted session (6044adb93), guardrail mutations admitted by nobody
// (a3470443a). Each rule below names the commit whose BEFORE state it would
// have caught.
//
// A hit is a LEAD REQUIRING A READING, not automatically a defect — the
// MEF-GAP-001 lesson. The gate is therefore a RATCHET: every current lead is
// pinned below with a disposition (`sanctioned` with justification, or
// `open_lead` awaiting its W1.2-class reading), and --check fails only when a
// NEW site appears or a pinned site disappears (stale pin — re-derive, then
// re-pin). It never certifies the pinned leads as correct.
//
//   node scripts/audit-admission-evidence-provenance.mjs           # JSON report
//   node scripts/audit-admission-evidence-provenance.mjs --check   # ratchet gate
//
// Rules (production spans only; every #[cfg(test)] mod is excluded by
// brace-matched span, because lifecycle_routes.rs interleaves four test mods
// with production code — truncating at the first would blind the gate):
//   A  a WHO-attribution key read from a request container            (e7deb8ca4, c639bba45)
//      exempt: presence-check refusals (.is_none()/.is_some()) and fns named
//      reject_*/refuse_*/prohibit_* — the sanctioned gate shape itself
//   B  an attribution key inside a body->record copy key-list         (c639bba45 patch)
//   C  nullable attribution written into a record via unwrap_or(Null) (e7deb8ca4 receipt)
//   D  constant or defaulted principal attribution                    (abc199662, a3470443a class)
//   E  record read before identity resolution in a mutating handler   (bc73b5b20)
//   F  a parallel identity resolver outside the canonical seam files  (6044adb93 class)
//   G  identity-envelope header literals in production                 (generalizes the two
//      in-file self-checks in managed_runtime_routes.rs / foundry_execution_routes.rs)
//   H  census: mutating handlers with no in-handler identity/authority call.
//      The daemon's inbound auth middleware covers /v1/* when enforcement is on,
//      so this is a pinned baseline (the known MEF-GAP-008 legacy surface), not
//      a per-handler verdict. Fails only on growth or on a vanished baseline name.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const routeDir = path.join(root, "crates", "node", "src", "bin", "hypervisor_daemon_routes");
const check = process.argv.includes("--check");

// ------------------------------------------------------------------ scanning

// Blank comment spans only, tracking strings so `//` inside a literal is kept.
// Strings are PRESERVED — rules A-D and G match string content.
function blankComments(source) {
  const out = source.split("");
  const blank = (from, to) => {
    for (let j = from; j < to && j < out.length; j += 1) if (out[j] !== "\n") out[j] = " ";
  };
  let i = 0;
  while (i < source.length) {
    const two = source.slice(i, i + 2);
    if (two === "//") {
      const end = source.indexOf("\n", i);
      const stop = end === -1 ? source.length : end;
      blank(i, stop);
      i = stop;
    } else if (two === "/*") {
      const end = source.indexOf("*/", i + 2);
      const stop = end === -1 ? source.length : end + 2;
      blank(i, stop);
      i = stop;
    } else if (/^r#*"/u.test(source.slice(i, i + 8))) {
      const hashes = /^r(#*)"/u.exec(source.slice(i, i + 8))[1];
      const terminator = `"${hashes}`;
      const end = source.indexOf(terminator, i + hashes.length + 2);
      i = end === -1 ? source.length : end + terminator.length;
    } else if (source[i] === "'" && /^'(?:\\.|[^\\'])'/u.test(source.slice(i, i + 5))) {
      i += /^'(?:\\.|[^\\'])'/u.exec(source.slice(i, i + 5))[0].length;
    } else if (source[i] === '"') {
      let j = i + 1;
      while (j < source.length) {
        if (source[j] === "\\") j += 2;
        else if (source[j] === '"') break;
        else j += 1;
      }
      i = j + 1;
    } else {
      i += 1;
    }
  }
  return out.join("");
}

// Additionally blank string CONTENTS — for call-order scans (rules E, H).
function blankStrings(commentless) {
  const out = commentless.split("");
  let i = 0;
  const blank = (from, to) => {
    for (let j = from; j < to && j < out.length; j += 1) if (out[j] !== "\n") out[j] = " ";
  };
  while (i < commentless.length) {
    if (/^r#*"/u.test(commentless.slice(i, i + 8))) {
      const hashes = /^r(#*)"/u.exec(commentless.slice(i, i + 8))[1];
      const terminator = `"${hashes}`;
      const end = commentless.indexOf(terminator, i + hashes.length + 2);
      const stop = end === -1 ? commentless.length : end + terminator.length;
      blank(i, stop);
      i = stop;
    } else if (commentless[i] === "'" && /^'(?:\\.|[^\\'])'/u.test(commentless.slice(i, i + 5))) {
      const width = /^'(?:\\.|[^\\'])'/u.exec(commentless.slice(i, i + 5))[0].length;
      blank(i, i + width);
      i += width;
    } else if (commentless[i] === '"') {
      let j = i + 1;
      while (j < commentless.length) {
        if (commentless[j] === "\\") j += 2;
        else if (commentless[j] === '"') break;
        else j += 1;
      }
      blank(i + 1, j);
      i = j + 1;
    } else {
      i += 1;
    }
  }
  return out.join("");
}

function braceSpanEnd(code, openIndex) {
  let depth = 0;
  for (let i = openIndex; i < code.length; i += 1) {
    if (code[i] === "{") depth += 1;
    else if (code[i] === "}") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return code.length;
}

// Every #[cfg(test)] mod span, brace-matched; production code between them stays.
function testSpans(code) {
  const spans = [];
  const marker = /#\[cfg\(test\)\]/gu;
  let m;
  while ((m = marker.exec(code)) !== null) {
    const open = code.indexOf("{", m.index);
    if (open === -1) continue;
    spans.push([m.index, braceSpanEnd(code, open)]);
    marker.lastIndex = spans[spans.length - 1][1];
  }
  return spans;
}

const blankSpans = (code, spans) => {
  const out = code.split("");
  for (const [from, to] of spans) {
    for (let j = from; j <= to && j < out.length; j += 1) if (out[j] !== "\n") out[j] = " ";
  }
  return out.join("");
};

const lineOf = (src, off) => src.slice(0, off).split("\n").length;

function enclosingFn(code, offset) {
  const before = code.slice(0, offset);
  const m = before.match(/(?:^|\n)\s*(?:pub(?:\(crate\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)\s*\([^\n]*$/u)
    ?? [...before.matchAll(/fn\s+([A-Za-z0-9_]+)\s*\(/gu)].pop();
  return m ? m[1] : "";
}

// ------------------------------------------------------------------ rule regexes

const WHO_KEYS =
  "actor|actor_ref|requested_by|reviewer|reviewer_ref|approved_by|approver|decided_by|changed_by|changed_by_principal_ref|acting_principal_ref|principal_ref|is_impersonated|impersonator|on_behalf_of|caller_ref";
const RULE_A = new RegExp(
  `\\b(?:body|payload|patch|req|request|params|form)\\s*(?:\\.get\\(|\\[)\\s*"(${WHO_KEYS})"`,
  "gu",
);
const RULE_B = new RegExp(
  `for\\s+\\w+\\s+in\\s+\\[[^\\]]*"(reviewer_ref|reviewer|actor_ref|acting_principal_ref|approved_by|changed_by_principal_ref|principal_ref|is_impersonated)"`,
  "gu",
);
const RULE_C = new RegExp(
  `"(reviewer_ref|acting_principal_ref|actor_ref|approved_by|changed_by_principal_ref)"\\s*:\\s*[^,}\\n]*unwrap_or\\(Value::Null\\)`,
  "gu",
);
const RULE_D_LITERAL = new RegExp(
  `"(reviewer_ref|actor_ref|acting_principal_ref|approved_by|changed_by_principal_ref|requesting_principal_ref)"\\s*:\\s*"(?:user|principal|agent)://`,
  "gu",
);
const RULE_D_DEFAULT =
  /unwrap_or(?:_else)?\(\s*(?:\|\|\s*)?"(user:\/\/local-operator|principal:\/\/operator|operator|unattributed|anonymous)"/gu;
const RULE_D_CONTEXT = /(principal|caller|actor|reviewer|subject|owner|requested_by|user_ref)/iu;
const RULE_F_HEADER =
  /headers\s*\.\s*get\s*\(\s*(?:"(?:authorization|cookie)"|(?:axum::http::)?header::(?:AUTHORIZATION|COOKIE))/gu;
const RULE_F_RESOLVER = /resolve_principal_tenant_refs\s*\(/gu;
const RULE_G = /x-ioi-principal|x-forwarded-user/gu;

const SEAM_FILES = new Set(["lifecycle_routes.rs", "portal_session_exchange_routes.rs"]);
const IDENTITY =
  /\b(resolve_request_identity|require_write_caller|require_authenticated_org_admin|require_authenticated_principal|require_authenticated_admin|resolve_governance_reviewer|prepare_approval_patch_identity|resolve_principal|bind_request_resource_scope|authorize_scope)\s*\(/gu;
const RECORD_READ =
  /\b(load|load_record|read_record_dir|find_by_key|read_owner_scoped_head|read_owner_scoped_history)\s*\(/gu;
const MUTATION =
  /\b(persist_record|persist_record_durable|remove_record|admit_owner_scoped_write|unlink_durable(?:_at)?|(?:std::)?fs::(?:write|remove_file|remove_dir_all|rename|create_dir_all))\s*\(/gu;

// ------------------------------------------------------------------ pinned dispositions
// Keyed file + rule + match key; `count` pins how many such sites exist today.
// `sanctioned` = read, judged INV-37-compliant, justification recorded.
// `open_lead`  = violation-shaped, awaiting its handler-level reading; pinning
//                it here neither closes nor excuses it — it stops the bleeding
//                by making every NEW site red.
const PINNED = [
  {"file": "lifecycle_routes.rs", "rule": "B", "key": "is_impersonated", "count": 1, "disposition": "sanctioned", "justification": "W1.2 2026-08-08: this is resolve_acting_principal_ref's REFUSAL list, not a body->record copy \u2014 it is the gate that ENFORCES INV-37 (refuses any caller-supplied WHO field incl. is_impersonated), the opposite of a violation"},
  {"file": "lifecycle_routes.rs", "rule": "D", "key": "user://local-operator", "count": 7, "disposition": "sanctioned", "justification": "W1.2 2026-08-08 all read: 1 canonical resolver local-dev lane (hypervisor_request_identity :6012), 1 new resolve_acting_principal_ref local-dev fallback (both the sanctioned unauthenticated lane), and 5 stored-session absent-owner_ref legacy defaults \u2014 under enforcement session_request_owner yields user://usr_* or the OPERATOR UUID so a defaulted record equals NO authenticated principal (legacy records invisible/unmodifiable = fail-closed); load-bearing only in the local-dev seed lane, not an impersonation surface"},
  {"file": "orchestration_routes.rs", "rule": "F", "key": "auth-header", "count": 1, "disposition": "sanctioned", "justification": "read 2026-08-08: webhook delivery authenticates by a per-automation rotated trigger token (x-ioi-trigger-token / Bearer) compared against the stored secret \u2014 a presented capability, not a principal resolver"},
  {"file": "portal_session_exchange_routes.rs", "rule": "F", "key": "tenant-resolver", "count": 1, "disposition": "sanctioned", "justification": "read 2026-08-08: session-mint seam delegates to the canonical lifecycle_routes resolver to snapshot full membership INTO the session record (the projection later requests narrow FROM); it does not re-derive scope on a later request"},
  {"file": "supervisor_routes.rs", "rule": "F", "key": "auth-header", "count": 1, "disposition": "sanctioned", "justification": "read 2026-08-08: bearer() extracts a capability-lease token adjudicated against the durable authority-grants record (lease_binds_env) \u2014 a presented grant independently verified, not a principal resolver"},
];

// Rule H baseline: mutating handlers with no in-handler identity/authority
// call — the middleware-covered legacy surface. Growth is red.
const H_BASELINE = [
  "authority_routes.rs::handle_authority_grant",
  "authority_routes.rs::handle_authority_revoke",
  "authority_routes.rs::handle_harness_binding_create",
  "binding_routes.rs::handle_binding_create",
  "binding_routes.rs::handle_env_files",
  "binding_routes.rs::handle_terminal_create",
  "capability_lease_plan_routes.rs::handle_plan_create",
  "capability_lease_plan_routes.rs::handle_plan_delete",
  "capability_lease_plan_routes.rs::handle_plan_patch",
  "capability_lease_plan_routes.rs::handle_plan_revoke",
  "connector_execution_routes.rs::handle_run_execute",
  "connector_execution_routes.rs::handle_set_delete",
  "connector_mapping_routes.rs::handle_connector_mapping_create",
  "connector_mapping_routes.rs::handle_connector_mapping_delete",
  "connector_mapping_routes.rs::handle_connector_mapping_patch",
  "connector_session_routes.rs::handle_session_cancel",
  "connector_session_routes.rs::handle_session_create",
  "connector_session_routes.rs::handle_session_delete",
  "connector_session_routes.rs::handle_session_open",
  "connector_session_routes.rs::handle_session_patch",
  "connector_session_routes.rs::handle_session_release",
  "decentralized_cloud_routes.rs::handle_intent_create",
  "editor_routes.rs::handle_editor_service_create",
  "editor_routes.rs::handle_provisioning_plan_create",
  "environment_routes.rs::handle_agent_run_upsert",
  "environment_routes.rs::handle_env_config",
  "environment_routes.rs::handle_env_pr_draft",
  "environment_routes.rs::handle_environment_action",
  "environment_routes.rs::handle_environment_classes",
  "environment_routes.rs::handle_project_delete",
  "environment_routes.rs::handle_snapshot_restore",
  "environment_routes.rs::handle_workrun_create",
  "environment_routes.rs::handle_workrun_execute",
  "environment_routes.rs::handle_workspace_exec",
  "eval_suite_routes.rs::handle_eval_suite_create",
  "eval_suite_routes.rs::handle_eval_suite_delete",
  "eval_suite_routes.rs::handle_eval_suite_patch",
  "feedback_routes.rs::handle_feedback_create",
  "feedback_routes.rs::handle_feedback_delete",
  "feedback_routes.rs::handle_feedback_patch",
  "foundry_routes.rs::handle_foundry_run_plan_create",
  "foundry_routes.rs::handle_foundry_run_plan_delete",
  "foundry_routes.rs::handle_foundry_spec_create",
  "foundry_routes.rs::handle_foundry_spec_delete",
  "foundry_routes.rs::handle_foundry_spec_patch",
  "goalrun_routes.rs::handle_goal_run_lifecycle_recovery",
  "goalrun_routes.rs::handle_goal_run_outcome_delta_create",
  "goalrun_routes.rs::handle_goal_run_reconcile",
  "goalrun_routes.rs::handle_goal_run_result_create",
  "goalrun_routes.rs::handle_goal_run_start",
  "governance_routes.rs::handle_approval_create",
  "governance_routes.rs::handle_cohort_create",
  "governance_routes.rs::handle_cohort_patch",
  "governance_routes.rs::handle_gate_create",
  "governance_routes.rs::handle_gate_patch",
  "governance_routes.rs::handle_kill_create",
  "governance_routes.rs::handle_kill_patch",
  "governance_routes.rs::handle_release_create",
  "governance_routes.rs::handle_release_patch",
  "ioi_agent_routes.rs::handle_ioi_agent_launch",
  "ioi_agent_routes.rs::handle_policies_clone",
  "ioi_agent_routes.rs::handle_policies_create",
  "ioi_agent_routes.rs::handle_policies_delete",
  "ioi_agent_routes.rs::handle_policies_patch",
  "ioi_agent_routes.rs::handle_policy_rollout_promote",
  "ioi_agent_routes.rs::handle_policy_rollout_rollback",
  "ioi_intelligence_routes.rs::handle_improvement_patch",
  "ioi_intelligence_routes.rs::handle_improvement_simulate",
  "ioi_intelligence_routes.rs::handle_improvements_create",
  "ioi_intelligence_routes.rs::handle_proposal_approve",
  "ioi_intelligence_routes.rs::handle_proposal_reject",
  "ioi_intelligence_routes.rs::handle_proposals_create",
  "ioi_intelligence_routes.rs::handle_spaces_create",
  "ioi_intelligence_routes.rs::handle_vault_import",
  "lifecycle_routes.rs::handle_agent_create",
  "lifecycle_routes.rs::handle_approval_request",
  "lifecycle_routes.rs::handle_artifact_create",
  "lifecycle_routes.rs::handle_auth_bootstrap",
  "lifecycle_routes.rs::handle_auth_logout",
  "lifecycle_routes.rs::handle_auth_oidc_callback",
  "lifecycle_routes.rs::handle_auth_oidc_start",
  "lifecycle_routes.rs::handle_budget_reconcile",
  "lifecycle_routes.rs::handle_compact",
  "lifecycle_routes.rs::handle_connector_bind_credential",
  // "lifecycle_routes.rs::handle_connector_delete" — LEFT the baseline 2026-08-08 (W1.5):
  // the handler now resolves an authenticated org admin and refuses discarded removals; the
  // vanishing entry is the ratchet improving, not a stale pin.
  "lifecycle_routes.rs::handle_connector_device_poll",
  "lifecycle_routes.rs::handle_connector_device_start",
  "lifecycle_routes.rs::handle_connector_oauth_callback",
  "lifecycle_routes.rs::handle_connector_oauth_discover",
  "lifecycle_routes.rs::handle_connector_oauth_start",
  "lifecycle_routes.rs::handle_connector_register",
  "lifecycle_routes.rs::handle_connector_revoke_credential",
  "lifecycle_routes.rs::handle_connector_set_policy",
  "lifecycle_routes.rs::handle_conversation_artifact_create",
  "lifecycle_routes.rs::handle_custom_domain_set",
  "lifecycle_routes.rs::handle_domain_verification_create",
  "lifecycle_routes.rs::handle_domain_verification_delete",
  "lifecycle_routes.rs::handle_domain_verification_verify",
  "lifecycle_routes.rs::handle_github_app_conversion",
  "lifecycle_routes.rs::handle_github_app_installation",
  "lifecycle_routes.rs::handle_oidc_set",
  "lifecycle_routes.rs::handle_org_invite_accept",
  "lifecycle_routes.rs::handle_preference_put",
  "lifecycle_routes.rs::handle_project_create",
  "lifecycle_routes.rs::handle_runtime_host_session",
  "lifecycle_routes.rs::handle_scim_group_create",
  "lifecycle_routes.rs::handle_scim_group_delete",
  "lifecycle_routes.rs::handle_scim_group_patch",
  "lifecycle_routes.rs::handle_scim_user_create",
  "lifecycle_routes.rs::handle_scim_user_delete",
  "lifecycle_routes.rs::handle_scim_user_patch",
  "lifecycle_routes.rs::handle_scm_abandon_pull_request",
  "lifecycle_routes.rs::handle_scm_connect_github",
  "lifecycle_routes.rs::handle_scm_connector_bind_credential",
  "lifecycle_routes.rs::handle_scm_connector_register",
  "lifecycle_routes.rs::handle_scm_connector_revoke_credential",
  "lifecycle_routes.rs::handle_secret_create",
  "lifecycle_routes.rs::handle_secret_delete",
  "lifecycle_routes.rs::handle_secret_update_value",
  "lifecycle_routes.rs::handle_snapshot_capture",
  "lifecycle_routes.rs::handle_subagent_spawn",
  "lifecycle_routes.rs::handle_thread_cancel",
  "lifecycle_routes.rs::handle_thread_create",
  "lifecycle_routes.rs::handle_thread_delete",
  "lifecycle_routes.rs::handle_workflow_edit_apply",
  "lifecycle_routes.rs::handle_workflow_edit_propose",
  "managed_runtime_routes.rs::handle_backup_export",
  "materializing_run_routes.rs::handle_mrun_acquire_lease",
  "materializing_run_routes.rs::handle_mrun_cancel",
  "materializing_run_routes.rs::handle_mrun_create",
  "materializing_run_routes.rs::handle_mrun_delete",
  "materializing_run_routes.rs::handle_mrun_patch",
  "materializing_run_routes.rs::handle_mrun_release_lease",
  "model_routes.rs::handle_model_route_bind_session",
  "model_routes.rs::handle_model_route_create",
  "model_routes.rs::handle_model_route_delete",
  "odk_routes.rs::handle_odk_descriptor_delete",
  "ontology_projection_routes.rs::handle_projection_create",
  "ontology_projection_routes.rs::handle_projection_delete",
  "ontology_projection_routes.rs::handle_projection_patch",
  "ontology_projection_routes.rs::handle_projection_recheck",
  "ontology_projection_routes.rs::handle_projection_retire",
  "orchestration_routes.rs::handle_automation_cancel",
  "orchestration_routes.rs::handle_automation_create",
  "orchestration_routes.rs::handle_automation_delete",
  "orchestration_routes.rs::handle_automation_patch",
  "orchestration_routes.rs::handle_automation_start",
  "orchestration_routes.rs::handle_automation_webhook",
  "orchestration_routes.rs::handle_placement_resolve",
  "orchestration_routes.rs::handle_venue_policy_put",
  "orchestration_routes.rs::handle_warm_pool_claim",
  "orchestration_routes.rs::handle_warm_pool_create",
  "placement_failover_routes.rs::handle_failover_plan_create",
  "provider_routes.rs::handle_provider_account_create",
  "provider_routes.rs::handle_provider_account_credential",
  "provider_routes.rs::handle_provider_account_credential_revoke",
  "provider_routes.rs::handle_provider_account_delete",
  "provider_routes.rs::handle_provider_account_patch",
  "provider_routes.rs::handle_provider_account_preflight",
  "provider_routes.rs::handle_provider_op",
  "resource_routes.rs::handle_allocate",
  "resource_routes.rs::handle_budget_create",
  "resource_routes.rs::handle_catchup",
  "resource_routes.rs::handle_pool_create",
  "resource_routes.rs::handle_release",
  "state_machine_routes.rs::handle_state_machine_create",
  "state_machine_routes.rs::handle_state_machine_delete",
  "state_machine_routes.rs::handle_state_machine_patch",
  "storage_backend_routes.rs::handle_storage_backend_create",
  "storage_backend_routes.rs::handle_storage_backend_credential",
  "storage_backend_routes.rs::handle_storage_backend_patch",
  "storage_backend_routes.rs::handle_storage_backend_preflight",
  "supervisor_routes.rs::handle_environment_ops",
  "transformation_run_routes.rs::handle_run_cancel",
  "transformation_run_routes.rs::handle_run_create",
  "transformation_run_routes.rs::handle_run_delete",
  "transformation_run_routes.rs::handle_run_dry_run",
  "transformation_run_routes.rs::handle_run_patch",
];

// ------------------------------------------------------------------ scan

const findings = [];
const hCensus = [];

const files = fs
  .readdirSync(routeDir)
  .filter((name) => name.endsWith(".rs"))
  .sort();

for (const name of files) {
  const raw = fs.readFileSync(path.join(routeDir, name), "utf8");
  const commentless = blankComments(raw);
  const tests = testSpans(blankStrings(commentless));
  const codeStrings = blankSpans(commentless, tests); // strings kept, tests+comments blanked
  const codeBlank = blankSpans(blankStrings(commentless), tests); // strings also blanked

  const add = (rule, at, key, note) =>
    findings.push({ file: name, rule, line: lineOf(raw, at), key, fn: enclosingFn(codeBlank, at), note });

  for (const m of codeStrings.matchAll(RULE_A)) {
    const stmtEnd = codeStrings.indexOf(";", m.index);
    const stmt = codeStrings.slice(m.index, stmtEnd === -1 ? m.index + 400 : stmtEnd);
    const fn = enclosingFn(codeBlank, m.index);
    if (/\.is_(?:none|some)\(\)/u.test(stmt) || /^(reject|refuse|prohibit)_/u.test(fn)) continue;
    add("A", m.index, m[1], "WHO-attribution key read from request input");
  }
  for (const m of codeStrings.matchAll(RULE_B)) add("B", m.index, m[1], "attribution key in body->record copy list");
  for (const m of codeStrings.matchAll(RULE_C)) add("C", m.index, m[1], "nullable attribution via unwrap_or(Value::Null)");
  for (const m of codeStrings.matchAll(RULE_D_LITERAL)) add("D", m.index, m[1], "attribution key assigned a literal principal URI");
  for (const m of codeStrings.matchAll(RULE_D_DEFAULT)) {
    const back = codeStrings.slice(Math.max(0, m.index - 200), m.index);
    if (RULE_D_CONTEXT.test(back)) add("D", m.index, m[1], "principal-valued expression defaulted to a constant");
  }
  if (!SEAM_FILES.has(name)) {
    for (const m of codeStrings.matchAll(RULE_F_HEADER)) add("F", m.index, "auth-header", "direct authorization/cookie read outside the canonical seam");
  }
  if (name !== "lifecycle_routes.rs") {
    for (const m of codeStrings.matchAll(RULE_F_RESOLVER)) add("F", m.index, "tenant-resolver", "parallel tenant-scope resolution outside lifecycle_routes");
  }
  for (const m of codeStrings.matchAll(RULE_G)) add("G", m.index, m[0], "identity-envelope header literal in production");

  // Rules E and H over handler spans.
  const signature = /pub\(crate\)\s+async\s+fn\s+(handle_[A-Za-z0-9_]*)\s*\(/gu;
  let sig;
  while ((sig = signature.exec(codeBlank)) !== null) {
    const open = codeBlank.indexOf("{", sig.index);
    if (open === -1) continue;
    const end = braceSpanEnd(codeBlank, open);
    const inSpan = (re) => {
      re.lastIndex = 0;
      const hits = [];
      let m;
      while ((m = re.exec(codeBlank)) !== null) if (m.index >= open && m.index < end) hits.push(m);
      return hits;
    };
    const ids = inSpan(IDENTITY);
    const muts = inSpan(MUTATION);
    if (muts.length === 0) continue;
    if (ids.length === 0) {
      hCensus.push(`${name}::${sig[1]}`);
      continue;
    }
    const reads = inSpan(RECORD_READ);
    if (reads.length > 0 && reads[0].index < ids[0].index) {
      findings.push({
        file: name,
        rule: "E",
        line: lineOf(raw, sig.index),
        key: sig[1],
        fn: sig[1],
        note: `record read (${reads[0][1]} @L${lineOf(raw, reads[0].index)}) precedes identity resolution (${ids[0][1]} @L${lineOf(raw, ids[0].index)})`,
      });
    }
  }
}

// ------------------------------------------------------------------ ratchet

const keyOf = (f) => `${f.file}|${f.rule}|${f.key}`;
const counts = new Map();
for (const f of findings) counts.set(keyOf(f), (counts.get(keyOf(f)) ?? 0) + 1);

const pinnedKeys = new Map(PINNED.map((p) => [`${p.file}|${p.rule}|${p.key}`, p]));
const newSites = [];
const staleSites = [];
for (const [key, count] of counts) {
  const pin = pinnedKeys.get(key);
  if (!pin) newSites.push({ key, count });
  else if (count > pin.count) newSites.push({ key, count, pinned: pin.count });
}
for (const [key, pin] of pinnedKeys) {
  const count = counts.get(key) ?? 0;
  if (count === 0) staleSites.push({ key });
  else if (count < pin.count) staleSites.push({ key, count, pinned: pin.count });
}
const hSet = new Set(H_BASELINE);
const hNew = hCensus.filter((h) => !hSet.has(h)).sort();
const hGone = H_BASELINE.filter((h) => !hCensus.includes(h)).sort();

const report = {
  schema_version: "ioi.hypervisor.admission-evidence-provenance.v1",
  method:
    "Rules A-G scan production spans of hypervisor_daemon_routes/*.rs (comments and every brace-matched #[cfg(test)] mod blanked; string literals preserved for key rules, blanked for call-order rules). Rule E orders the first record read against the first identity-seam call per mutating handler. Every finding is a lead requiring a reading, not a defect count; pinned dispositions record the reading that was done or still owed.",
  totals: {
    files: files.length,
    findings: findings.length,
    pinned: PINNED.length,
    new_sites: newSites.length,
    stale_pins: staleSites.length,
    h_census: hCensus.length,
    h_baseline: H_BASELINE.length,
    h_new: hNew.length,
    h_gone: hGone.length,
  },
  new_sites: newSites,
  stale_pins: staleSites,
  h_new: hNew,
  h_gone: hGone,
  findings: findings.sort((a, b) => keyOf(a).localeCompare(keyOf(b)) || a.line - b.line),
};

if (!check) {
  console.log(JSON.stringify(report, null, 2));
  process.exit(0);
}

const problems = [];
if (newSites.length > 0)
  problems.push(
    `${newSites.length} NEW evidence-provenance site(s) beyond the pinned set: ${newSites
      .map((s) => `${s.key} (${s.count}${s.pinned !== undefined ? ` > pinned ${s.pinned}` : ""})`)
      .join("; ")} — read each site; either fix it to resolve identity server-side or pin it with an explicit disposition.`,
  );
if (staleSites.length > 0)
  problems.push(
    `${staleSites.length} stale pin(s) no longer match the tree: ${staleSites.map((s) => s.key).join("; ")} — re-derive and re-pin.`,
  );
if (hNew.length > 0)
  problems.push(
    `${hNew.length} mutating handler(s) with no in-handler identity/authority call beyond the pinned baseline: ${hNew.join(", ")} — resolve identity in the handler or pin with justification.`,
  );
if (hGone.length > 0)
  problems.push(`${hGone.length} baseline handler(s) vanished: ${hGone.join(", ")} — re-pin the baseline.`);

if (problems.length > 0) {
  for (const p of problems) console.error(p);
  process.exitCode = 1;
} else {
  console.log(
    `admission-evidence provenance OK — ${files.length} files, ${findings.length} pinned lead(s) (a lead is not a verdict), H-census ${hCensus.length}/${H_BASELINE.length} baseline.`,
  );
}
