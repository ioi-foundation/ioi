//! Worker-package-install admission planner.
//!
//! A faithful Rust port of the retired JS `admitWorkerPackageInstall`
//! (`packages/runtime-daemon/src/runtime-worker-package-install-admission.mjs`). Pure validation:
//! a worker package install is admitted only when its manifest / ontology / vertical packs /
//! integration surfaces / primitive + authority requirements / policy + receipt + evidence +
//! artifact refs + wallet approval + (mode-specific) install-right / managed-instance / physical-
//! action safety envelope are bound, and a vertical pack never forks daemon runtime truth.
//!
//! STATUS: field-shape helpers (required/enum/prefix/manifest/owner) reject 400; policy
//! assertions (requireRefs + admissionError) reject 403. `uniqueStrings` is the no-trim shared
//! variant; scalars trim via the ECMAScript js_trim set. `requirePrefix` rejects with a per-field
//! `..._{field}_invalid` code (details key = the dynamic field name).

use serde_json::{json, Map, Value};

pub const WORKER_PACKAGE_INSTALL_ADMISSION_SCHEMA_VERSION: &str =
    "ioi.runtime.worker_package_install_admission.v1";

const INSTALL_MODES: &[&str] = &[
    "local_hypervisor_install",
    "managed_instance_initialization",
    "api_worker_binding",
    "workflow_node_install",
];

const RUNTIME_PROFILES: &[&str] = &[
    "local",
    "hosted",
    "provider",
    "depin",
    "private_workspace_ctee",
    "tee",
    "customer_vpc",
];

const PERSISTENCE_PROFILES: &[&str] = &["ephemeral", "session", "zero_to_idle", "persistent"];

const OWNER_PREFIXES: &[&str] = &["wallet://", "org://", "project://"];

const RETIRED_ALIASES: &[&str] = &[
    "installId",
    "workerPackageRef",
    "workerManifestRef",
    "ownerRef",
    "baseOntologyRef",
    "verticalPackRefs",
    "integrationSurfaceRefs",
    "primitiveCapabilityRequirements",
    "authorityScopeRequirements",
    "agentgresOperationRefs",
    "receiptRefs",
];

#[derive(Debug, Clone)]
pub struct RuntimeWorkerPackageInstallAdmissionError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl RuntimeWorkerPackageInstallAdmissionError {
    fn new(status: u16, code: String, message: String, details: Value) -> Self {
        Self {
            status,
            code,
            message,
            details,
        }
    }
}

type AdmitResult<T> = Result<T, RuntimeWorkerPackageInstallAdmissionError>;

#[derive(Default)]
pub struct RuntimeWorkerPackageInstallAdmissionCore;

impl RuntimeWorkerPackageInstallAdmissionCore {
    pub fn admit(&self, request: &Value, now_iso: &str) -> AdmitResult<Value> {
        assert_no_retired_aliases(request)?;

        let install_id = required_string(request.get("install_id"), "install_id")?;
        let worker_package_ref =
            required_string(request.get("worker_package_ref"), "worker_package_ref")?;
        let worker_manifest_ref =
            required_string(request.get("worker_manifest_ref"), "worker_manifest_ref")?;
        let owner_ref = required_string(request.get("owner_ref"), "owner_ref")?;
        let install_mode = enum_value(request.get("install_mode"), "install_mode", INSTALL_MODES)?;
        let base_ontology_ref =
            required_string(request.get("base_ontology_ref"), "base_ontology_ref")?;
        let vertical_pack_refs = unique_strings_raw(request.get("vertical_pack_refs"));
        let integration_surface_refs = unique_strings_raw(request.get("integration_surface_refs"));
        let primitive_capability_requirements =
            unique_strings_raw(request.get("primitive_capability_requirements"));
        let authority_scope_requirements =
            unique_strings_raw(request.get("authority_scope_requirements"));
        let risk_classes = unique_strings_raw(request.get("risk_classes"));
        let policy_profile_refs = unique_strings_raw(request.get("policy_profile_refs"));
        let receipt_policy_ref =
            required_string(request.get("receipt_policy_ref"), "receipt_policy_ref")?;
        let evidence_requirement_refs =
            unique_strings_raw(request.get("evidence_requirement_refs"));
        let benchmark_profile_refs = unique_strings_raw(request.get("benchmark_profile_refs"));
        let runtime_profile = enum_value(
            request.get("runtime_profile"),
            "runtime_profile",
            RUNTIME_PROFILES,
        )?;
        let persistence_profile = enum_value(
            request.get("persistence_profile"),
            "persistence_profile",
            PERSISTENCE_PROFILES,
        )?;
        let memory_policy_ref = optional_value(request.get("memory_policy_ref"));
        let archive_policy_ref = optional_value(request.get("archive_policy_ref"));
        let package_artifact_refs = unique_strings_raw(request.get("package_artifact_refs"));
        let wallet_approval_ref = optional_value(request.get("wallet_approval_ref"));
        let install_right_ref = optional_value(request.get("install_right_ref"));
        let managed_instance_ref = optional_value(request.get("managed_instance_ref"));
        let physical_action_policy_refs =
            unique_strings_raw(request.get("physical_action_policy_refs"));
        let safety_envelope_refs = unique_strings_raw(request.get("safety_envelope_refs"));
        let emergency_stop_authority_refs =
            unique_strings_raw(request.get("emergency_stop_authority_refs"));
        let agentgres_operation_refs = unique_strings_raw(request.get("agentgres_operation_refs"));
        let receipt_refs = unique_strings_raw(request.get("receipt_refs"));
        let state_root = optional_value(request.get("state_root"));
        let hardcoded_vertical_runtime =
            boolean_value(request.get("hardcoded_vertical_runtime")).unwrap_or(false);

        // assertWorkerPackageInstall — prefixes (400) interleaved with policy assertions (403).
        require_prefix(&install_id, "install://", "install_id")?;
        require_prefix(&worker_package_ref, "package://", "worker_package_ref")?;
        require_manifest_ref(&worker_manifest_ref)?;
        require_owner_ref(&owner_ref)?;
        require_prefix(&base_ontology_ref, "ontology:", "base_ontology_ref")?;
        require_refs(&integration_surface_refs, "integration_surface_refs")?;
        for reference in &integration_surface_refs {
            require_prefix(
                reference,
                "integration_surface:",
                "integration_surface_refs",
            )?;
        }
        require_refs(
            &primitive_capability_requirements,
            "primitive_capability_requirements",
        )?;
        for reference in &primitive_capability_requirements {
            require_prefix(reference, "prim:", "primitive_capability_requirements")?;
        }
        require_refs(
            &authority_scope_requirements,
            "authority_scope_requirements",
        )?;
        if authority_scope_requirements
            .iter()
            .any(|reference| reference.starts_with("prim:"))
        {
            return Err(authority_error(
                "worker_package_install_primitive_scope_masquerade_blocked",
                "Worker package installs must not treat prim:* execution capabilities as wallet authority scopes.",
                json!({ "authority_scope_requirements": authority_scope_requirements }),
            ));
        }
        for reference in &authority_scope_requirements {
            require_prefix(reference, "scope:", "authority_scope_requirements")?;
        }
        if hardcoded_vertical_runtime {
            return Err(authority_error(
                "worker_package_install_vertical_runtime_fork_blocked",
                "Vertical packs extend ontology and policy; they must not fork Hypervisor Daemon runtime truth.",
                json!({ "hardcoded_vertical_runtime": hardcoded_vertical_runtime }),
            ));
        }
        require_refs(&policy_profile_refs, "policy_profile_refs")?;
        for reference in &policy_profile_refs {
            require_prefix(reference, "policy://", "policy_profile_refs")?;
        }
        require_prefix(
            &receipt_policy_ref,
            "receipt_policy://",
            "receipt_policy_ref",
        )?;
        require_refs(&evidence_requirement_refs, "evidence_requirement_refs")?;
        for reference in &evidence_requirement_refs {
            require_prefix(
                reference,
                "evidence_requirement:",
                "evidence_requirement_refs",
            )?;
        }
        require_refs(&package_artifact_refs, "package_artifact_refs")?;
        for reference in &package_artifact_refs {
            require_prefix(reference, "artifact://", "package_artifact_refs")?;
        }
        require_refs(&agentgres_operation_refs, "agentgres_operation_refs")?;
        require_refs(&receipt_refs, "receipt_refs")?;
        if wallet_approval_ref.is_none() {
            return Err(authority_error(
                "worker_package_install_wallet_approval_required",
                "Worker package install admission requires wallet.network approval.",
                json!({ "wallet_approval_ref": wallet_approval_ref }),
            ));
        }
        if install_mode != "workflow_node_install" && install_right_ref.is_none() {
            return Err(authority_error(
                "worker_package_install_right_ref_required",
                "Worker package install admission requires an install/license right except for workflow-node-only bindings.",
                json!({ "install_mode": install_mode }),
            ));
        }
        if install_mode == "managed_instance_initialization" && managed_instance_ref.is_none() {
            return Err(authority_error(
                "worker_package_install_managed_instance_ref_required",
                "Managed worker initialization requires a managed_instance_ref.",
                json!({ "install_mode": install_mode }),
            ));
        }
        if matches!(persistence_profile.as_str(), "zero_to_idle" | "persistent")
            && (memory_policy_ref.is_none() || archive_policy_ref.is_none())
        {
            return Err(authority_error(
                "worker_package_install_persistence_policy_required",
                "Zero-to-idle and persistent installs require memory and archive policy refs.",
                json!({ "persistence_profile": persistence_profile }),
            ));
        }
        if let Some(ref memory_policy) = memory_policy_ref {
            require_prefix(memory_policy, "policy://", "memory_policy_ref")?;
        }
        if let Some(ref archive_policy) = archive_policy_ref {
            require_prefix(archive_policy, "policy://", "archive_policy_ref")?;
        }
        if let Some(ref install_right) = install_right_ref {
            require_prefix(install_right, "license://", "install_right_ref")?;
        }
        if let Some(ref managed_instance) = managed_instance_ref {
            require_prefix(managed_instance, "agent://", "managed_instance_ref")?;
        }
        if risk_classes.iter().any(|class| class == "physical_action") {
            require_refs(&vertical_pack_refs, "vertical_pack_refs")?;
            require_refs(&physical_action_policy_refs, "physical_action_policy_refs")?;
            require_refs(&safety_envelope_refs, "safety_envelope_refs")?;
            require_refs(
                &emergency_stop_authority_refs,
                "emergency_stop_authority_refs",
            )?;
        }
        for reference in &vertical_pack_refs {
            require_prefix(reference, "vertical_pack:", "vertical_pack_refs")?;
        }
        for reference in &physical_action_policy_refs {
            require_prefix(reference, "policy://", "physical_action_policy_refs")?;
        }
        for reference in &safety_envelope_refs {
            require_prefix(reference, "safety://", "safety_envelope_refs")?;
        }
        for reference in &emergency_stop_authority_refs {
            require_prefix(reference, "estop://", "emergency_stop_authority_refs")?;
        }
        if runtime_profile == "private_workspace_ctee"
            && !policy_profile_refs
                .iter()
                .any(|reference| reference.contains("ctee"))
        {
            return Err(authority_error(
                "worker_package_install_ctee_policy_required",
                "Private Workspace cTEE installs require an explicit cTEE policy profile ref.",
                json!({ "runtime_profile": runtime_profile }),
            ));
        }

        let admission_id = optional_value(request.get("admission_id")).unwrap_or_else(|| {
            format!(
                "worker-package-install:{}:{}",
                safe_id(&install_id),
                safe_id(&install_mode)
            )
        });
        let admitted_at =
            optional_value(request.get("admitted_at")).unwrap_or_else(|| now_iso.to_string());

        Ok(json!({
            "schema_version": WORKER_PACKAGE_INSTALL_ADMISSION_SCHEMA_VERSION,
            "admission_id": admission_id,
            "install_id": install_id,
            "worker_package_ref": worker_package_ref,
            "worker_manifest_ref": worker_manifest_ref,
            "owner_ref": owner_ref,
            "install_mode": install_mode,
            "base_ontology_ref": base_ontology_ref,
            "vertical_pack_refs": vertical_pack_refs,
            "integration_surface_refs": integration_surface_refs,
            "primitive_capability_requirements": primitive_capability_requirements,
            "authority_scope_requirements": authority_scope_requirements,
            "risk_classes": risk_classes,
            "policy_profile_refs": policy_profile_refs,
            "receipt_policy_ref": receipt_policy_ref,
            "evidence_requirement_refs": evidence_requirement_refs,
            "benchmark_profile_refs": benchmark_profile_refs,
            "runtime_profile": runtime_profile,
            "persistence_profile": persistence_profile,
            "memory_policy_ref": memory_policy_ref,
            "archive_policy_ref": archive_policy_ref,
            "package_artifact_refs": package_artifact_refs,
            "wallet_approval_ref": wallet_approval_ref,
            "install_right_ref": install_right_ref,
            "managed_instance_ref": managed_instance_ref,
            "physical_action_policy_refs": physical_action_policy_refs,
            "safety_envelope_refs": safety_envelope_refs,
            "emergency_stop_authority_refs": emergency_stop_authority_refs,
            "agentgres_operation_refs": agentgres_operation_refs,
            "receipt_refs": receipt_refs,
            "state_root": state_root,
            "decision": "admitted",
            "requiresDaemonGate": true,
            "runtimeTruthSource": "daemon-runtime",
            "admitted_at": admitted_at,
        }))
    }
}

fn assert_no_retired_aliases(request: &Value) -> AdmitResult<()> {
    let empty = Map::new();
    let object = request.as_object().unwrap_or(&empty);
    let retired: Vec<String> = RETIRED_ALIASES
        .iter()
        .filter(|alias| object.contains_key(**alias))
        .map(|alias| alias.to_string())
        .collect();
    if retired.is_empty() {
        return Ok(());
    }
    Err(RuntimeWorkerPackageInstallAdmissionError::new(
        400,
        "worker_package_install_request_aliases_retired".to_string(),
        "Worker package install admission accepts only canonical snake_case request fields."
            .to_string(),
        json!({ "retired_aliases": retired }),
    ))
}

fn enum_value(value: Option<&Value>, field: &str, allowed: &[&str]) -> AdmitResult<String> {
    let normalized = optional_value(value);
    match &normalized {
        Some(value) if allowed.contains(&value.as_str()) => Ok(value.clone()),
        _ => {
            let mut details = Map::new();
            details.insert(
                field.to_string(),
                normalized.map(Value::String).unwrap_or(Value::Null),
            );
            details.insert("allowed_values".to_string(), json!(allowed));
            Err(RuntimeWorkerPackageInstallAdmissionError::new(
                400,
                format!("worker_package_install_{field}_invalid"),
                format!("Worker package install admission requires a valid {field}."),
                Value::Object(details),
            ))
        }
    }
}

fn required_string(value: Option<&Value>, field: &str) -> AdmitResult<String> {
    optional_value(value).ok_or_else(|| {
        RuntimeWorkerPackageInstallAdmissionError::new(
            400,
            format!("worker_package_install_{field}_required"),
            format!("Worker package install admission requires {field}."),
            json!({ "field": field }),
        )
    })
}

fn require_prefix(value: &str, prefix: &str, field: &str) -> AdmitResult<()> {
    if value.starts_with(prefix) {
        return Ok(());
    }
    let mut details = Map::new();
    details.insert(field.to_string(), Value::String(value.to_string()));
    Err(RuntimeWorkerPackageInstallAdmissionError::new(
        400,
        format!("worker_package_install_{field}_invalid"),
        format!("Worker package install {field} must start with {prefix}."),
        Value::Object(details),
    ))
}

fn require_manifest_ref(value: &str) -> AdmitResult<()> {
    if value.starts_with("manifest://") || value.starts_with("artifact://") {
        return Ok(());
    }
    Err(RuntimeWorkerPackageInstallAdmissionError::new(
        400,
        "worker_package_install_worker_manifest_ref_invalid".to_string(),
        "Worker package install worker_manifest_ref must identify a manifest or artifact ref."
            .to_string(),
        json!({ "worker_manifest_ref": value }),
    ))
}

fn require_owner_ref(value: &str) -> AdmitResult<()> {
    if OWNER_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix))
    {
        return Ok(());
    }
    Err(RuntimeWorkerPackageInstallAdmissionError::new(
        400,
        "worker_package_install_owner_ref_invalid".to_string(),
        "Worker package install owner_ref must identify a wallet, organization, or project."
            .to_string(),
        json!({ "owner_ref": value, "allowed_prefixes": OWNER_PREFIXES }),
    ))
}

fn require_refs(refs: &[String], field: &str) -> AdmitResult<()> {
    if !refs.is_empty() {
        return Ok(());
    }
    Err(authority_error(
        &format!("worker_package_install_{field}_required"),
        &format!("Worker package install admission requires {field}."),
        json!({ "field": field }),
    ))
}

fn authority_error(
    code: &str,
    message: &str,
    details: Value,
) -> RuntimeWorkerPackageInstallAdmissionError {
    RuntimeWorkerPackageInstallAdmissionError::new(
        403,
        code.to_string(),
        message.to_string(),
        details,
    )
}

/// Mirror JS `optionalString`: String(value).trim() (ECMAScript trim set), None when null/blank.
fn optional_value(value: Option<&Value>) -> Option<String> {
    match value {
        None | Some(Value::Null) => None,
        Some(value) => {
            let coerced = js_string_coerce(value);
            let trimmed = js_trim(&coerced);
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
    }
}

fn boolean_value(value: Option<&Value>) -> Option<bool> {
    match value {
        Some(Value::Bool(value)) => Some(*value),
        Some(Value::String(value)) => match value.to_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Mirror the SHARED/LOCAL `uniqueStrings(normalizeArray(value))`: truthy raw items, `String()`-
/// coerced (NO trim), drop blanks, first-seen dedup. Non-array → empty.
fn unique_strings_raw(value: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for item in items {
        if !is_truthy(item) {
            continue;
        }
        let coerced = js_string_coerce(item);
        if coerced.is_empty() {
            continue;
        }
        if !out.contains(&coerced) {
            out.push(coerced);
        }
    }
    out
}

fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(boolean) => *boolean,
        Value::Number(number) => number.as_f64().map(|float| float != 0.0).unwrap_or(false),
        Value::String(string) => !string.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

fn js_string_coerce(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(boolean) => boolean.to_string(),
        Value::Number(number) => js_number_to_string(number.as_f64().unwrap_or(0.0)),
        Value::String(string) => string.clone(),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Null => String::new(),
                other => js_string_coerce(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_string(),
    }
}

fn js_number_to_string(value: f64) -> String {
    if value == 0.0 {
        return "0".to_string();
    }
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 {
            "Infinity".to_string()
        } else {
            "-Infinity".to_string()
        };
    }
    let negative = value < 0.0;
    let magnitude = value.abs();
    let exp_form = format!("{magnitude:e}");
    let (mantissa, exp_str) = exp_form.split_once('e').unwrap_or((exp_form.as_str(), "0"));
    let exp: i32 = exp_str.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|ch| *ch != '.').collect();
    let k = digits.len() as i32;
    let n = exp + 1;

    let body = if k <= n && n <= 21 {
        let mut out = digits;
        for _ in 0..(n - k) {
            out.push('0');
        }
        out
    } else if 0 < n && n <= 21 {
        let (head, tail) = digits.split_at(n as usize);
        format!("{head}.{tail}")
    } else if -6 < n && n <= 0 {
        let mut out = String::from("0.");
        for _ in 0..(-n) {
            out.push('0');
        }
        out.push_str(&digits);
        out
    } else {
        let mut chars = digits.chars();
        let first = chars.next().unwrap_or('0');
        let rest: String = chars.collect();
        let mut out = String::new();
        out.push(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(&rest);
        }
        out.push('e');
        let e = n - 1;
        if e >= 0 {
            out.push('+');
            out.push_str(&e.to_string());
        } else {
            out.push('-');
            out.push_str(&(-e).to_string());
        }
        out
    };
    if negative {
        format!("-{body}")
    } else {
        body
    }
}

/// JS `String.prototype.trim` whitespace set (trims U+FEFF/BOM, not U+0085/NEL — unlike Rust).
fn is_js_whitespace(ch: char) -> bool {
    matches!(
        ch,
        '\u{0009}'
            | '\u{000A}'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

fn js_trim(value: &str) -> &str {
    value.trim_matches(is_js_whitespace)
}

fn safe_id(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut in_run = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-') {
            out.push(ch);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request() -> Value {
        json!({
            "install_id": "install://worker/carwash-prep",
            "worker_package_ref": "package://worker/carwash-prep",
            "worker_manifest_ref": "manifest://worker/carwash-prep",
            "owner_ref": "wallet://operator/carwash",
            "install_mode": "local_hypervisor_install",
            "base_ontology_ref": "ontology:core/worker",
            "vertical_pack_refs": ["vertical_pack:carwash"],
            "integration_surface_refs": ["integration_surface:carwash/bay"],
            "primitive_capability_requirements": ["prim:physical.actuate"],
            "authority_scope_requirements": ["scope:physical.actuate"],
            "risk_classes": ["physical_action"],
            "policy_profile_refs": ["policy://worker/carwash"],
            "receipt_policy_ref": "receipt_policy://worker/carwash",
            "evidence_requirement_refs": ["evidence_requirement:carwash/preflight"],
            "benchmark_profile_refs": ["benchmark:carwash"],
            "runtime_profile": "local",
            "persistence_profile": "session",
            "package_artifact_refs": ["artifact://worker/carwash-prep"],
            "wallet_approval_ref": "approval://wallet/worker/carwash",
            "install_right_ref": "license://worker/carwash",
            "physical_action_policy_refs": ["policy://physical/carwash"],
            "safety_envelope_refs": ["safety://carwash/bay"],
            "emergency_stop_authority_refs": ["estop://carwash/bay"],
            "agentgres_operation_refs": ["agentgres://operation/worker/carwash"],
            "receipt_refs": ["receipt://worker/carwash"],
        })
    }

    #[test]
    fn admits_worker_package_install() {
        let admission = RuntimeWorkerPackageInstallAdmissionCore
            .admit(&base_request(), "2026-06-18T00:00:00.000Z")
            .expect("admitted");
        assert_eq!(
            admission["schema_version"],
            WORKER_PACKAGE_INSTALL_ADMISSION_SCHEMA_VERSION
        );
        assert_eq!(admission["decision"], "admitted");
        assert_eq!(
            admission["admission_id"],
            "worker-package-install:install_worker_carwash-prep:local_hypervisor_install"
        );
        assert_eq!(admission["requiresDaemonGate"], true);
    }

    #[test]
    fn blocks_primitive_scope_masquerade() {
        let mut request = base_request();
        request["authority_scope_requirements"] = json!(["prim:physical.actuate"]);
        let error = RuntimeWorkerPackageInstallAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(
            error.code,
            "worker_package_install_primitive_scope_masquerade_blocked"
        );
        assert_eq!(error.status, 403);
    }

    #[test]
    fn blocks_vertical_runtime_fork() {
        let mut request = base_request();
        request["hardcoded_vertical_runtime"] = json!(true);
        let error = RuntimeWorkerPackageInstallAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(
            error.code,
            "worker_package_install_vertical_runtime_fork_blocked"
        );
        assert_eq!(error.status, 403);
    }

    #[test]
    fn requires_wallet_approval() {
        let mut request = base_request();
        request
            .as_object_mut()
            .unwrap()
            .remove("wallet_approval_ref");
        let error = RuntimeWorkerPackageInstallAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(
            error.code,
            "worker_package_install_wallet_approval_required"
        );
        assert_eq!(error.status, 403);
    }

    #[test]
    fn physical_action_requires_safety_envelope() {
        let mut request = base_request();
        request["safety_envelope_refs"] = json!([]);
        let error = RuntimeWorkerPackageInstallAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(
            error.code,
            "worker_package_install_safety_envelope_refs_required"
        );
        assert_eq!(error.status, 403);
    }

    #[test]
    fn bad_install_prefix_is_400() {
        let mut request = base_request();
        request["install_id"] = json!("nope://x");
        let error = RuntimeWorkerPackageInstallAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "worker_package_install_install_id_invalid");
    }

    #[test]
    fn ctee_runtime_requires_ctee_policy() {
        let mut request = base_request();
        request["runtime_profile"] = json!("private_workspace_ctee");
        let error = RuntimeWorkerPackageInstallAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.code, "worker_package_install_ctee_policy_required");
        assert_eq!(error.status, 403);
    }

    #[test]
    fn rejects_retired_aliases() {
        let mut request = base_request();
        request["installId"] = json!("legacy");
        let error = RuntimeWorkerPackageInstallAdmissionCore
            .admit(&request, "now")
            .expect_err("retired");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "worker_package_install_request_aliases_retired");
    }
}
