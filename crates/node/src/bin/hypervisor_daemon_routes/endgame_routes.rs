//! Cut G — provider ladder (D6) + end-game consumers.
//!
//! The provider ladder is one `EnvironmentRecipe` resolving across providers of increasing isolation
//! with HONEST claims: local (trusted) → container (single-user) → microVM (untrusted/autonomous) →
//! remote VM (enterprise VPC) → confidential TEE (no-provider-trust) → wasm (bounded deterministic)
//! → DePIN (decentralized, policy-gated). Resolution picks the LOWEST rung that satisfies the trust /
//! residency / confidential / deterministic requirement and records the REJECTED rungs with honest
//! reasons (never a silent drop, never an overstated isolation claim). Disabled rungs say WHY.
//!
//! The end-game consumers (MCP Gateway, Agent Studio, Foundry, ODK, Marketplace, Work Ledger /
//! Operations / Governance) CONSUME this substrate — none needs a new execution substrate. The
//! manifest is honest about what is wired live (the MCP Gateway, Cut F) vs declared.
use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, DaemonState};

/// Is a real microVM monitor present on this host? (honest enablement for the microVM+ rungs.)
fn microvm_monitor_present() -> bool {
    ["cloud-hypervisor", "qemu-system-x86_64", "firecracker"]
        .iter()
        .any(|bin| {
            std::process::Command::new("which")
                .arg(bin)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
}

/// The provider ladder with honest isolation claims. `cross_tenant` is the TRUTH of whether the rung
/// is a cross-tenant isolation boundary — only real kernel/HW boundaries claim it.
fn provider_ladder() -> Value {
    let microvm_ok = microvm_monitor_present();
    json!([
        { "rung": 0, "provider": "local_workspace_provider_v0", "display_name": "Local Workspace", "substrate": "local_host",
          "trust_model": "trusted_operator", "isolation_boundary": "process + scoped worktree/runtime state",
          "cross_tenant": false, "locality": "local", "confidential": false, "deterministic": false,
          "enabled": true, "reason": "single-user trusted-operator lane (default)" },
        { "rung": 1, "provider": "container_provider_v1", "display_name": "Container", "substrate": "container",
          "trust_model": "single_user", "isolation_boundary": "container namespaces (setup/inner-sandbox assist)",
          "cross_tenant": false, "locality": "local", "confidential": false, "deterministic": false,
          "enabled": false, "reason": "container runtime not provisioned in this deployment" },
        { "rung": 2, "provider": "microvm_provider_v1", "display_name": "microVM", "substrate": "microvm",
          "trust_model": "untrusted_autonomous", "isolation_boundary": "vm_kernel (monitor-enforced cpu/mem; private vpc)",
          "cross_tenant": true, "locality": "local", "confidential": false, "deterministic": false,
          "enabled": microvm_ok, "reason": if microvm_ok { "microVM monitor detected on host" } else { "no microVM monitor (cloud-hypervisor/qemu/firecracker) on host" } },
        { "rung": 3, "provider": "remote_vm_provider_v1", "display_name": "Remote VM", "substrate": "vm",
          "trust_model": "enterprise_vpc", "isolation_boundary": "vm_kernel + customer VPC",
          "cross_tenant": true, "locality": "cloud", "confidential": false, "deterministic": false,
          "enabled": false, "reason": "no remote VM provider endpoint configured (IOI_REMOTE_PROVIDER_ENDPOINT)" },
        { "rung": 4, "provider": "ctee_private_compute_provider_v1", "display_name": "Confidential TEE", "substrate": "cvm_tee",
          "trust_model": "no_provider_trust", "isolation_boundary": "hardware TEE (attested, memory-encrypted)",
          "cross_tenant": true, "locality": "cloud", "confidential": true, "deterministic": false,
          "enabled": false, "reason": "no attested confidential-compute backend configured" },
        { "rung": 5, "provider": "wasm_provider_v1", "display_name": "WASM", "substrate": "wasm",
          "trust_model": "bounded_deterministic", "isolation_boundary": "wasm sandbox (capability-scoped)",
          "cross_tenant": true, "locality": "local", "confidential": false, "deterministic": true,
          "enabled": false, "reason": "wasm runtime not provisioned in this deployment" },
        { "rung": 6, "provider": "depin_provider_v1", "display_name": "DePIN", "substrate": "depin",
          "trust_model": "decentralized_policy_gated", "isolation_boundary": "remote attested node (policy-gated routes)",
          "cross_tenant": true, "locality": "decentralized", "confidential": false, "deterministic": false,
          "enabled": false, "reason": "no DePIN route policy configured" }
    ])
}

/// GET /v1/hypervisor/provider-ladder — the ladder catalog with honest claims.
pub(crate) async fn handle_provider_ladder(State(_st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(
        json!({ "schema_version": "ioi.hypervisor.provider-ladder.v1", "ladder": provider_ladder() }),
    )
}

/// POST /v1/hypervisor/provider-ladder/resolve — resolve ONE recipe across the ladder.
/// Body: `{ recipe_ref?, trust ("trusted"|"cross_tenant"), residency ("any"|"local"|"cloud_ok"),
/// confidential?, deterministic? }`. Picks the LOWEST eligible rung; records rejected with reasons.
pub(crate) async fn handle_provider_ladder_resolve(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let trust = body
        .get("trust")
        .and_then(|v| v.as_str())
        .unwrap_or("trusted");
    let residency = body
        .get("residency")
        .and_then(|v| v.as_str())
        .unwrap_or("any");
    let confidential = body
        .get("confidential")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let deterministic = body
        .get("deterministic")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let recipe_ref = body
        .get("recipe_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // honest recipe binding: if a recipe_ref is given it must exist (the SAME recipe resolves across rungs).
    let recipe = if recipe_ref.is_empty() {
        json!({ "synthetic": true })
    } else {
        super::recipe_routes::load_recipe(&st.data_dir, recipe_ref).unwrap_or(Value::Null)
    };
    if recipe.is_null() {
        return Json(json!({ "ok": false, "reason": format!("recipe '{recipe_ref}' not found") }));
    }

    let ladder = provider_ladder();
    let mut eligible: Vec<Value> = Vec::new();
    let mut rejected: Vec<Value> = Vec::new();
    for rung in ladder.as_array().unwrap() {
        let p = rung["provider"].as_str().unwrap_or("");
        let reject =
            |reason: &str| json!({ "provider": p, "rung": rung["rung"], "reason": reason });
        if rung["enabled"].as_bool() != Some(true) {
            rejected.push(reject(&format!(
                "not enabled: {}",
                rung["reason"].as_str().unwrap_or("")
            )));
            continue;
        }
        if trust == "cross_tenant" && rung["cross_tenant"].as_bool() != Some(true) {
            rejected.push(reject(
                "isolation is not a cross-tenant boundary for an untrusted/cross-tenant workload",
            ));
            continue;
        }
        if residency == "local" && rung["locality"].as_str() != Some("local") {
            rejected.push(reject("violates local data residency (non-local locality)"));
            continue;
        }
        if confidential && rung["confidential"].as_bool() != Some(true) {
            rejected.push(reject(
                "no confidential-compute attestation (workload requires no-provider-trust)",
            ));
            continue;
        }
        if deterministic && rung["deterministic"].as_bool() != Some(true) {
            rejected.push(reject("not a bounded-deterministic substrate"));
            continue;
        }
        eligible.push(rung.clone());
    }
    // lowest rung that satisfies the requirement = cheapest sufficient isolation.
    eligible.sort_by(|a, b| {
        a["rung"]
            .as_i64()
            .unwrap_or(99)
            .cmp(&b["rung"].as_i64().unwrap_or(99))
    });
    let chosen = eligible.first().cloned();
    let decision = json!({
        "schema_version": "ioi.hypervisor.provider-ladder-resolution.v1",
        "recipe_ref": if recipe_ref.is_empty() { Value::Null } else { json!(recipe_ref) },
        "requirement": { "trust": trust, "residency": residency, "confidential": confidential, "deterministic": deterministic },
        "chosen": chosen, "eligible": eligible, "rejected": rejected, "at": iso_now()
    });
    if decision["chosen"].is_null() {
        return Json(
            json!({ "ok": false, "reason": "no rung satisfies the requirement (all rejected with honest reasons)", "resolution": decision }),
        );
    }
    Json(json!({ "ok": true, "resolution": decision }))
}

/// GET /v1/hypervisor/endgame/consumers — the broader architecture that consumes this substrate.
/// Honest: `wired` consumers have a live route; `declared` consumers name the substrate primitives
/// they will consume (no new execution substrate required for any of them).
pub(crate) async fn handle_endgame_consumers(State(_st): State<Arc<DaemonState>>) -> Json<Value> {
    Json(json!({
        "schema_version": "ioi.hypervisor.endgame-consumers.v1",
        "principle": "the env+agent substrate is the foundation; consumers CONSUME it, none needs a new execution substrate",
        "consumers": [
            { "name": "MCP Gateway", "status": "wired", "consumes": ["environments", "exec", "guardrails"],
              "route": "/v1/hypervisor/mcp-gateway/tools", "note": "external agents on scoped surface capabilities (Cut F)" },
            { "name": "Agent Studio", "status": "declared", "consumes": ["agent-runner-profiles", "harness-bindings", "agentops/conversations"],
              "note": "author harness profiles / worker packages against the runner capability matrix (Cut D)" },
            { "name": "Foundry", "status": "declared", "consumes": ["invocation-receipts", "automation-executions", "operability/metrics"],
              "note": "train/eval/promote workers from the opted-in evidence the substrate already records" },
            { "name": "ODK", "status": "declared", "consumes": ["recipes", "environments", "agentops/conversations"],
              "note": "domain apps + data/ontology recipes on the same env/session substrate (Cut B/D)" },
            { "name": "Marketplace", "status": "declared", "consumes": ["agent-runner-profiles", "automations", "provider-ladder"],
              "note": "deployable agents/workers/adapters/managed instances over the ladder (Cut E/G)" },
            { "name": "Work Ledger / Operations / Governance", "status": "declared", "consumes": ["receipts", "incidents", "audit", "placement-decisions"],
              "note": "proof, policy, receipts, audit, release, recovery, settlement (Cut F)" }
        ]
    }))
}
