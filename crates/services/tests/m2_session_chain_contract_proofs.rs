//! M2 session-chain contract proofs: the registered architecture contracts for the
//! project-discovery/startup/session chain are bound to the REAL runtime-kernel planes.
//!
//! Claim under proof (M2 record contract): "Full predecessor/product/recovery chain" fails on
//! missing predecessor, wrong project/System, orphan resources, fabricated readiness.
//!
//! - Positive fixtures are kernel-produced objects: each kernel-output fixture is rebuilt here
//!   through the actual kernel code path and asserted byte-equal (as JSON values) with the
//!   registered fixture, then validated against the registered contract.
//! - Input-family fixtures (binding, spawn, readiness) both validate against their registered
//!   contracts AND pass the actual kernel admission paths that consume them.
//! - Missing predecessor, wrong project, fabricated readiness, and orphan resources each have a
//!   named negative proof at the load-bearing link.
//!
//! System-binding note: no existing plane carries `system_ref` for this chain (it is declared on
//! the canon-only `HypervisorEnvironmentStartupPlan`, which has no implementation), so the
//! wrong-System refusal is not provable at the unit bar yet and is deferred with that family.

use ioi_services::agentic::runtime::kernel::RuntimeKernelService;
use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;
use ioi_types::app::hypervisor_environment_lifecycle::{
    compile_cleanup_open, compile_cleanup_satisfy,
};
use serde_json::{json, Value};

const NOW: &str = "2026-07-28T12:00:00.000Z";

const LAUNCH_RECIPE_ADMISSION_CONTRACT: &str =
    "schema://ioi/components/hypervisor/hypervisor-session-launch-recipe-admission/v1";
const BINDING_CONTRACT: &str = "schema://ioi/components/hypervisor/harness-session-binding/v1";
const BINDING_ADMISSION_CONTRACT: &str =
    "schema://ioi/components/hypervisor/harness-session-binding-admission/v1";
const SPAWN_CONTRACT: &str = "schema://ioi/components/hypervisor/harness-session-spawn/v1";
const READINESS_CONTRACT: &str = "schema://ioi/components/hypervisor/harness-session-readiness/v1";
const ATTACH_CONTRACT: &str =
    "schema://ioi/components/hypervisor/harness-session-terminal-attach/v1";
const CLEANUP_OBLIGATION_CONTRACT: &str =
    "schema://ioi/components/hypervisor/hypervisor-resource-cleanup-obligation/v1";

macro_rules! fixture {
    ($rel:expr) => {
        serde_json::from_str::<Value>(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/_meta/schemas/fixtures/",
            $rel
        )))
        .expect($rel)
    };
}

fn kernel() -> RuntimeKernelService {
    RuntimeKernelService::new()
}

// ---------------------------------------------------------------------------
// Chain inputs (deterministic; the same objects the registered fixtures pin).
// ---------------------------------------------------------------------------

fn project_request() -> Value {
    json!({
        "repository_url": "https://github.com/teamioitest/ioi",
        "project_name": "ioi",
        "source": "manual_url",
        "environment_class_refs": ["environment-class:local-dev-replay"],
    })
}

fn workbench_recipe() -> Value {
    json!({
        "schema_version": "ioi.hypervisor.session_launch_recipe.v1",
        "recipe_id": "workbench.default",
        "label": "Workbench",
        "description": "Governed code/systems session that opens the selected code editor adapter.",
        "kind": "workbench",
        "surface_id": "workbench",
        "required_inputs": ["project", "adapter_preference", "harness", "model_route", "privacy_posture"],
        "model_mount_policy": "inherit",
        "harness_profile_policy": "select",
        "authority_scope_templates": ["scope:workspace.read", "scope:workspace.patch"],
        "privacy_posture_templates": ["public_trunk", "redacted_projection"],
    })
}

fn workbench_target_binding(project_ref: &str) -> Value {
    json!({
        "schema_version": "ioi.hypervisor.new_session_target_binding.v1",
        "target_binding_ref": "target-binding:new-session/workbench-default/ioi",
        "recipe_ref": "workbench.default",
        "target_kind": "workbench",
        "surface_id": "workbench",
        "project_ref": project_ref,
        "operator_intent_ref": "target-binding:new-session/workbench.default/ioi/operator-intent",
        "session_route_ref": "session-route:workbench/workbench-default/ioi",
        "code_editor_adapter_target_ref": "code-editor-target:vscode",
        "runtimeTruthSource": "daemon-runtime",
    })
}

fn workbench_launch_recipe_request(project_ref: &str) -> Value {
    json!({
        "schema_version": "ioi.hypervisor.session_launch_recipe_admission_request.v1",
        "recipe": workbench_recipe(),
        "target_binding": workbench_target_binding(project_ref),
        "model_route_ref": "model-route:hypervisor/default-local",
        "privacy_posture_ref": "privacy:redacted-projection",
        "authority_scope_refs": ["scope:workspace.read", "scope:workspace.patch"],
        "receipt_preview_ref": "receipt-preview:new-session/workbench",
        "expected_receipt_refs": [
            "receipt-preview:new-session/workbench",
            "receipt-policy:harness-adapter/default",
        ],
        "agentgres_operation_refs": ["agentgres://operation/hypervisor/session-launch-recipe/workbench-default-ioi"],
        "receipt_refs": ["receipt://hypervisor/session-launch-recipe/workbench-default-ioi"],
        "state_root": "agentgres://state-root/hypervisor/session-launch-recipe/workbench-default-ioi",
        "requires_daemon_gate": true,
        "runtimeTruthSource": "daemon-runtime",
    })
}

fn mission_launch_recipe_request() -> Value {
    json!({
        "schema_version": "ioi.hypervisor.session_launch_recipe_admission_request.v1",
        "recipe": {
            "schema_version": "ioi.hypervisor.session_launch_recipe.v1",
            "recipe_id": "mission.default",
            "label": "Mission",
            "description": "Governed mission session over the sessions surface.",
            "kind": "mission",
            "surface_id": "sessions",
            "required_inputs": ["project", "harness", "model_route", "privacy_posture"],
            "model_mount_policy": "inherit",
            "harness_profile_policy": "default",
            "authority_scope_templates": ["scope:workspace.read"],
            "privacy_posture_templates": ["public_trunk", "redacted_projection"],
        },
        "target_binding": {
            "schema_version": "ioi.hypervisor.new_session_target_binding.v1",
            "target_binding_ref": "target-binding:new-session/mission-default/ioi",
            "recipe_ref": "mission.default",
            "target_kind": "mission",
            "surface_id": "sessions",
            "project_ref": "project:ioi",
            "operator_intent_ref": null,
            "session_route_ref": "session-route:sessions/mission-default/ioi",
            "code_editor_adapter_target_ref": null,
            "runtimeTruthSource": "daemon-runtime",
        },
        "model_route_ref": "model-route:hypervisor/default-local",
        "privacy_posture_ref": "privacy:redacted-projection",
        "authority_scope_refs": ["scope:workspace.read"],
        "receipt_preview_ref": "receipt-preview:new-session/mission",
        "expected_receipt_refs": [
            "receipt-preview:new-session/mission",
            "receipt-policy:harness-profile/default",
        ],
        "requires_daemon_gate": true,
        "runtimeTruthSource": "daemon-runtime",
    })
}

// ---------------------------------------------------------------------------
// Positive proofs: registered fixtures are the kernel's own products.
// ---------------------------------------------------------------------------

#[test]
fn launch_recipe_admission_fixtures_are_kernel_products() {
    let workbench = kernel()
        .admit_hypervisor_session_launch_recipe(
            &workbench_launch_recipe_request("project:ioi"),
            NOW,
        )
        .expect("workbench admitted");
    assert_eq!(
        workbench,
        fixture!("hypervisor-session-launch-recipe-admission-v1/positive-workbench.json"),
        "registered fixture must be the kernel-produced object"
    );
    validate_architecture_contract(LAUNCH_RECIPE_ADMISSION_CONTRACT, &workbench)
        .expect("kernel product validates against the registered contract");

    let mission = kernel()
        .admit_hypervisor_session_launch_recipe(&mission_launch_recipe_request(), NOW)
        .expect("mission admitted");
    assert_eq!(
        mission,
        fixture!("hypervisor-session-launch-recipe-admission-v1/positive-mission.json")
    );
    validate_architecture_contract(LAUNCH_RECIPE_ADMISSION_CONTRACT, &mission).expect("valid");
}

#[test]
fn binding_fixtures_pass_both_registered_contract_and_kernel_gate() {
    for (binding_fixture, admission_fixture) in [
        (
            "harness-session-binding-v1/positive-profile-local-mount.json",
            "harness-session-binding-admission-v1/positive-profile.json",
        ),
        (
            "harness-session-binding-v1/positive-adapter-proposal-source.json",
            "harness-session-binding-admission-v1/positive-adapter.json",
        ),
    ] {
        let binding: Value = match binding_fixture {
            "harness-session-binding-v1/positive-profile-local-mount.json" => {
                fixture!("harness-session-binding-v1/positive-profile-local-mount.json")
            }
            _ => fixture!("harness-session-binding-v1/positive-adapter-proposal-source.json"),
        };
        validate_architecture_contract(BINDING_CONTRACT, &binding)
            .expect("binding fixture validates against the registered contract");
        let admission = kernel()
            .admit_harness_session_binding(&binding, NOW)
            .expect("the registered binding fixture is admitted by the real kernel gate");
        let expected: Value = match admission_fixture {
            "harness-session-binding-admission-v1/positive-profile.json" => {
                fixture!("harness-session-binding-admission-v1/positive-profile.json")
            }
            _ => fixture!("harness-session-binding-admission-v1/positive-adapter.json"),
        };
        assert_eq!(
            admission, expected,
            "admission fixture is the kernel product"
        );
        validate_architecture_contract(BINDING_ADMISSION_CONTRACT, &admission).expect("valid");
    }
}

#[test]
fn attach_fixture_is_kernel_product_over_registered_spawn_and_readiness() {
    let spawn = fixture!("harness-session-spawn-v1/positive-local-qwen.json");
    let readiness = fixture!("harness-session-readiness-v1/positive-probed.json");
    validate_architecture_contract(SPAWN_CONTRACT, &spawn).expect("spawn fixture valid");
    validate_architecture_contract(READINESS_CONTRACT, &readiness)
        .expect("readiness fixture valid");

    let attach = kernel()
        .admit_harness_session_terminal_attach(
            &json!({ "session_spawn": spawn, "session_readiness": readiness }),
            NOW,
        )
        .expect("attach admitted through the real kernel path");
    assert_eq!(
        attach,
        fixture!("harness-session-terminal-attach-v1/positive-workbench-codex.json"),
        "registered attach fixture must be the kernel-produced object"
    );
    validate_architecture_contract(ATTACH_CONTRACT, &attach).expect("valid");
}

// ---------------------------------------------------------------------------
// Full predecessor chain: project -> launch-recipe admission -> binding
// admission -> spawn -> readiness -> terminal attach, every product validated
// against its registered contract and every link cited exactly.
// ---------------------------------------------------------------------------

#[test]
fn full_predecessor_chain_validates_end_to_end() {
    let service = kernel();

    // project (chain root; produced by the real kernel planner)
    let project = service
        .plan_hypervisor_project_create(&project_request(), NOW)
        .expect("project record");
    let project_id = project["project_id"].as_str().expect("project id");
    assert_eq!(project_id, "project:ioi");

    // launch-recipe admission bound to that exact project
    let admission = service
        .admit_hypervisor_session_launch_recipe(&workbench_launch_recipe_request(project_id), NOW)
        .expect("launch recipe admitted");
    validate_architecture_contract(LAUNCH_RECIPE_ADMISSION_CONTRACT, &admission).expect("valid");
    assert_eq!(admission["project_ref"], project["project_id"]);
    assert_eq!(admission["admission_state"], "admitted_for_session_binding");

    // harness binding admission over the exact admitted session route
    let binding = fixture!("harness-session-binding-v1/positive-profile-local-mount.json");
    assert_eq!(binding["session_route_ref"], admission["session_route_ref"]);
    let binding_admission = service
        .admit_harness_session_binding(&binding, NOW)
        .expect("binding admitted");
    validate_architecture_contract(BINDING_ADMISSION_CONTRACT, &binding_admission).expect("valid");
    assert_eq!(
        binding_admission["session_route_ref"],
        admission["session_route_ref"]
    );
    assert_eq!(
        binding_admission["admission_state"],
        "admitted_for_harness_launch"
    );

    // spawn + readiness cite the exact admitted binding; workspace comes from the project record
    let spawn = fixture!("harness-session-spawn-v1/positive-local-qwen.json");
    let readiness = fixture!("harness-session-readiness-v1/positive-probed.json");
    assert_eq!(
        spawn["session_binding_ref"],
        binding_admission["session_binding_ref"]
    );
    assert_eq!(spawn["workspace_ref"], project["workspace_ref"]);
    assert_eq!(spawn["workspace_root"], project["root_path"]);
    assert_eq!(readiness["spawn_id"], spawn["spawn_id"]);
    assert_eq!(readiness["launch_id"], spawn["launch_id"]);
    assert_eq!(
        readiness["session_binding_ref"],
        spawn["session_binding_ref"]
    );

    // terminal attach over spawn + readiness
    let attach = service
        .admit_harness_session_terminal_attach(
            &json!({ "session_spawn": spawn.clone(), "session_readiness": readiness.clone() }),
            NOW,
        )
        .expect("attach admitted");
    validate_architecture_contract(ATTACH_CONTRACT, &attach).expect("valid");
    assert_eq!(attach["spawn_id"], spawn["spawn_id"]);
    assert_eq!(attach["readiness_id"], readiness["readiness_id"]);
    assert_eq!(attach["session_binding_ref"], spawn["session_binding_ref"]);
    // The attach carries the union of predecessor receipts plus its own admission receipt.
    let receipts: Vec<&str> = attach["receipt_refs"]
        .as_array()
        .expect("receipts")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(receipts.contains(&"receipt://harness-session-readiness/workbench-default-ioi-0001"));
    assert!(receipts.contains(&"receipt://harness-session-spawn/workbench-default-ioi-0001"));
    assert_eq!(
        receipts.len(),
        3,
        "readiness + spawn + attach admission receipts"
    );
}

// ---------------------------------------------------------------------------
// Dimension: missing predecessor refuses at each load-bearing link.
// ---------------------------------------------------------------------------

#[test]
fn missing_recipe_predecessor_refuses_launch_admission() {
    let mut request = workbench_launch_recipe_request("project:ioi");
    request.as_object_mut().unwrap().remove("recipe");
    let error = kernel()
        .admit_hypervisor_session_launch_recipe(&request, NOW)
        .expect_err("refused");
    assert_eq!(
        error.code,
        "hypervisor_session_launch_recipe_schema_invalid"
    );
}

#[test]
fn missing_target_binding_predecessor_refuses_launch_admission() {
    let mut request = workbench_launch_recipe_request("project:ioi");
    request.as_object_mut().unwrap().remove("target_binding");
    let error = kernel()
        .admit_hypervisor_session_launch_recipe(&request, NOW)
        .expect_err("refused");
    assert_eq!(
        error.code,
        "hypervisor_session_launch_recipe_target_binding_invalid"
    );
}

#[test]
fn foreign_recipe_target_pair_refuses_launch_admission() {
    let mut request = workbench_launch_recipe_request("project:ioi");
    request["target_binding"]["recipe_ref"] = json!("agent.default");
    request["target_binding"]["target_kind"] = json!("agent");
    request["target_binding"]["surface_id"] = json!("agents");
    let error = kernel()
        .admit_hypervisor_session_launch_recipe(&request, NOW)
        .expect_err("refused");
    assert_eq!(
        error.code,
        "hypervisor_session_launch_recipe_target_mismatch"
    );
}

#[test]
fn binding_that_does_not_cite_its_session_route_refuses() {
    let mut binding = fixture!("harness-session-binding-v1/positive-profile-local-mount.json");
    binding["session_binding_ref"] =
        json!("harness-session-binding:some-other-session:harness-profile-default_harness_profile");
    let error = kernel()
        .admit_harness_session_binding(&binding, NOW)
        .expect_err("refused");
    assert_eq!(error.code, "harness_session_binding_route_unbound");
    assert_eq!(error.status, 403);
}

#[test]
fn attach_without_spawn_predecessor_refuses() {
    let readiness = fixture!("harness-session-readiness-v1/positive-probed.json");
    let error = kernel()
        .admit_harness_session_terminal_attach(&json!({ "session_readiness": readiness }), NOW)
        .expect_err("refused");
    assert_eq!(error.code, "harness_session_terminal_attach_spawn_required");
    assert_eq!(error.status, 400);
}

#[test]
fn attach_without_readiness_predecessor_refuses() {
    let spawn = fixture!("harness-session-spawn-v1/positive-local-qwen.json");
    let error = kernel()
        .admit_harness_session_terminal_attach(&json!({ "session_spawn": spawn }), NOW)
        .expect_err("refused");
    assert_eq!(
        error.code,
        "harness_session_terminal_attach_readiness_required"
    );
}

#[test]
fn readiness_for_a_different_spawn_refuses_attach() {
    let spawn = fixture!("harness-session-spawn-v1/positive-local-qwen.json");
    let mut readiness = fixture!("harness-session-readiness-v1/positive-probed.json");
    readiness["spawn_id"] = json!("harness-session-spawn:OTHER");
    let error = kernel()
        .admit_harness_session_terminal_attach(
            &json!({ "session_spawn": spawn, "session_readiness": readiness }),
            NOW,
        )
        .expect_err("refused");
    assert_eq!(
        error.code,
        "harness_session_terminal_attach_readiness_boundary_invalid"
    );
    assert_eq!(error.status, 403);
}

// ---------------------------------------------------------------------------
// Dimension: wrong project cannot be silently substituted or defaulted.
// ---------------------------------------------------------------------------

#[test]
fn missing_project_refuses_launch_admission() {
    let mut request = workbench_launch_recipe_request("project:ioi");
    request["target_binding"]
        .as_object_mut()
        .unwrap()
        .remove("project_ref");
    let error = kernel()
        .admit_hypervisor_session_launch_recipe(&request, NOW)
        .expect_err("refused");
    assert_eq!(
        error.code,
        "hypervisor_session_launch_recipe_field_required"
    );
    assert_eq!(error.details["field"], "target_binding.project_ref");
}

#[test]
fn admission_binds_the_exact_target_project_never_a_default() {
    let admission = kernel()
        .admit_hypervisor_session_launch_recipe(
            &workbench_launch_recipe_request("project:some-other-project"),
            NOW,
        )
        .expect("admitted");
    // The kernel echoes the target binding's project byte-exactly; there is no fallback project.
    assert_eq!(admission["project_ref"], "project:some-other-project");
}

#[test]
fn non_project_ref_fails_registered_contract_even_when_kernel_admits() {
    // The kernel requires project_ref but does not validate its prefix (a recorded gap). The
    // registered contract pins the `project:` prefix, so the wrong-project shape fails the
    // contract instead of passing silently.
    let admission = kernel()
        .admit_hypervisor_session_launch_recipe(&workbench_launch_recipe_request("ioi"), NOW)
        .expect("kernel admits (gap under record)");
    assert_eq!(admission["project_ref"], "ioi");
    let error = validate_architecture_contract(LAUNCH_RECIPE_ADMISSION_CONTRACT, &admission)
        .expect_err("registered contract refuses the non-project ref");
    assert!(error.contains("project_ref"), "unexpected error: {error}");
}

// ---------------------------------------------------------------------------
// Dimension: fabricated readiness is unrepresentable (INV-37).
// ---------------------------------------------------------------------------

#[test]
fn readiness_without_probe_checks_fails_registered_contract() {
    let mut readiness = fixture!("harness-session-readiness-v1/positive-probed.json");
    readiness["checks"] = json!([]);
    validate_architecture_contract(READINESS_CONTRACT, &readiness)
        .expect_err("checkless readiness must fail");
}

#[test]
fn readiness_check_without_evidence_fails_registered_contract() {
    let mut readiness = fixture!("harness-session-readiness-v1/positive-probed.json");
    readiness["checks"][0]["evidence_refs"] = json!([]);
    validate_architecture_contract(READINESS_CONTRACT, &readiness)
        .expect_err("evidence-free check must fail");
}

#[test]
fn readiness_with_failed_check_cannot_claim_ready() {
    let mut readiness = fixture!("harness-session-readiness-v1/positive-probed.json");
    readiness["checks"][1]["status"] = json!("fail");
    validate_architecture_contract(READINESS_CONTRACT, &readiness)
        .expect_err("a failed probe cannot ride a ready record");
}

#[test]
fn readiness_without_spawn_predecessor_fails_contract_and_kernel() {
    let spawn = fixture!("harness-session-spawn-v1/positive-local-qwen.json");
    let mut readiness = fixture!("harness-session-readiness-v1/positive-probed.json");
    readiness.as_object_mut().unwrap().remove("spawn_id");
    validate_architecture_contract(READINESS_CONTRACT, &readiness)
        .expect_err("spawnless readiness must fail the contract");
    let error = kernel()
        .admit_harness_session_terminal_attach(
            &json!({ "session_spawn": spawn, "session_readiness": readiness }),
            NOW,
        )
        .expect_err("kernel refuses the same object");
    assert_eq!(
        error.code,
        "harness_session_terminal_attach_readiness_boundary_invalid"
    );
}

#[test]
fn replay_mock_spawn_state_is_refused_by_kernel_and_contract() {
    // The dev-replay mock emits spawn_state "host_spawn_admitted"; neither the kernel gate nor
    // the registered contract accepts it (recorded divergence at the canonical owner).
    let readiness = fixture!("harness-session-readiness-v1/positive-probed.json");
    let mut spawn = fixture!("harness-session-spawn-v1/positive-local-qwen.json");
    spawn["spawn_state"] = json!("host_spawn_admitted");
    validate_architecture_contract(SPAWN_CONTRACT, &spawn).expect_err("contract refuses");
    let error = kernel()
        .admit_harness_session_terminal_attach(
            &json!({ "session_spawn": spawn, "session_readiness": readiness }),
            NOW,
        )
        .expect_err("kernel refuses");
    assert_eq!(
        error.code,
        "harness_session_terminal_attach_spawn_boundary_invalid"
    );
}

// ---------------------------------------------------------------------------
// Dimension: orphan resources — every spawned resource carries a receipted
// cleanup obligation (integrating the already-registered
// HypervisorResourceCleanupObligation contract, not duplicating it).
// ---------------------------------------------------------------------------

fn terminal_cleanup_obligation(attach: &Value) -> Value {
    let terminal_session_ref = attach["terminal_session_ref"]
        .as_str()
        .expect("terminal ref");
    // Canonicalize the spawned resource identity from the attach record itself.
    let canonical_resource_ref = format!(
        "terminal-session://{}",
        terminal_session_ref.trim_start_matches("terminal-session:")
    );
    json!({
        "schema_version": "ioi.hypervisor-resource-cleanup-obligation.v1",
        "cleanup_obligation_ref": "cleanup-obligation://harness-session/terminal/workbench-default-ioi-0001",
        "revision": 1,
        "predecessor_obligation_root": null,
        "originating_plan_ref": null,
        "originating_execution_ref": null,
        "originating_daemon_or_provider_operation_ref": attach["agentgres_operation_refs"][2],
        "environment_ref": null,
        "session_ref": null,
        "provider_ref": "provider://local-host",
        "resource_refs": [
            {
                "resource_kind": "other",
                "canonical_resource_ref": canonical_resource_ref,
                "provider_native_evidence_ref": null,
                "identity_commitment": "sha256:0f4b2f9a4c1de8b3a6a1c2d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718",
            }
        ],
        "required_disposition": "destroy",
        "cause": "policy",
        "reclaim_policy_ref": "policy://hypervisor/harness-session/terminal-cleanup",
        "required_authority_refs": [],
        "lifecycle_head_ref": attach["state_root"],
        "status": "pending",
        "escalation": null,
        "attempt_count": 0,
        "last_attempt_ref": null,
        "next_attempt_after": null,
        "evidence_refs": [],
        "receipt_refs": [],
    })
}

fn admitted_attach() -> Value {
    let spawn = fixture!("harness-session-spawn-v1/positive-local-qwen.json");
    let readiness = fixture!("harness-session-readiness-v1/positive-probed.json");
    kernel()
        .admit_harness_session_terminal_attach(
            &json!({ "session_spawn": spawn, "session_readiness": readiness }),
            NOW,
        )
        .expect("attach admitted")
}

#[test]
fn spawned_terminal_resource_opens_a_cleanup_obligation() {
    let attach = admitted_attach();
    let obligation = terminal_cleanup_obligation(&attach);
    let opened = compile_cleanup_open(&obligation).expect("obligation opens over durable custody");
    validate_architecture_contract(CLEANUP_OBLIGATION_CONTRACT, &opened).expect("valid");
    // The obligation commits the exact spawned resource and the attach's own state root.
    assert_eq!(
        opened["resource_refs"][0]["canonical_resource_ref"],
        "terminal-session://workbench-default-ioi-0001"
    );
    assert_eq!(opened["lifecycle_head_ref"], attach["state_root"]);
}

#[test]
fn resource_leak_without_custody_row_is_unrepresentable() {
    // An "obligation" that names no resource cannot open: the registered contract requires at
    // least one identity-committed custody row, so a leaked resource has no representable
    // obligation-free disposition.
    let attach = admitted_attach();
    let mut obligation = terminal_cleanup_obligation(&attach);
    obligation["resource_refs"] = json!([]);
    let error = compile_cleanup_open(&obligation).expect_err("empty custody must refuse");
    assert!(
        error.contains("resource_refs"),
        "refusal names the custody rows: {error}"
    );
}

#[test]
fn unreceipted_close_of_the_spawned_resource_refuses() {
    let attach = admitted_attach();
    let opened = compile_cleanup_open(&terminal_cleanup_obligation(&attach)).expect("opened");
    let error = compile_cleanup_satisfy(&opened, "completed", None, &[])
        .expect_err("closing without a receipt must refuse");
    assert!(
        error.contains("unreceipted_close"),
        "refusal is the named unreceipted_close dimension: {error}"
    );
    // With a receipted disposition the same close succeeds and stays contract-valid.
    let closed = compile_cleanup_satisfy(
        &opened,
        "completed",
        Some("receipt://harness-session/terminal/workbench-default-ioi-0001/cleanup"),
        &[],
    )
    .expect("receipted close");
    validate_architecture_contract(CLEANUP_OBLIGATION_CONTRACT, &closed).expect("valid");
}
