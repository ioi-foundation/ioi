#[cfg(test)]
mod tests {
    use ioi_client::workload_client::WORKLOAD_STEP_MODULE_DISPATCH_SCHEMA_VERSION;
    use ioi_services::agentic::runtime::kernel::coding_tool_step_module::{
        artifact_read_response, computer_use_request_lease_response, file_apply_patch_response,
        tool_retrieve_result_response,
        CodingToolStepModuleBridgeRequest as StepModuleBridgeRequest,
    };
    use ioi_services::agentic::runtime::kernel::coding_tool_workspace::{
        inspect_git_diff, inspect_lsp_diagnostics, inspect_test_run, inspect_workspace_path,
        inspect_workspace_status,
    };
    use serde_json::{json, Value};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{fs, path::Path, process::Command};

    const CODING_TOOL_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.coding-tool-result.v1";
    #[test]
    fn workspace_status_reads_git_porcelain_status() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        run_test_git(&workspace, &["init"]);
        run_test_git(&workspace, &["config", "user.email", "test@example.com"]);
        run_test_git(&workspace, &["config", "user.name", "IOI Test"]);
        fs::write(workspace.join("README.md"), "before\n").expect("fixture file");
        run_test_git(&workspace, &["add", "README.md"]);
        run_test_git(&workspace, &["commit", "-m", "initial"]);
        fs::write(workspace.join("README.md"), "after\n").expect("updated file");
        fs::write(workspace.join("new.txt"), "new\n").expect("new file");

        let result = inspect_workspace_status(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "includeIgnored": true
            }),
        )
        .expect("status result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["git"]["available"], true);
        assert!(
            result["git"]["branch"]
                .as_str()
                .expect("branch")
                .contains("main")
                || result["git"]["branch"]
                    .as_str()
                    .expect("branch")
                    .contains("master")
        );
        assert!(result["changedFiles"]
            .as_array()
            .expect("changed files")
            .iter()
            .any(|entry| entry["path"] == "README.md"));
        assert!(result["changedFiles"]
            .as_array()
            .expect("changed files")
            .iter()
            .any(|entry| entry["path"] == "new.txt" && entry["status"] == "??"));
        assert_eq!(result["counts"]["changed"], 2);
        assert_eq!(result["counts"]["untracked"], 1);
        assert_eq!(
            result["git"]["porcelainHash"].as_str().expect("hash").len(),
            64
        );
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn workspace_status_reports_not_git_repository_without_failing_step() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");

        let result = inspect_workspace_status(workspace.to_str().expect("utf8 path"), &json!({}))
            .expect("status result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["git"]["available"], false);
        assert_eq!(result["git"]["status"], "not_git_repository");
        assert_eq!(result["changedFiles"], json!([]));
        assert_eq!(result["counts"]["changed"], 0);
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn test_run_node_test_reports_passed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(
            workspace.join("passing.test.mjs"),
            "import test from 'node:test';\nimport assert from 'node:assert/strict';\ntest('passes', () => assert.equal(1, 1));\n",
        )
        .expect("fixture file");

        let result = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "node.test",
                "path": "passing.test.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("test result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["commandId"], "node.test");
        assert_eq!(result["command"], "node --test");
        assert_eq!(result["args"], json!(["--test", "passing.test.mjs"]));
        assert_eq!(result["testStatus"], "passed");
        assert_eq!(result["exitCode"], 0);
        assert_eq!(result["timedOut"], false);
        assert_eq!(result["shellFallbackUsed"], false);
        assert_eq!(result["outputHash"].as_str().expect("hash").len(), 64);
    }

    #[test]
    fn test_run_node_test_reports_failure() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(
            workspace.join("failing.test.mjs"),
            "import test from 'node:test';\nimport assert from 'node:assert/strict';\ntest('fails', () => assert.equal(1, 2));\n",
        )
        .expect("fixture file");

        let result = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "node.test",
                "path": "failing.test.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("test result");

        assert_eq!(result["commandId"], "node.test");
        assert_eq!(result["testStatus"], "failed");
        assert_ne!(result["exitCode"], 0);
        assert_eq!(result["timedOut"], false);
    }

    #[cfg(unix)]
    #[test]
    fn test_run_npm_test_uses_sanitized_env_and_extra_args() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let bin = temp.path().join("bin");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::create_dir(&bin).expect("bin dir");
        write_fake_executable(
            &bin.join("npm"),
            "#!/bin/sh\nif [ -n \"$SECRET_TOKEN\" ]; then exit 7; fi\nif [ -n \"$NODE_TEST_CONTEXT\" ]; then exit 8; fi\necho fake npm \"$@\"\n",
        );
        let path_env = format!(
            "{}:{}",
            bin.to_string_lossy(),
            std::env::var("PATH").unwrap_or_default()
        );

        let result = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "npm.test",
                "args": ["--", "unit"],
                "timeoutMs": 5000,
                "env": {
                    "PATH": path_env,
                    "SECRET_TOKEN": "must-not-leak",
                    "NODE_TEST_CONTEXT": "must-not-leak"
                }
            }),
        )
        .expect("test result");

        assert_eq!(result["commandId"], "npm.test");
        assert_eq!(result["command"], "npm test");
        assert_eq!(result["executable"], "npm");
        assert_eq!(result["args"], json!(["test", "--", "unit"]));
        assert_eq!(result["testStatus"], "passed");
        assert!(result["stdout"]
            .as_str()
            .expect("stdout")
            .contains("fake npm test -- unit"));
    }

    #[cfg(unix)]
    #[test]
    fn test_run_cargo_backends_use_rust_live_command_mapping() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let bin = temp.path().join("bin");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::create_dir(&bin).expect("bin dir");
        write_fake_executable(
            &bin.join("cargo"),
            "#!/bin/sh\nif [ -n \"$SECRET_TOKEN\" ]; then exit 7; fi\necho fake cargo \"$@\"\n",
        );
        let path_env = format!(
            "{}:{}",
            bin.to_string_lossy(),
            std::env::var("PATH").unwrap_or_default()
        );

        let check_result = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "cargo.check",
                "timeoutMs": 5000,
                "env": {
                    "PATH": path_env,
                    "SECRET_TOKEN": "must-not-leak"
                }
            }),
        )
        .expect("cargo check result");
        let test_result = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "cargo.test",
                "timeoutMs": 5000,
                "env": {
                    "PATH": path_env,
                    "SECRET_TOKEN": "must-not-leak"
                }
            }),
        )
        .expect("cargo test result");

        assert_eq!(check_result["command"], "cargo check");
        assert_eq!(check_result["args"], json!(["check"]));
        assert_eq!(check_result["testStatus"], "passed");
        assert!(check_result["stdout"]
            .as_str()
            .expect("stdout")
            .contains("fake cargo check"));
        assert_eq!(test_result["command"], "cargo test");
        assert_eq!(test_result["args"], json!(["test"]));
        assert_eq!(test_result["testStatus"], "passed");
        assert!(test_result["stdout"]
            .as_str()
            .expect("stdout")
            .contains("fake cargo test"));
    }

    #[test]
    fn test_run_disallowed_command_fails_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");

        let error = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "python.test"
            }),
        )
        .expect_err("unknown command should fail closed");

        assert_eq!(error.code(), "test_run_command_not_allowed");
    }

    #[test]
    fn file_apply_patch_writes_and_binds_agentgres_admission() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("README.md"), "before\n").expect("fixture file");
        let request = bridge_request(
            "file.apply_patch",
            workspace.to_str().expect("utf8 path"),
            json!({
                "path": "README.md",
                "oldText": "before",
                "newText": "after"
            }),
        );

        let response = file_apply_patch_response(request).expect("patch response");

        assert_eq!(
            fs::read_to_string(workspace.join("README.md")).expect("updated file"),
            "after\n"
        );
        assert_eq!(response["workload_observation"]["result"]["applied"], true);
        assert_eq!(response["workload_observation"]["result"]["changed"], true);
        assert_eq!(
            response["router_admission"]["authoritative_transition"],
            true
        );
        assert_eq!(
            response["workload_dispatch"]["schema_version"],
            WORKLOAD_STEP_MODULE_DISPATCH_SCHEMA_VERSION,
        );
        assert_eq!(
            response["workload_dispatch"]["module_ref"],
            "file.apply_patch"
        );
        assert_eq!(response["workload_dispatch"]["transport"], "workload_grpc");
        assert!(response["workload_dispatch"]["evidence_refs"]
            .as_array()
            .expect("workload dispatch evidence")
            .iter()
            .any(|value| value == "rust_workload_client_step_module_dispatch"));
        assert!(response["result"]["workflow_projection"]["evidence_refs"]
            .as_array()
            .expect("projection evidence")
            .iter()
            .any(|value| value == "rust_workload_client_step_module_dispatch"));
        assert_eq!(
            response["result"]["agentgres_operation_refs"][0],
            response["agentgres_admission"]["operation_ref"],
        );
        assert!(response["result"]["state_root_after"]
            .as_str()
            .expect("state root")
            .starts_with("state://workspace/"));
        assert!(response["receipt_binding"]["expected_heads"]
            .as_array()
            .expect("expected heads")
            .first()
            .and_then(Value::as_str)
            .expect("expected head")
            .starts_with("head://workspace/"));
        assert_eq!(
            response["agentgres_admission"]["state_root_after"],
            response["result"]["state_root_after"],
        );
        assert_eq!(
            response["projection_record"]["status"],
            response["result"]["workflow_projection"]["status"],
        );
    }

    #[test]
    fn file_apply_patch_dry_run_has_no_agentgres_transition() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("README.md"), "before\n").expect("fixture file");
        let request = bridge_request(
            "file.apply_patch",
            workspace.to_str().expect("utf8 path"),
            json!({
                "path": "README.md",
                "oldText": "before",
                "newText": "after",
                "dryRun": true
            }),
        );

        let response = file_apply_patch_response(request).expect("patch response");

        assert_eq!(
            fs::read_to_string(workspace.join("README.md")).expect("original file"),
            "before\n"
        );
        assert_eq!(response["workload_observation"]["result"]["applied"], false);
        assert_eq!(response["workload_observation"]["result"]["changed"], true);
        assert_eq!(
            response["router_admission"]["authoritative_transition"],
            true
        );
        assert_eq!(response["result"]["agentgres_operation_refs"], json!([]));
        assert_eq!(response["agentgres_admission"], Value::Null);
        assert_eq!(response["result"]["state_root_after"], Value::Null);
    }

    #[test]
    fn artifact_read_uses_prefetched_data_plane_payload() {
        let request = bridge_request(
            "artifact.read",
            "/tmp",
            json!({
                "artifact_id": "artifact_alpha",
                "rust_workload_data_plane": {
                    "schema_version": "ioi.runtime.coding-tool-data-plane.v1",
                    "source": "daemon_artifact_store",
                    "operation": "artifact.read",
                    "artifact_id": "artifact_alpha",
                    "result": {
                        "schema_version": "ioi.runtime.coding-tool-result.v1",
                        "artifact_id": "artifact_alpha",
                        "artifact_ref": "artifact_alpha",
                        "artifact_refs": ["artifact_alpha"],
                        "content": "hello artifact\n",
                        "content_hash": "prefetch-hash",
                        "full_content_hash": "full-hash",
                        "offset_bytes": 0,
                        "length_bytes": 15,
                        "total_bytes": 15,
                        "truncated": false,
                        "receipt_refs": ["receipt_artifact_prefetch"],
                        "shell_fallback_used": true,
                        "schemaVersion": "retired",
                        "artifactRefs": ["retired_artifact"],
                        "contentHash": "retired-hash",
                        "receiptRefs": ["retired_receipt"],
                        "shellFallbackUsed": true
                    }
                }
            }),
        );

        let response = artifact_read_response(request).expect("artifact read response");

        assert_eq!(
            response["workload_observation"]["result"]["backend"],
            "rust_artifact_read"
        );
        assert_eq!(
            response["workload_observation"]["result"]["data_plane_source"],
            "daemon_artifact_store"
        );
        assert_eq!(
            response["workload_observation"]["result"]["shell_fallback_used"],
            false
        );
        assert_eq!(
            response["workload_observation"]["result"]["content_hash"]
                .as_str()
                .expect("content hash")
                .len(),
            64
        );
        assert_ne!(
            response["workload_observation"]["result"]["content_hash"],
            "prefetch-hash"
        );
        for retired_field in [
            "schemaVersion",
            "artifactRefs",
            "contentHash",
            "receiptRefs",
            "shellFallbackUsed",
        ] {
            assert_eq!(
                response["workload_observation"]["result"][retired_field],
                Value::Null
            );
        }
        assert_eq!(
            response["result"]["artifact_refs"],
            json!(["artifact_alpha"])
        );
        assert!(response["result"]["receipt_refs"]
            .as_array()
            .expect("receipt refs")
            .iter()
            .any(|value| value == "receipt_artifact_prefetch"));
        assert_eq!(response["agentgres_admission"], Value::Null);
        assert_eq!(
            response["projection_record"]["status"],
            response["result"]["workflow_projection"]["status"],
        );
    }

    #[test]
    fn tool_retrieve_result_uses_prefetched_data_plane_payload() {
        let request = bridge_request(
            "tool.retrieve_result",
            "/tmp",
            json!({
                "tool_call_id": "tool_patch",
                "channel": "stdout",
                "rust_workload_data_plane": {
                    "schema_version": "ioi.runtime.coding-tool-data-plane.v1",
                    "source": "daemon_artifact_store",
                    "operation": "tool.retrieve_result",
                    "query": {
                        "tool_call_id": "tool_patch",
                        "channel": "stdout"
                    },
                    "result": {
                        "schema_version": "ioi.runtime.coding-tool-result.v1",
                        "tool_call_id": "tool_patch",
                        "artifact_id": "artifact_result",
                        "artifact_ref": "artifact_result",
                        "artifact_refs": ["artifact_result"],
                        "channel": "stdout",
                        "content": "stored stdout\n",
                        "content_hash": "prefetch-hash",
                        "full_content_hash": "full-hash",
                        "available_artifacts": [{
                            "artifact_id": "artifact_result",
                            "channel": "stdout"
                        }],
                        "receipt_refs": ["receipt_tool_result_prefetch"],
                        "shell_fallback_used": true,
                        "schemaVersion": "retired",
                        "artifactRefs": ["retired_artifact"],
                        "contentHash": "retired-hash",
                        "receiptRefs": ["retired_receipt"],
                        "shellFallbackUsed": true
                    }
                }
            }),
        );

        let response = tool_retrieve_result_response(request).expect("retrieve response");

        assert_eq!(
            response["workload_observation"]["result"]["backend"],
            "rust_tool_result_retrieve"
        );
        assert_eq!(
            response["workload_observation"]["result"]["tool_call_id"],
            "tool_patch"
        );
        assert_eq!(
            response["workload_observation"]["result"]["content_hash"]
                .as_str()
                .expect("content hash")
                .len(),
            64
        );
        for retired_field in [
            "schemaVersion",
            "artifactRefs",
            "contentHash",
            "receiptRefs",
            "shellFallbackUsed",
        ] {
            assert_eq!(
                response["workload_observation"]["result"][retired_field],
                Value::Null
            );
        }
        assert_eq!(
            response["result"]["artifact_refs"],
            json!(["artifact_result"])
        );
        assert!(response["result"]["receipt_refs"]
            .as_array()
            .expect("receipt refs")
            .iter()
            .any(|value| value == "receipt_tool_result_prefetch"));
        assert_eq!(response["agentgres_admission"], Value::Null);
    }

    #[test]
    fn artifact_read_requires_prefetched_data_plane_payload() {
        let request = bridge_request(
            "artifact.read",
            "/tmp",
            json!({
                "artifact_id": "artifact_alpha"
            }),
        );

        let error = artifact_read_response(request).expect_err("missing payload should fail");

        assert_eq!(error.code(), "data_plane_payload_required");
    }

    #[test]
    fn artifact_read_rejects_retired_data_plane_aliases() {
        let request = bridge_request(
            "artifact.read",
            "/tmp",
            json!({
                "artifact_id": "artifact_alpha",
                "rustWorkloadDataPlane": {
                    "schemaVersion": "ioi.runtime.coding-tool-data-plane.v1",
                    "source": "daemon_artifact_store",
                    "operation": "artifact.read",
                    "result": {
                        "artifact_id": "artifact_alpha",
                        "content": "hello artifact\n"
                    }
                }
            }),
        );

        let error = artifact_read_response(request).expect_err("retired payload alias should fail");

        assert_eq!(error.code(), "data_plane_payload_alias_retired");
    }

    #[test]
    fn computer_use_request_lease_records_wallet_gated_act_request() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Open the browser and click the sign in button.",
                "lane": "native_browser",
                "session_mode": "controlled_relaunch",
                "action_kind": "click",
                "url": "https://example.test"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");

        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["lane"],
            "native_browser"
        );
        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["authority_scope"],
            "computer_use.native_browser.act"
        );
        assert_eq!(
            response["workload_observation"]["result"]["approval_required_before_execution"],
            true
        );
        assert_eq!(
            response["workload_observation"]["result"]["wallet_network_authority_boundary"]
                ["authority_layer"],
            "wallet.network"
        );
        assert_eq!(
            response["workload_observation"]["result"]["thread_tool"]["tool_name"],
            "ioi.computer_use.native_browser"
        );
        assert!(response["workload_observation"]["result"]["request_ref"]
            .as_str()
            .expect("request ref")
            .starts_with("computer_use_lease_request_"));
        assert!(response["result"]["receipt_refs"]
            .as_array()
            .expect("receipt refs")
            .iter()
            .any(|value| {
                value
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("receipt_computer_use_lease_request_")
            }));
        assert_eq!(response["agentgres_admission"], Value::Null);
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_lane_alias() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer the lane through a retired alias.",
                "computerUseLane": "sandboxed_hosted",
                "action_kind": "inspect"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");

        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["lane"],
            "native_browser"
        );
        assert_eq!(
            response["workload_observation"]["result"]["thread_tool"]["tool_name"],
            "ioi.computer_use.native_browser"
        );
        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["authority_scope"],
            "computer_use.native_browser.read"
        );
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_action_kind_alias() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to escalate authority through a retired action alias.",
                "lane": "native_browser",
                "actionKind": "click"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");

        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["action_kind"],
            "inspect"
        );
        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["authority_scope"],
            "computer_use.native_browser.read"
        );
        assert_eq!(
            response["workload_observation"]["result"]["approval_required_before_execution"],
            false
        );
        assert_eq!(
            response["workload_observation"]["result"]["wallet_network_authority_boundary"]
                ["required_before_execution"],
            false
        );
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_approval_alias() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to satisfy approval through a retired alias.",
                "lane": "native_browser",
                "action_kind": "click",
                "approvalRef": "approval_legacy"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");

        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["authority_scope"],
            "computer_use.native_browser.act"
        );
        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["approval_ref"],
            Value::Null
        );
        assert_eq!(
            response["workload_observation"]["result"]["approval_required_before_execution"],
            true
        );
        assert_eq!(
            response["workload_observation"]["result"]["wallet_network_authority_boundary"]
                ["required_before_execution"],
            true
        );
    }

    #[test]
    fn computer_use_request_lease_records_unavailable_provider_fail_closed() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Open a hosted sandbox.",
                "lane": "sandboxed_hosted",
                "session_mode": "hosted_sandbox",
                "sandbox_provider": "local_container",
                "action_kind": "inspect"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");

        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["provider_id"],
            "ioi.computer_use.sandboxed_hosted.local_container"
        );
        assert_eq!(
            response["workload_observation"]["result"]["thread_tool"]["tool_name"],
            Value::Null
        );
        assert!(
            response["workload_observation"]["result"]["thread_tool"]["unavailable_reason"]
                .as_str()
                .expect("unavailable reason")
                .contains("no container runtime adapter")
        );
        assert_eq!(
            response["workload_observation"]["result"]["approval_required_before_execution"],
            false
        );
        assert_eq!(response["agentgres_admission"], Value::Null);
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_provider_aliases() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer the provider through retired aliases.",
                "lane": "sandboxed_hosted",
                "session_mode": "local_sandbox",
                "sandboxProvider": "local_container",
                "providerKind": "local_container",
                "action_kind": "inspect"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");

        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["provider_id"],
            "ioi.computer_use.sandboxed_hosted.local_fixture"
        );
        assert_eq!(
            response["workload_observation"]["result"]["lease_request"]["provider_kind"],
            "local_fixture"
        );
        assert_eq!(
            response["workload_observation"]["result"]["thread_tool"]["tool_name"],
            "ioi.computer_use.sandboxed_hosted"
        );
        assert_eq!(
            response["workload_observation"]["result"]["thread_tool"]["unavailable_reason"],
            Value::Null
        );
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_target_ref_alias() {
        let retired_alias_request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer the target through a retired alias.",
                "lane": "native_browser",
                "action_kind": "inspect",
                "targetRef": "target_retired"
            }),
        );
        let baseline_request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer the target through a retired alias.",
                "lane": "native_browser",
                "action_kind": "inspect"
            }),
        );

        let retired_alias_response = computer_use_request_lease_response(retired_alias_request)
            .expect("retired alias lease request response");
        let baseline_response =
            computer_use_request_lease_response(baseline_request).expect("baseline response");

        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["request_ref"],
            baseline_response["workload_observation"]["result"]["request_ref"]
        );
        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["thread_tool"]["input"]
                ["target_ref"],
            Value::Null
        );
        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["lease_request"]
                ["authority_scope"],
            "computer_use.native_browser.read"
        );
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_session_mode_alias() {
        let retired_alias_request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer the session mode through a retired alias.",
                "lane": "sandboxed_hosted",
                "sessionMode": "hosted_sandbox",
                "action_kind": "inspect"
            }),
        );
        let baseline_request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer the session mode through a retired alias.",
                "lane": "sandboxed_hosted",
                "action_kind": "inspect"
            }),
        );

        let retired_alias_response = computer_use_request_lease_response(retired_alias_request)
            .expect("retired alias lease request response");
        let baseline_response =
            computer_use_request_lease_response(baseline_request).expect("baseline response");

        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["request_ref"],
            baseline_response["workload_observation"]["result"]["request_ref"]
        );
        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["lease_request"]
                ["session_mode"],
            "local_sandbox"
        );
        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["thread_tool"]["input"]
                ["session_mode"],
            "local_sandbox"
        );
        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["thread_tool"]["tool_name"],
            "ioi.computer_use.sandboxed_hosted"
        );
    }

    #[test]
    fn computer_use_request_lease_ignores_retired_observation_retention_alias() {
        let retired_alias_request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Try to steer retention through a retired alias.",
                "lane": "native_browser",
                "action_kind": "inspect",
                "observationRetentionMode": "local_raw_artifacts"
            }),
        );
        let canonical_request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Use canonical retention.",
                "lane": "native_browser",
                "action_kind": "inspect",
                "observation_retention_mode": "local_raw_artifacts"
            }),
        );

        let retired_alias_response = computer_use_request_lease_response(retired_alias_request)
            .expect("retired alias lease request response");
        let canonical_response =
            computer_use_request_lease_response(canonical_request).expect("canonical response");

        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["thread_tool"]["input"]
                ["observation_retention_mode"],
            "prompt_visible_summary_only"
        );
        assert_eq!(
            canonical_response["workload_observation"]["result"]["thread_tool"]["input"]
                ["observation_retention_mode"],
            "local_raw_artifacts"
        );
        assert_eq!(
            retired_alias_response["workload_observation"]["result"]["lease_request"]
                ["authority_scope"],
            "computer_use.native_browser.read"
        );
    }

    #[test]
    fn computer_use_request_lease_binds_canonical_receipt_and_request_refs() {
        let request = bridge_request(
            "computer_use.request_lease",
            "/tmp/workspace",
            json!({
                "prompt": "Bind canonical computer-use refs.",
                "lane": "native_browser",
                "action_kind": "inspect"
            }),
        );

        let response =
            computer_use_request_lease_response(request).expect("lease request response");
        let workload_result = &response["workload_observation"]["result"];
        let canonical_receipt_ref = workload_result["receipt_refs"][0]
            .as_str()
            .expect("canonical receipt ref");
        let canonical_request_ref = workload_result["request_ref"]
            .as_str()
            .expect("canonical request ref");
        let evidence_ref =
            format!("evidence://rust-workload/computer_use.request_lease/{canonical_request_ref}");

        assert!(response["result"]["receipt_refs"]
            .as_array()
            .expect("result receipt refs")
            .iter()
            .any(|value| value == canonical_receipt_ref));
        assert!(response["result"]["workflow_projection"]["evidence_refs"]
            .as_array()
            .expect("projection evidence refs")
            .iter()
            .any(|value| value == &evidence_ref));
        for retired_field in [
            "schemaVersion",
            "requestRef",
            "workspaceRoot",
            "leaseRequest",
            "threadTool",
            "providerRegistry",
            "approvalRequiredBeforeExecution",
            "walletNetworkAuthorityBoundary",
            "evidenceRefs",
            "receiptRefs",
            "shellFallbackUsed",
        ] {
            assert!(
                workload_result.get(retired_field).is_none(),
                "retired workload result field {retired_field} must not be emitted"
            );
        }
        for retired_field in [
            "sessionMode",
            "actionKind",
            "authorityScope",
            "repoAuthorityScope",
            "sharedClipboardPolicy",
            "artifactPolicy",
            "approvalRef",
            "failClosedWhenUnavailable",
            "providerId",
            "providerKind",
            "walletNetworkAuthorityRequiredBeforeExecution",
        ] {
            assert!(
                workload_result["lease_request"]
                    .get(retired_field)
                    .is_none(),
                "retired lease_request field {retired_field} must not be emitted"
            );
        }
        for retired_field in ["toolPack", "toolName", "unavailableReason"] {
            assert!(
                workload_result["thread_tool"].get(retired_field).is_none(),
                "retired thread_tool field {retired_field} must not be emitted"
            );
        }
        for retired_field in [
            "actionKind",
            "sessionMode",
            "targetRef",
            "approvalRef",
            "observationRetentionMode",
        ] {
            assert!(
                workload_result["thread_tool"]["input"]
                    .get(retired_field)
                    .is_none(),
                "retired thread_tool input field {retired_field} must not be emitted"
            );
        }
    }

    #[test]
    fn lsp_diagnostics_node_check_reports_clean_javascript() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("ok.mjs"), "const value = 1;\n").expect("fixture file");

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "node.check",
                "path": "ok.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["backend"], "node.check");
        assert_eq!(result["resolvedCommandId"], "node.check");
        assert_eq!(result["diagnosticStatus"], "clean");
        assert_eq!(result["diagnosticCount"], 0);
        assert_eq!(result["paths"], json!(["ok.mjs"]));
        assert_eq!(result["exitCode"], 0);
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn lsp_diagnostics_node_check_reports_syntax_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("broken.mjs"), "const = ;\n").expect("fixture file");

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "node.check",
                "path": "broken.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics result");

        assert_eq!(result["backend"], "node.check");
        assert_eq!(result["diagnosticStatus"], "findings");
        assert_eq!(result["diagnosticCount"], 1);
        assert_ne!(result["exitCode"], 0);
        assert_eq!(result["diagnostics"][0]["path"], "broken.mjs");
        assert_eq!(result["diagnostics"][0]["severity"], "error");
    }

    #[test]
    fn lsp_diagnostics_auto_routes_javascript_to_node_check() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("ok.mjs"), "const value = 1;\n").expect("fixture file");

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "auto",
                "path": "ok.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics result");

        assert_eq!(result["backend"], "node.check");
        assert_eq!(result["resolvedCommandId"], "node.check");
        assert_eq!(result["diagnosticStatus"], "clean");
        assert_eq!(result["fallbackUsed"], false);
    }

    #[cfg(unix)]
    #[test]
    fn lsp_diagnostics_typescript_check_reports_tsc_diagnostic() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let source_dir = workspace.join("src");
        let bin = workspace.join("node_modules").join(".bin");
        fs::create_dir_all(&source_dir).expect("source dir");
        fs::create_dir_all(&bin).expect("bin dir");
        fs::write(
            workspace.join("tsconfig.json"),
            r#"{"compilerOptions":{"strict":true},"include":["src/**/*.ts"]}"#,
        )
        .expect("tsconfig");
        fs::write(
            source_dir.join("broken.ts"),
            "const value: number = 'oops';\n",
        )
        .expect("ts fixture");
        write_fake_executable(
            &bin.join("tsc"),
            "#!/bin/sh\necho \"src/broken.ts(1,7): error TS2322: Type 'string' is not assignable to type 'number'.\"\nexit 2\n",
        );

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "typescript.check",
                "path": "src/broken.ts",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics result");

        assert_eq!(result["backend"], "typescript.project.check");
        assert_eq!(result["resolvedCommandId"], "typescript.check");
        assert_eq!(
            result["command"],
            "tsc --noEmit --pretty false -p tsconfig.json"
        );
        assert_eq!(result["backendStatus"], "available");
        assert_eq!(result["diagnosticStatus"], "findings");
        assert_eq!(result["diagnosticCount"], 1);
        assert_eq!(result["diagnostics"][0]["path"], "src/broken.ts");
        assert_eq!(result["diagnostics"][0]["code"], "TS2322");
        assert_eq!(result["diagnostics"][0]["line"], 1);
        assert_eq!(result["diagnostics"][0]["column"], 7);
        assert_eq!(result["projectContext"]["tsconfigPath"], "tsconfig.json");
        assert_eq!(result["projectContext"]["tscAvailable"], true);
    }

    #[test]
    fn lsp_diagnostics_auto_typescript_degrades_without_local_tsc() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let source_dir = workspace.join("src");
        fs::create_dir_all(&source_dir).expect("source dir");
        fs::write(
            workspace.join("tsconfig.json"),
            r#"{"compilerOptions":{"strict":true},"include":["src/**/*.ts"]}"#,
        )
        .expect("tsconfig");
        fs::write(
            source_dir.join("broken.ts"),
            "const value: number = 'oops';\n",
        )
        .expect("ts fixture");

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "auto",
                "path": "src/broken.ts",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics result");

        assert_eq!(result["backend"], "typescript.project.check");
        assert_eq!(result["resolvedCommandId"], "typescript.check");
        assert_eq!(result["backendStatus"], "degraded");
        assert_eq!(result["backendReason"], "typescript_executable_missing");
        assert_eq!(result["diagnosticStatus"], "degraded");
        assert_eq!(result["projectContext"]["tscAvailable"], false);
        assert_eq!(result["fallbackUsed"], false);
    }

    #[test]
    fn git_diff_reads_bounded_workspace_diff() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        run_test_git(&workspace, &["init"]);
        run_test_git(&workspace, &["config", "user.email", "test@example.com"]);
        run_test_git(&workspace, &["config", "user.name", "IOI Test"]);
        fs::write(workspace.join("README.md"), "before\n").expect("fixture file");
        run_test_git(&workspace, &["add", "README.md"]);
        run_test_git(&workspace, &["commit", "-m", "initial"]);
        fs::write(workspace.join("README.md"), "before\nafter\n").expect("updated file");

        let result = inspect_git_diff(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "path": "README.md",
                "maxBytes": 4096
            }),
        )
        .expect("diff result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["paths"], json!(["README.md"]));
        assert_eq!(result["git"]["available"], true);
        assert!(result["diff"].as_str().expect("diff").contains("+after"));
        assert!(result["stat"].as_str().expect("stat").contains("README.md"));
        assert_eq!(result["diffHash"].as_str().expect("hash").len(), 64);
        assert_eq!(result["truncated"], false);
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn git_diff_rejects_paths_outside_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");

        let error = inspect_git_diff(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "path": "../outside.txt"
            }),
        )
        .expect_err("outside path should fail");

        assert_eq!(error.code(), "path_outside_workspace");
    }

    #[test]
    fn file_inspect_reads_workspace_file_preview() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("README.md"), "# IOI\nsecond line\n").expect("fixture file");

        let result = inspect_workspace_path(
            workspace.to_str().expect("utf8 path"),
            "README.md",
            &json!({
                "maxBytes": 128,
                "previewLines": 1
            }),
        )
        .expect("inspect result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["path"], "README.md");
        assert_eq!(result["kind"], "file");
        assert_eq!(result["preview"], "# IOI");
        assert_eq!(result["previewLineCount"], 1);
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn file_inspect_rejects_paths_outside_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(temp.path().join("outside.txt"), "outside").expect("outside fixture");

        let error = inspect_workspace_path(
            workspace.to_str().expect("utf8 path"),
            "../outside.txt",
            &json!({}),
        )
        .expect_err("outside path should fail");

        assert_eq!(error.code(), "path_outside_workspace");
    }

    fn run_test_git(workspace: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(workspace)
            .args(args)
            .output()
            .expect("git command");
        assert!(
            output.status.success(),
            "git {:?} failed: {}{}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn bridge_request(
        tool_id: &str,
        workspace_root: &str,
        input: Value,
    ) -> StepModuleBridgeRequest {
        let invocation = serde_json::from_value(json!({
            "schema_version": "ioi.step_module_invocation.v1",
            "invocation_id": format!("invocation://test/{tool_id}"),
            "run_id": "run:test",
            "task_id": "task:test",
            "thread_id": "thread:test",
            "workflow_graph_id": "graph:test",
            "workflow_node_id": format!("node:test:{tool_id}"),
            "context_chamber_ref": null,
            "action_proposal_ref": format!("action:test:{tool_id}"),
            "gate_result_ref": format!("gate:test:{tool_id}"),
            "module_ref": {
                "kind": "workload_job",
                "id": tool_id,
                "version": "test",
                "manifest_ref": null
            },
            "actor": {
                "actor_id": "runtime:hypervisor-daemon",
                "runtime_node_ref": "node://local"
            },
            "authority": {
                "authority_grant_refs": [],
                "policy_hash": "sha256:policy",
                "primitive_capabilities": ["prim:fs.apply_patch", "prim:fs.write"],
                "authority_scopes": ["scope:workspace.write"],
                "approval_ref": "approval:test"
            },
            "input": {
                "input_hash": "sha256:input",
                "expected_schema_ref": format!("schema://coding-tool/{tool_id}/input"),
                "context_refs": [],
                "artifact_refs": [],
                "payload_refs": [],
                "state_root_before": null,
                "projection_watermark": null,
                "data_plane_handle": null
            },
            "custody": {
                "privacy_profile": "internal",
                "plaintext_policy": {
                    "node_plaintext_allowed": true,
                    "declassification_required": false
                },
                "custody_proof_ref": null,
                "leakage_profile_ref": null
            },
            "execution": {
                "backend": "workload_grpc",
                "idempotency_key": format!("idempotency:test:{tool_id}"),
                "deadline_ms": 60000,
                "resource_lease_ref": null,
                "retry_policy_ref": null
            }
        }))
        .expect("test invocation");
        StepModuleBridgeRequest {
            backend: "rust_workload_live".to_string(),
            invocation,
            workspace_root: Some(workspace_root.to_string()),
            input,
        }
    }

    #[cfg(unix)]
    fn write_fake_executable(path: &Path, content: &str) {
        fs::write(path, content).expect("fake executable");
        let mut permissions = fs::metadata(path)
            .expect("fake executable metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("fake executable permissions");
    }
}
