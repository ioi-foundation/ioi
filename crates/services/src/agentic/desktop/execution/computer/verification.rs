use super::super::resilience;
use super::click::click_by_som_id;
use super::{ToolExecutionResult, ToolExecutor};
use ioi_api::vm::drivers::gui::MouseButton;
use serde_json::json;
use std::collections::BTreeMap;

fn append_verify_metadata(
    mut result: ToolExecutionResult,
    verify: serde_json::Value,
) -> ToolExecutionResult {
    if !result.success {
        return result;
    }

    let base = result
        .history_entry
        .take()
        .unwrap_or_else(|| "GUI click executed".to_string());
    result.history_entry = Some(format!("{base}. verify={verify}"));
    result
}

fn verification_attempt_payload(
    attempt: u32,
    verification: &resilience::verifier::VerificationResult,
) -> serde_json::Value {
    json!({
        "attempt": attempt,
        "tree_changed": verification.tree_changed,
        "visual_distance": verification.visual_distance,
        "significant": verification.is_significant(),
    })
}

pub(super) async fn execute_verified_gui_click_element_som(
    exec: &ToolExecutor,
    som_id: u32,
    som_map: Option<&BTreeMap<u32, (i32, i32, i32, i32)>>,
    active_lens: Option<&str>,
) -> Option<ToolExecutionResult> {
    let before_snapshot =
        resilience::verifier::ActionVerifier::capture_snapshot(exec, active_lens).await;
    let mut attempts: Vec<serde_json::Value> = Vec::new();

    let first = click_by_som_id(exec, som_id, som_map, MouseButton::Left).await?;
    if !first.success {
        return Some(first);
    }

    let before_snapshot = match before_snapshot {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let verify = json!({
                "method": "som_id",
                "som_id": som_id,
                "snapshot": "unavailable",
                "snapshot_error": error,
                "postcondition": { "met": true },
            });
            return Some(append_verify_metadata(first, verify));
        }
    };

    tokio::time::sleep(std::time::Duration::from_millis(220)).await;
    match resilience::verifier::ActionVerifier::capture_snapshot(exec, active_lens).await {
        Ok(after_first) => {
            let verification =
                resilience::verifier::ActionVerifier::verify_impact(&before_snapshot, &after_first);
            attempts.push(verification_attempt_payload(1, &verification));
            if verification.is_significant() {
                let verify = json!({
                    "method": "som_id",
                    "som_id": som_id,
                    "snapshot": "available",
                    "postcondition": { "met": true },
                    "attempts": attempts,
                });
                return Some(append_verify_metadata(first, verify));
            }
        }
        Err(error) => {
            let verify = json!({
                "method": "som_id",
                "som_id": som_id,
                "snapshot": "unavailable",
                "snapshot_error": error,
                "postcondition": { "met": true },
            });
            return Some(append_verify_metadata(first, verify));
        }
    }

    let retry = match click_by_som_id(exec, som_id, som_map, MouseButton::Left).await {
        Some(result) => result,
        None => {
            return Some(ToolExecutionResult::failure(format!(
                "ERROR_CLASS=TargetNotFound SoM ID {} could not be resolved for retry.",
                som_id
            )))
        }
    };
    if !retry.success {
        return Some(retry);
    }

    tokio::time::sleep(std::time::Duration::from_millis(220)).await;
    match resilience::verifier::ActionVerifier::capture_snapshot(exec, active_lens).await {
        Ok(after_retry) => {
            let verification =
                resilience::verifier::ActionVerifier::verify_impact(&before_snapshot, &after_retry);
            attempts.push(verification_attempt_payload(2, &verification));
            if verification.is_significant() {
                let verify = json!({
                    "method": "som_id",
                    "som_id": som_id,
                    "snapshot": "available",
                    "postcondition": { "met": true },
                    "attempts": attempts,
                });
                return Some(append_verify_metadata(retry, verify));
            }

            let verify = json!({
                "method": "som_id",
                "som_id": som_id,
                "snapshot": "available",
                "postcondition": { "met": false },
                "attempts": attempts,
            });
            Some(ToolExecutionResult::failure(format!(
                "ERROR_CLASS=NoEffectAfterAction UI state static after SoM click (som_id={}). verify={}",
                som_id, verify
            )))
        }
        Err(error) => {
            let verify = json!({
                "method": "som_id",
                "som_id": som_id,
                "snapshot": "unavailable",
                "snapshot_error": error,
                "postcondition": { "met": true },
                "attempts": attempts,
            });
            Some(append_verify_metadata(retry, verify))
        }
    }
}
