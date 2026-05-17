use anyhow::{Context, Result};
use std::path::PathBuf;

pub fn print_lifecycle_readiness(manifest_path: PathBuf, json: bool) -> Result<()> {
    let manifest_content = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("read manifest {}", manifest_path.display()))?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest_content)
        .with_context(|| format!("parse manifest {}", manifest_path.display()))?;
    let projection = lifecycle_readiness_projection(&manifest);
    if json {
        println!("{}", serde_json::to_string_pretty(&projection)?);
        return Ok(());
    }

    let system_id = lifecycle_string(&manifest, &["systemId"])
        .unwrap_or_else(|| "system://unidentified".to_string());
    let status = projection
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("blocked");
    println!("Autonomous System Package: {system_id}");
    println!("Lifecycle readiness: {status}");
    if let Some(categories) = projection
        .get("categories")
        .and_then(serde_json::Value::as_array)
    {
        for category in categories {
            let label = category
                .get("label")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Readiness");
            let category_status = category
                .get("status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("blocked");
            println!("- {label}: {category_status}");
        }
    }
    Ok(())
}

pub fn lifecycle_readiness_projection(manifest: &serde_json::Value) -> serde_json::Value {
    let categories = vec![
        lifecycle_category(
            "run",
            "Run readiness",
            "Blocks Run",
            vec![
                lifecycle_missing(
                    lifecycle_string(manifest, &["workflow", "workflowManifestRef"]),
                    "workflow manifest ref missing",
                ),
                lifecycle_missing(
                    !lifecycle_strings(manifest, &["capabilities", "modelCapabilityRefs"])
                        .is_empty(),
                    "model capability refs missing",
                ),
            ],
            Vec::new(),
        ),
        lifecycle_category(
            "authority",
            "Authority readiness",
            "Blocks live effects",
            vec![
                lifecycle_missing(
                    !lifecycle_strings(manifest, &["authority", "authorityScopeRequirements"])
                        .is_empty(),
                    "authority scope requirements missing",
                ),
                lifecycle_missing(
                    lifecycle_string(manifest, &["authority", "revocationPosture"]).as_deref()
                        == Some("fail_closed"),
                    "revocation posture must fail closed",
                ),
            ],
            Vec::new(),
        ),
        lifecycle_category(
            "package",
            "Package readiness",
            "Blocks package/publish",
            vec![
                lifecycle_missing(
                    lifecycle_string(manifest, &["worker", "workerRef"]),
                    "worker ref missing",
                ),
                lifecycle_missing(
                    lifecycle_string(manifest, &["workflow", "workflowManifestRef"]),
                    "workflow manifest ref missing",
                ),
                lifecycle_missing(
                    !lifecycle_strings(manifest, &["capabilities", "modelCapabilityRefs"])
                        .is_empty(),
                    "model capability refs missing",
                ),
                lifecycle_missing(
                    lifecycle_tool_or_connector_count(manifest) > 0,
                    "tool or connector capability refs missing",
                ),
                lifecycle_missing(
                    !lifecycle_strings(manifest, &["authority", "authorityScopeRequirements"])
                        .is_empty(),
                    "authority scope requirements missing",
                ),
            ],
            Vec::new(),
        ),
        lifecycle_category(
            "evaluation",
            "Evaluation readiness",
            "Blocks promotion",
            vec![lifecycle_missing(
                !lifecycle_strings(manifest, &["evaluation", "evalProfileRefs"]).is_empty(),
                "eval profile refs missing",
            )],
            Vec::new(),
        ),
        lifecycle_category(
            "deployment",
            "Deployment readiness",
            "Blocks deploy",
            vec![lifecycle_missing(
                lifecycle_runtime_profile_ready(manifest),
                "runtime profile missing",
            )],
            Vec::new(),
        ),
        lifecycle_category(
            "promotion",
            "Promotion readiness",
            "Blocks promotion",
            vec![
                lifecycle_missing(
                    !lifecycle_strings(manifest, &["evaluation", "evalProfileRefs"]).is_empty(),
                    "eval profile refs missing",
                ),
                lifecycle_missing(
                    !lifecycle_strings(manifest, &["receipts", "latestEvalReceiptRefs"]).is_empty(),
                    "eval receipt evidence missing",
                ),
                lifecycle_missing(
                    lifecycle_string(manifest, &["promotion", "promotionProfileRef"]).is_some()
                        || !lifecycle_strings(manifest, &["evaluation", "qualityGateRefs"])
                            .is_empty(),
                    "promotion profile or quality gate missing",
                ),
            ],
            lifecycle_strings(manifest, &["receipts", "latestEvalReceiptRefs"]),
        ),
    ];
    let status = if categories.iter().any(|category| {
        category.get("status").and_then(serde_json::Value::as_str) == Some("blocked")
    }) {
        "blocked"
    } else {
        "ready"
    };
    serde_json::json!({
        "schemaVersion": "ioi.workflow.lifecycle-readiness.v1",
        "packageArtifact": "Autonomous System Package",
        "lifecycleLoop": [
            "compose",
            "bind",
            "simulate",
            "authorize",
            "run",
            "verify",
            "inspect_receipts",
            "package",
            "deploy",
            "promote",
            "improve"
        ],
        "systemId": lifecycle_string(manifest, &["systemId"]).unwrap_or_else(|| "system://unidentified".to_string()),
        "manifest": manifest,
        "categories": categories,
        "status": status
    })
}

fn lifecycle_category(
    kind: &str,
    label: &str,
    blocking_scope: &str,
    blockers: Vec<Option<&'static str>>,
    evidence_refs: Vec<String>,
) -> serde_json::Value {
    let blockers: Vec<&str> = blockers.into_iter().flatten().collect();
    let status = if blockers.is_empty() {
        "ready"
    } else {
        "blocked"
    };
    let summary = if status == "ready" {
        "Ready"
    } else {
        "Needs attention"
    };
    serde_json::json!({
        "kind": kind,
        "label": label,
        "status": status,
        "blockingScope": blocking_scope,
        "summary": summary,
        "blockers": blockers,
        "warnings": [],
        "evidenceRefs": evidence_refs
    })
}

fn lifecycle_json_path<'a>(
    value: &'a serde_json::Value,
    path: &[&str],
) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

fn lifecycle_string(value: &serde_json::Value, path: &[&str]) -> Option<String> {
    lifecycle_json_path(value, path)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn lifecycle_strings(value: &serde_json::Value, path: &[&str]) -> Vec<String> {
    lifecycle_json_path(value, path)
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn lifecycle_missing<T>(value: T, message: &'static str) -> Option<&'static str>
where
    T: IntoLifecyclePresent,
{
    if value.into_present() {
        None
    } else {
        Some(message)
    }
}

trait IntoLifecyclePresent {
    fn into_present(self) -> bool;
}

impl IntoLifecyclePresent for bool {
    fn into_present(self) -> bool {
        self
    }
}

impl IntoLifecyclePresent for Option<String> {
    fn into_present(self) -> bool {
        self.is_some()
    }
}

fn lifecycle_tool_or_connector_count(manifest: &serde_json::Value) -> usize {
    lifecycle_strings(manifest, &["capabilities", "toolCapabilityRefs"]).len()
        + lifecycle_strings(manifest, &["capabilities", "connectorRefs"]).len()
}

fn lifecycle_runtime_profile_ready(manifest: &serde_json::Value) -> bool {
    lifecycle_json_path(manifest, &["runtimeProfiles"])
        .and_then(serde_json::Value::as_array)
        .map(|profiles| {
            profiles.iter().any(|profile| {
                lifecycle_string(profile, &["readiness"])
                    .map(|readiness| {
                        readiness == "ready" || readiness == "degraded" || readiness == "external"
                    })
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_readiness_blocks_promotion_without_eval_receipts() {
        let manifest = serde_json::json!({
            "systemId": "system://repo-maintenance",
            "worker": { "workerRef": "worker://repo-maintenance" },
            "workflow": { "workflowManifestRef": "workflow.json" },
            "capabilities": {
                "modelCapabilityRefs": ["model-capability:local"],
                "toolCapabilityRefs": ["tool-capability:file.apply_patch"],
                "connectorRefs": []
            },
            "authority": {
                "authorityScopeRequirements": ["scope:workspace.write"],
                "revocationPosture": "fail_closed"
            },
            "runtimeProfiles": [{ "readiness": "ready" }],
            "evaluation": {
                "evalProfileRefs": ["eval://repo-maintenance"],
                "qualityGateRefs": ["gate://quality/repo-maintenance"]
            },
            "promotion": {
                "promotionProfileRef": "profile://promotion/repo-maintenance"
            },
            "receipts": { "latestEvalReceiptRefs": [] }
        });

        let projection = lifecycle_readiness_projection(&manifest);
        assert_eq!(
            projection["status"],
            serde_json::Value::String("blocked".to_string())
        );
        let promotion = projection["categories"]
            .as_array()
            .and_then(|categories| {
                categories.iter().find(|category| {
                    category.get("kind").and_then(serde_json::Value::as_str) == Some("promotion")
                })
            })
            .expect("promotion category should be present");
        assert_eq!(
            promotion["blockers"],
            serde_json::json!(["eval receipt evidence missing"])
        );
    }
}
