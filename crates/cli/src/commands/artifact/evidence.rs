use anyhow::{Context, Result};
use ioi_api::studio::{
    parse_studio_generated_artifact_payload, pdf_artifact_bytes, StudioArtifactBlueprint,
    StudioArtifactCandidateSummary, StudioArtifactSelectedSkill, StudioArtifactTasteMemory,
    StudioArtifactUxLifecycle, StudioArtifactValidationResult, StudioArtifactValidationStatus,
    StudioGeneratedArtifactFile, StudioGeneratedArtifactPayload,
};
use ioi_types::app::{
    StudioArtifactFailure, StudioArtifactFileRole, StudioArtifactLifecycleState,
    StudioArtifactManifest, StudioArtifactManifestFile, StudioArtifactManifestStorage,
    StudioArtifactManifestTab, StudioArtifactManifestVerification, StudioArtifactPersistenceMode,
    StudioArtifactTabKind, StudioArtifactVerificationStatus, StudioOutcomeArtifactRequest,
    StudioRendererKind, StudioRuntimeProvenance,
};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use super::types::{ArtifactLaneReceipt, GeneratedArtifactEvidence, LoadedRefinementEvidence};
use super::workspace::workspace_recipe_for_request;

pub(super) fn run_validation_result(evidence_path: &Path, json_output: bool) -> Result<()> {
    let evidence = load_generated_evidence(evidence_path)?;
    let validation = evidence
        .validation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Generated evidence is missing a validation result."))?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(validation)?);
        return Ok(());
    }

    println!("Validation: {}", format_validation_label(validation));
    println!("  rationale: {}", validation.rationale);
    if let Some(contradiction) = &validation.strongest_contradiction {
        println!("  strongest contradiction: {}", contradiction);
    }
    println!(
        "  faithfulness / coverage / interaction: {}/{}/{}",
        validation.request_faithfulness,
        validation.concept_coverage,
        validation.interaction_relevance
    );
    Ok(())
}

pub(super) fn derive_generated_artifact_title(prompt: &str) -> String {
    let trimmed = prompt.trim();
    let first_line = trimmed.lines().next().unwrap_or("Studio artifact");
    let normalized = first_line
        .trim_start_matches("Create ")
        .trim_start_matches("create ")
        .trim();
    if normalized.is_empty() {
        "Studio artifact".to_string()
    } else {
        normalized.chars().take(72).collect::<String>()
    }
}

fn artifact_lane_receipt(
    kind: &str,
    status: &str,
    title: &str,
    summary: String,
    details: Vec<String>,
) -> ArtifactLaneReceipt {
    ArtifactLaneReceipt {
        receipt_id: kind.to_string(),
        kind: kind.to_string(),
        status: status.to_string(),
        title: title.to_string(),
        summary,
        details,
    }
}

pub(super) fn build_artifact_lane_receipts(
    blueprint: Option<&StudioArtifactBlueprint>,
    selected_skills: &[StudioArtifactSelectedSkill],
    candidate_summaries: &[StudioArtifactCandidateSummary],
    validation: &StudioArtifactValidationResult,
    ux_lifecycle: StudioArtifactUxLifecycle,
) -> Vec<ArtifactLaneReceipt> {
    let component_families = blueprint
        .map(|resolved| {
            resolved
                .component_plan
                .iter()
                .map(|component| component.component_family.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let repair_passes = candidate_summaries
        .iter()
        .filter_map(|candidate| candidate.convergence.as_ref())
        .map(|trace| {
            format!(
                "{} pass {} score {}",
                trace.pass_kind, trace.pass_index, trace.score_total
            )
        })
        .collect::<Vec<_>>();

    vec![
        artifact_lane_receipt(
            "blueprint_family",
            if blueprint.is_some() {
                "success"
            } else {
                "warning"
            },
            "Blueprint family",
            blueprint
                .map(|resolved| {
                    format!(
                        "{} with {} sections and {} interaction contracts.",
                        resolved.scaffold_family,
                        resolved.section_plan.len(),
                        resolved.interaction_plan.len()
                    )
                })
                .unwrap_or_else(|| {
                    "No typed blueprint was retained for this artifact.".to_string()
                }),
            blueprint
                .map(|resolved| {
                    vec![
                        format!("narrative_arc={}", resolved.narrative_arc),
                        format!("variation_strategy={}", resolved.variation_strategy),
                    ]
                })
                .unwrap_or_default(),
        ),
        artifact_lane_receipt(
            "skill_discovery_evidence",
            if selected_skills.is_empty() {
                "warning"
            } else {
                "success"
            },
            "Skill discovery evidence",
            if selected_skills.is_empty() {
                "No runtime-selected skills were retained for this artifact.".to_string()
            } else {
                format!(
                    "{} retained skill matches support this artifact.",
                    selected_skills.len()
                )
            },
            selected_skills
                .iter()
                .map(|skill| format!("{} -> {}", skill.name, skill.match_rationale))
                .collect(),
        ),
        artifact_lane_receipt(
            "scaffold_family",
            if blueprint.is_some() {
                "success"
            } else {
                "warning"
            },
            "Scaffold family",
            blueprint
                .map(|resolved| {
                    format!(
                        "Scaffold '{}' governs the primary artifact surface.",
                        resolved.scaffold_family
                    )
                })
                .unwrap_or_else(|| "Scaffold selection was not retained.".to_string()),
            blueprint
                .map(|resolved| {
                    vec![
                        format!(
                            "design_system={} / {}",
                            resolved.design_system.color_strategy,
                            resolved.design_system.typography_strategy
                        ),
                        format!(
                            "accessibility_obligations={}",
                            resolved.accessibility_plan.obligations.len()
                        ),
                    ]
                })
                .unwrap_or_default(),
        ),
        artifact_lane_receipt(
            "component_pack_inventory",
            if component_families.is_empty() {
                "warning"
            } else {
                "success"
            },
            "Component pack inventory",
            if component_families.is_empty() {
                "No structural component families were retained.".to_string()
            } else {
                format!(
                    "{} component families were retained for composition.",
                    component_families.len()
                )
            },
            component_families,
        ),
        artifact_lane_receipt(
            "audit_findings",
            if validation.issue_classes.is_empty() && validation.truthfulness_warnings.is_empty() {
                "success"
            } else if validation.classification == StudioArtifactValidationStatus::Blocked {
                "blocked"
            } else {
                "warning"
            },
            "Audit findings",
            if validation.issue_classes.is_empty() && validation.truthfulness_warnings.is_empty() {
                "Static audit retained no structural or truthfulness warnings.".to_string()
            } else {
                format!(
                    "{} issue classes and {} truthfulness warnings retained.",
                    validation.issue_classes.len(),
                    validation.truthfulness_warnings.len()
                )
            },
            validation
                .issue_classes
                .iter()
                .cloned()
                .chain(validation.truthfulness_warnings.iter().cloned())
                .chain(validation.file_findings.iter().cloned())
                .collect(),
        ),
        artifact_lane_receipt(
            "validation_findings",
            match validation.classification {
                StudioArtifactValidationStatus::Pass => "success",
                StudioArtifactValidationStatus::Repairable => "warning",
                StudioArtifactValidationStatus::Blocked => "blocked",
            },
            "Validation findings",
            format!(
                "{:?} :: {}",
                validation.classification, validation.rationale
            ),
            validation
                .strengths
                .iter()
                .cloned()
                .chain(validation.blocked_reasons.iter().cloned())
                .collect(),
        ),
        artifact_lane_receipt(
            "repair_passes",
            if repair_passes.is_empty() {
                "success"
            } else {
                "warning"
            },
            "Repair passes",
            if repair_passes.is_empty() {
                "No targeted repair passes were retained beyond the selected winner.".to_string()
            } else {
                format!(
                    "{} targeted repair traces were retained.",
                    repair_passes.len()
                )
            },
            repair_passes,
        ),
        artifact_lane_receipt(
            "presentation_gate",
            if validation.deserves_primary_artifact_view {
                "success"
            } else {
                "warning"
            },
            "Final presentation gate",
            format!(
                "Primary artifact eligibility={} with lifecycle {:?}.",
                validation.deserves_primary_artifact_view, ux_lifecycle
            ),
            vec![
                format!("classification={:?}", validation.classification),
                format!(
                    "generic_shell_detected={}",
                    validation.generic_shell_detected
                ),
                format!(
                    "trivial_shell_detected={}",
                    validation.trivial_shell_detected
                ),
            ],
        ),
    ]
}

pub(super) fn write_generated_payload(
    output: &Path,
    title: &str,
    payload: &StudioGeneratedArtifactPayload,
) -> Result<()> {
    for file in &payload.files {
        let target_path = output.join(&file.path);
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed to create parent directory '{}' for '{}'.",
                    parent.display(),
                    target_path.display()
                )
            })?;
        }
        let bytes = if file.mime.eq_ignore_ascii_case("application/pdf")
            || file.path.to_ascii_lowercase().ends_with(".pdf")
        {
            pdf_artifact_bytes(title, &file.body)
        } else if let Some(unwrapped_html) = unwrap_nested_html_artifact_body(file) {
            unwrapped_html.into_bytes()
        } else {
            file.body.as_bytes().to_vec()
        };
        fs::write(&target_path, bytes)
            .with_context(|| format!("Failed to write '{}'.", target_path.display()))?;
    }
    Ok(())
}

fn unwrap_nested_html_artifact_body(file: &StudioGeneratedArtifactFile) -> Option<String> {
    if !(file.mime.eq_ignore_ascii_case("text/html")
        || file.path.to_ascii_lowercase().ends_with(".html"))
    {
        return None;
    }

    let trimmed = file.body.trim();
    if trimmed.is_empty() || (!trimmed.starts_with('{') && !trimmed.starts_with("```")) {
        return None;
    }

    let nested_payload = parse_studio_generated_artifact_payload(trimmed).ok()?;
    let nested_primary = nested_payload.files.iter().find(|nested_file| {
        matches!(
            nested_file.role,
            StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
        ) && (nested_file.mime.eq_ignore_ascii_case("text/html")
            || nested_file.path.to_ascii_lowercase().ends_with(".html"))
    })?;
    let nested_body = nested_primary.body.trim();
    let nested_lower = nested_body.to_ascii_lowercase();
    if nested_body.is_empty()
        || nested_body == trimmed
        || !(nested_lower.contains("<html") || nested_lower.contains("<!doctype html"))
    {
        return None;
    }

    Some(nested_body.to_string())
}

pub(super) fn generated_tabs_for_request(
    request: &StudioOutcomeArtifactRequest,
    payload: &StudioGeneratedArtifactPayload,
) -> Vec<StudioArtifactManifestTab> {
    let recipe = workspace_recipe_for_request(request);
    let primary_path = payload
        .files
        .iter()
        .find(|file| file.role == StudioArtifactFileRole::Primary)
        .map(|file| file.path.clone())
        .or_else(|| payload.files.first().map(|file| file.path.clone()));
    if request.renderer == StudioRendererKind::WorkspaceSurface {
        return vec![
            StudioArtifactManifestTab {
                id: "preview".to_string(),
                label: "Preview".to_string(),
                kind: StudioArtifactTabKind::Render,
                renderer: Some(StudioRendererKind::HtmlIframe),
                file_path: None,
                lens: Some("preview".to_string()),
            },
            StudioArtifactManifestTab {
                id: "workspace".to_string(),
                label: "Workspace".to_string(),
                kind: StudioArtifactTabKind::Workspace,
                renderer: Some(StudioRendererKind::WorkspaceSurface),
                file_path: Some(recipe.entry_document().to_string()),
                lens: Some("code".to_string()),
            },
            StudioArtifactManifestTab {
                id: "evidence".to_string(),
                label: "Evidence".to_string(),
                kind: StudioArtifactTabKind::Evidence,
                renderer: None,
                file_path: None,
                lens: Some("evidence".to_string()),
            },
        ];
    }
    match request.renderer {
        StudioRendererKind::DownloadCard => vec![
            StudioArtifactManifestTab {
                id: "download".to_string(),
                label: "Download".to_string(),
                kind: StudioArtifactTabKind::Download,
                renderer: Some(StudioRendererKind::DownloadCard),
                file_path: primary_path,
                lens: Some("download".to_string()),
            },
            StudioArtifactManifestTab {
                id: "evidence".to_string(),
                label: "Evidence".to_string(),
                kind: StudioArtifactTabKind::Evidence,
                renderer: None,
                file_path: None,
                lens: Some("evidence".to_string()),
            },
        ],
        _ => vec![
            StudioArtifactManifestTab {
                id: "render".to_string(),
                label: "Render".to_string(),
                kind: StudioArtifactTabKind::Render,
                renderer: Some(request.renderer),
                file_path: primary_path.clone(),
                lens: Some("render".to_string()),
            },
            StudioArtifactManifestTab {
                id: "source".to_string(),
                label: "Source".to_string(),
                kind: StudioArtifactTabKind::Source,
                renderer: None,
                file_path: primary_path,
                lens: Some("source".to_string()),
            },
            StudioArtifactManifestTab {
                id: "evidence".to_string(),
                label: "Evidence".to_string(),
                kind: StudioArtifactTabKind::Evidence,
                renderer: None,
                file_path: None,
                lens: Some("evidence".to_string()),
            },
        ],
    }
}

pub(super) fn manifest_verification_from_validation(
    validation: &StudioArtifactValidationResult,
    production_provenance: &StudioRuntimeProvenance,
    acceptance_provenance: &StudioRuntimeProvenance,
    failure: Option<&StudioArtifactFailure>,
) -> StudioArtifactManifestVerification {
    let lifecycle_state = match validation.classification {
        StudioArtifactValidationStatus::Pass => StudioArtifactLifecycleState::Ready,
        StudioArtifactValidationStatus::Repairable => StudioArtifactLifecycleState::Partial,
        StudioArtifactValidationStatus::Blocked => StudioArtifactLifecycleState::Blocked,
    };
    let status = match lifecycle_state {
        StudioArtifactLifecycleState::Ready => StudioArtifactVerificationStatus::Ready,
        StudioArtifactLifecycleState::Partial => StudioArtifactVerificationStatus::Partial,
        StudioArtifactLifecycleState::Blocked => StudioArtifactVerificationStatus::Blocked,
        _ => StudioArtifactVerificationStatus::Failed,
    };

    StudioArtifactManifestVerification {
        status,
        lifecycle_state,
        summary: validation.rationale.clone(),
        production_provenance: Some(production_provenance.clone()),
        acceptance_provenance: Some(acceptance_provenance.clone()),
        failure: failure.cloned(),
    }
}

pub(super) fn build_generated_manifest(
    title: &str,
    request: &StudioOutcomeArtifactRequest,
    payload: &StudioGeneratedArtifactPayload,
    validation: &StudioArtifactValidationResult,
    production_provenance: &StudioRuntimeProvenance,
    acceptance_provenance: &StudioRuntimeProvenance,
    failure: Option<&StudioArtifactFailure>,
) -> StudioArtifactManifest {
    let mut files = payload
        .files
        .iter()
        .map(|file| StudioArtifactManifestFile {
            path: file.path.clone(),
            mime: file.mime.clone(),
            role: match file.role {
                StudioArtifactFileRole::Primary => StudioArtifactFileRole::Primary,
                StudioArtifactFileRole::Source => StudioArtifactFileRole::Source,
                StudioArtifactFileRole::Export => StudioArtifactFileRole::Export,
                StudioArtifactFileRole::Supporting => StudioArtifactFileRole::Supporting,
            },
            renderable: file.renderable,
            downloadable: file.downloadable,
            artifact_id: Some(format!("generated-{}", file.path.replace('/', "-"))),
            external_url: None,
        })
        .collect::<Vec<_>>();
    if request.renderer == StudioRendererKind::WorkspaceSurface {
        files.push(StudioArtifactManifestFile {
            path: "artifact-manifest.json".to_string(),
            mime: "application/json".to_string(),
            role: StudioArtifactFileRole::Supporting,
            renderable: false,
            downloadable: true,
            artifact_id: Some("generated-artifact-manifest".to_string()),
            external_url: None,
        });
    }

    StudioArtifactManifest {
        artifact_id: Uuid::new_v4().to_string(),
        title: title.to_string(),
        artifact_class: request.artifact_class,
        renderer: request.renderer,
        primary_tab: if request.renderer == StudioRendererKind::WorkspaceSurface {
            "workspace".to_string()
        } else if request.renderer == StudioRendererKind::DownloadCard {
            "download".to_string()
        } else {
            "render".to_string()
        },
        tabs: generated_tabs_for_request(request, payload),
        files,
        verification: manifest_verification_from_validation(
            validation,
            production_provenance,
            acceptance_provenance,
            failure,
        ),
        storage: Some(StudioArtifactManifestStorage {
            mode: StudioArtifactPersistenceMode::ArtifactScoped,
            api_label: Some("artifact storage".to_string()),
        }),
    }
}

pub(super) fn resolve_generation_json_path(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.join("generation.json")
    } else {
        path.to_path_buf()
    }
}

pub(super) fn load_generated_evidence(path: &Path) -> Result<GeneratedArtifactEvidence> {
    let evidence_path = resolve_generation_json_path(path);
    let bytes = fs::read(&evidence_path)
        .with_context(|| format!("Failed to read '{}'.", evidence_path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("Failed to parse '{}'.", evidence_path.display()))
}

pub(super) fn load_refinement_evidence(
    path: Option<&Path>,
) -> Result<Option<LoadedRefinementEvidence>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let evidence = load_generated_evidence(path)?;
    let evidence_root = resolve_generation_json_path(path)
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("Refinement evidence path has no parent directory."))?;
    let files = evidence
        .manifest
        .files
        .iter()
        .filter_map(|file| {
            let file_path = evidence_root.join(&file.path);
            if !file_path.exists() || !super::manifest::should_read_as_text(&file.path, &file.mime)
            {
                return None;
            }
            let body = fs::read_to_string(&file_path).ok()?;
            Some(StudioGeneratedArtifactFile {
                path: file.path.clone(),
                mime: file.mime.clone(),
                role: file.role,
                renderable: file.renderable,
                downloadable: file.downloadable,
                encoding: None,
                body,
            })
        })
        .collect::<Vec<_>>();

    Ok(Some(LoadedRefinementEvidence {
        artifact_id: Some(evidence.manifest.artifact_id),
        revision_id: None,
        title: evidence.title,
        summary: evidence.verified_reply.summary,
        renderer: evidence.manifest.renderer,
        files,
        selected_targets: evidence
            .edit_intent
            .as_ref()
            .map(|intent| intent.selected_targets.clone())
            .unwrap_or_default(),
        taste_memory: evidence
            .artifact_brief
            .as_ref()
            .map(|brief| StudioArtifactTasteMemory {
                directives: brief.style_directives.clone(),
                summary: brief.artifact_thesis.clone(),
                typography_preferences: Vec::new(),
                density_preference: None,
                tone_family: brief.visual_tone.clone(),
                motion_tolerance: None,
                preferred_scaffold_families: Vec::new(),
                preferred_component_patterns: Vec::new(),
                anti_patterns: Vec::new(),
            }),
    }))
}

pub(super) fn format_validation_label(validation: &StudioArtifactValidationResult) -> &'static str {
    match validation.classification {
        StudioArtifactValidationStatus::Pass => "pass",
        StudioArtifactValidationStatus::Repairable => "repairable",
        StudioArtifactValidationStatus::Blocked => "blocked",
    }
}

#[cfg(test)]
#[path = "evidence/tests.rs"]
mod tests;
