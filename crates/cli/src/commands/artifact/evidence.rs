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
mod tests {
    use super::*;
    use ioi_api::studio::{
        StudioArtifactAcceptanceTargets, StudioArtifactAccessibilityPlan,
        StudioArtifactCandidateConvergenceTrace, StudioArtifactComponentPlanEntry,
        StudioArtifactDesignSystem, StudioArtifactOutputOrigin, StudioArtifactSkillNeed,
        StudioArtifactSkillNeedKind, StudioArtifactSkillNeedPriority,
    };

    fn sample_blueprint() -> StudioArtifactBlueprint {
        StudioArtifactBlueprint {
            version: 1,
            renderer: StudioRendererKind::HtmlIframe,
            narrative_arc: "comparison_story".to_string(),
            section_plan: vec![],
            interaction_plan: vec![],
            evidence_plan: vec![],
            design_system: StudioArtifactDesignSystem {
                color_strategy: "editorial".to_string(),
                typography_strategy: "display+mono".to_string(),
                density: "medium".to_string(),
                motion_style: "restrained".to_string(),
                emphasis_modes: vec!["contrast-led".to_string(), "detail-rail".to_string()],
            },
            component_plan: vec![StudioArtifactComponentPlanEntry {
                id: "component-1".to_string(),
                component_family: "tabbed_evidence_rail".to_string(),
                role: "evidence".to_string(),
                section_ids: vec!["section-1".to_string()],
                interaction_ids: vec!["interaction-1".to_string()],
            }],
            accessibility_plan: StudioArtifactAccessibilityPlan {
                obligations: vec!["keyboard".to_string()],
                focus_order: vec![],
                aria_expectations: vec![],
            },
            acceptance_targets: StudioArtifactAcceptanceTargets {
                minimum_section_count: 2,
                minimum_interactive_regions: 1,
                require_first_paint_evidence: true,
                require_persistent_detail_region: true,
                require_distinct_typography: true,
                require_keyboard_affordances: true,
            },
            scaffold_family: "comparison_story".to_string(),
            variation_strategy: "editorial".to_string(),
            skill_needs: vec![StudioArtifactSkillNeed {
                kind: StudioArtifactSkillNeedKind::VisualArtDirection,
                priority: StudioArtifactSkillNeedPriority::Required,
                rationale: "Need strong art direction.".to_string(),
            }],
        }
    }

    fn sample_selected_skill() -> StudioArtifactSelectedSkill {
        StudioArtifactSelectedSkill {
            skill_hash: "a".repeat(64),
            name: "frontend-skill".to_string(),
            description: "Frontend design".to_string(),
            lifecycle_state: "published".to_string(),
            source_type: "skill".to_string(),
            reliability_bps: 9400,
            semantic_score_bps: 9300,
            adjusted_score_bps: 9500,
            relative_path: Some("skills/frontend/SKILL.md".to_string()),
            matched_need_ids: vec!["visual_art_direction-1".to_string()],
            matched_need_kinds: vec![StudioArtifactSkillNeedKind::VisualArtDirection],
            match_rationale: "Structural visual match.".to_string(),
            guidance_markdown: Some("Use a strong visual hierarchy.".to_string()),
        }
    }

    fn sample_validation() -> StudioArtifactValidationResult {
        StudioArtifactValidationResult {
            classification: StudioArtifactValidationStatus::Repairable,
            request_faithfulness: 4,
            concept_coverage: 4,
            interaction_relevance: 4,
            layout_coherence: 4,
            visual_hierarchy: 4,
            completeness: 4,
            generic_shell_detected: false,
            trivial_shell_detected: false,
            deserves_primary_artifact_view: true,
            patched_existing_artifact: Some(true),
            continuity_revision_ux: Some(4),
            issue_classes: vec!["first_paint_density".to_string()],
            repair_hints: vec!["Add a richer first-paint evidence rail.".to_string()],
            strengths: vec!["Strong layout".to_string()],
            blocked_reasons: vec![],
            file_findings: vec!["index.html keeps the detail panel visible.".to_string()],
            aesthetic_verdict: "Good".to_string(),
            interaction_verdict: "Repairable".to_string(),
            truthfulness_warnings: vec!["Needs more visible evidence.".to_string()],
            recommended_next_pass: Some("repair_loop".to_string()),
            strongest_contradiction: Some("Needs more visible evidence.".to_string()),
            rationale: "Repairable with a stronger first paint.".to_string(),
        }
    }

    fn sample_candidate_summary(
        validation: &StudioArtifactValidationResult,
    ) -> StudioArtifactCandidateSummary {
        StudioArtifactCandidateSummary {
            candidate_id: "candidate-1".to_string(),
            seed: 7,
            model: "fixture".to_string(),
            temperature: 0.0,
            strategy: "fixture".to_string(),
            origin: StudioArtifactOutputOrigin::FixtureRuntime,
            provenance: None,
            summary: "Fixture candidate".to_string(),
            renderable_paths: vec!["index.html".to_string()],
            selected: true,
            fallback: false,
            failure: None,
            raw_output_preview: None,
            convergence: Some(StudioArtifactCandidateConvergenceTrace {
                lineage_root_id: "candidate-1".to_string(),
                parent_candidate_id: None,
                pass_kind: "semantic_refinement".to_string(),
                pass_index: 1,
                score_total: 412,
                score_delta_from_parent: Some(24),
                terminated_reason: None,
            }),
            render_evaluation: None,
            validation: validation.clone(),
        }
    }

    #[test]
    fn build_artifact_lane_receipts_captures_all_conformance_categories() {
        let validation = sample_validation();
        let receipts = build_artifact_lane_receipts(
            Some(&sample_blueprint()),
            &[sample_selected_skill()],
            &[sample_candidate_summary(&validation)],
            &validation,
            StudioArtifactUxLifecycle::Validated,
        );

        let kinds = receipts
            .iter()
            .map(|receipt| receipt.kind.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            kinds,
            vec![
                "blueprint_family",
                "skill_discovery_evidence",
                "scaffold_family",
                "component_pack_inventory",
                "audit_findings",
                "validation_findings",
                "repair_passes",
                "presentation_gate",
            ]
        );
        assert_eq!(receipts[1].status, "success");
        assert_eq!(receipts[6].status, "warning");
        assert!(receipts[3]
            .details
            .iter()
            .any(|detail| detail == "tabbed_evidence_rail"));
    }
}
