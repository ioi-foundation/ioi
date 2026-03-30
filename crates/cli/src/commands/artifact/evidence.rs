use anyhow::{Context, Result};
use ioi_api::studio::{
    pdf_artifact_bytes, StudioArtifactJudgeClassification, StudioArtifactJudgeResult,
    StudioArtifactTasteMemory, StudioGeneratedArtifactFile, StudioGeneratedArtifactPayload,
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

use super::types::{GeneratedArtifactEvidence, LoadedRefinementEvidence};
use super::workspace::workspace_recipe_for_request;

pub(super) fn run_judge(evidence_path: &Path, json_output: bool) -> Result<()> {
    let evidence = load_generated_evidence(evidence_path)?;
    let judge = evidence
        .judge
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Generated evidence is missing a judge result."))?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(judge)?);
        return Ok(());
    }

    println!("Judge: {}", format_judge_label(judge));
    println!("  rationale: {}", judge.rationale);
    if let Some(contradiction) = &judge.strongest_contradiction {
        println!("  strongest contradiction: {}", contradiction);
    }
    println!(
        "  faithfulness / coverage / interaction: {}/{}/{}",
        judge.request_faithfulness, judge.concept_coverage, judge.interaction_relevance
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
        } else {
            file.body.as_bytes().to_vec()
        };
        fs::write(&target_path, bytes)
            .with_context(|| format!("Failed to write '{}'.", target_path.display()))?;
    }
    Ok(())
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

pub(super) fn manifest_verification_from_judge(
    judge: &StudioArtifactJudgeResult,
    production_provenance: &StudioRuntimeProvenance,
    acceptance_provenance: &StudioRuntimeProvenance,
    failure: Option<&StudioArtifactFailure>,
) -> StudioArtifactManifestVerification {
    let lifecycle_state = match judge.classification {
        StudioArtifactJudgeClassification::Pass => StudioArtifactLifecycleState::Ready,
        StudioArtifactJudgeClassification::Repairable => StudioArtifactLifecycleState::Partial,
        StudioArtifactJudgeClassification::Blocked => StudioArtifactLifecycleState::Blocked,
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
        summary: judge.rationale.clone(),
        production_provenance: Some(production_provenance.clone()),
        acceptance_provenance: Some(acceptance_provenance.clone()),
        failure: failure.cloned(),
    }
}

pub(super) fn build_generated_manifest(
    title: &str,
    request: &StudioOutcomeArtifactRequest,
    payload: &StudioGeneratedArtifactPayload,
    judge: &StudioArtifactJudgeResult,
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
        verification: manifest_verification_from_judge(
            judge,
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
            }),
    }))
}

pub(super) fn format_judge_label(judge: &StudioArtifactJudgeResult) -> &'static str {
    match judge.classification {
        StudioArtifactJudgeClassification::Pass => "pass",
        StudioArtifactJudgeClassification::Repairable => "repairable",
        StudioArtifactJudgeClassification::Blocked => "blocked",
    }
}
