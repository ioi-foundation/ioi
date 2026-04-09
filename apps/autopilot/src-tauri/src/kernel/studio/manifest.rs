use crate::models::{
    BuildArtifactSession, StudioArtifactFileRole, StudioArtifactLifecycleState,
    StudioArtifactManifest, StudioArtifactManifestFile, StudioArtifactManifestStorage,
    StudioArtifactManifestTab, StudioArtifactManifestVerification, StudioArtifactNavigatorNode,
    StudioArtifactPersistenceMode, StudioArtifactTabKind, StudioArtifactVerificationStatus,
    StudioOutcomeArtifactRequest, StudioRendererKind, StudioRendererSession, StudioVerifiedReply,
};
use uuid::Uuid;

use super::{mime_for_workspace_entry, now_iso};

pub(super) fn verification_status_for_lifecycle(
    state: StudioArtifactLifecycleState,
) -> StudioArtifactVerificationStatus {
    match state {
        StudioArtifactLifecycleState::Draft
        | StudioArtifactLifecycleState::Planned
        | StudioArtifactLifecycleState::Materializing
        | StudioArtifactLifecycleState::Rendering
        | StudioArtifactLifecycleState::Implementing
        | StudioArtifactLifecycleState::Verifying => StudioArtifactVerificationStatus::Pending,
        StudioArtifactLifecycleState::Ready => StudioArtifactVerificationStatus::Ready,
        StudioArtifactLifecycleState::Partial => StudioArtifactVerificationStatus::Partial,
        StudioArtifactLifecycleState::Failed => StudioArtifactVerificationStatus::Failed,
        StudioArtifactLifecycleState::Blocked => StudioArtifactVerificationStatus::Blocked,
    }
}

pub(super) fn manifest_tabs_for_request(
    request: &StudioOutcomeArtifactRequest,
    build_session: Option<&BuildArtifactSession>,
) -> Vec<StudioArtifactManifestTab> {
    match request.renderer {
        StudioRendererKind::WorkspaceSurface => vec![
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
                file_path: build_session.map(|session| session.entry_document.clone()),
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
        ],
        StudioRendererKind::DownloadCard => vec![
            StudioArtifactManifestTab {
                id: "download".to_string(),
                label: "Download".to_string(),
                kind: StudioArtifactTabKind::Download,
                renderer: Some(StudioRendererKind::DownloadCard),
                file_path: None,
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
                file_path: None,
                lens: Some("render".to_string()),
            },
            StudioArtifactManifestTab {
                id: "source".to_string(),
                label: "Source".to_string(),
                kind: StudioArtifactTabKind::Source,
                renderer: None,
                file_path: None,
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

pub(super) fn artifact_manifest_for_request(
    title: &str,
    request: &StudioOutcomeArtifactRequest,
    attached_artifact_ids: &[String],
    build_session: Option<&BuildArtifactSession>,
    renderer_session: Option<&StudioRendererSession>,
    lifecycle_state: StudioArtifactLifecycleState,
) -> StudioArtifactManifest {
    let verification = StudioArtifactManifestVerification {
        status: verification_status_for_lifecycle(lifecycle_state),
        lifecycle_state,
        summary: if request.renderer == StudioRendererKind::WorkspaceSurface {
            "Studio is materializing the workspace renderer and running verification.".to_string()
        } else {
            "Studio materialized the artifact and verified the render contract.".to_string()
        },
        production_provenance: None,
        acceptance_provenance: None,
        failure: None,
    };

    let primary_tab = if request.renderer == StudioRendererKind::WorkspaceSurface {
        renderer_session
            .map(|session| session.current_tab.clone())
            .or_else(|| build_session.map(|session| session.current_lens.clone()))
            .unwrap_or_else(|| "workspace".to_string())
    } else if request.renderer == StudioRendererKind::DownloadCard {
        "download".to_string()
    } else {
        "render".to_string()
    };

    StudioArtifactManifest {
        artifact_id: attached_artifact_ids
            .first()
            .cloned()
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        title: title.to_string(),
        artifact_class: request.artifact_class,
        renderer: request.renderer,
        primary_tab,
        tabs: manifest_tabs_for_request(request, build_session),
        files: Vec::new(),
        verification,
        storage: match request.persistence {
            StudioArtifactPersistenceMode::ArtifactScoped
            | StudioArtifactPersistenceMode::SharedArtifactScoped => {
                Some(StudioArtifactManifestStorage {
                    mode: request.persistence,
                    api_label: Some("artifact storage".to_string()),
                })
            }
            _ => None,
        },
    }
}

pub(super) fn manifest_files_for_request(
    request: &StudioOutcomeArtifactRequest,
    build_session: Option<&BuildArtifactSession>,
) -> Vec<StudioArtifactManifestFile> {
    if request.renderer == StudioRendererKind::WorkspaceSurface {
        let mut files = Vec::new();
        if let Some(session) = build_session {
            files.push(StudioArtifactManifestFile {
                path: session.entry_document.clone(),
                mime: mime_for_workspace_entry(&session.entry_document),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                artifact_id: None,
                external_url: session.preview_url.clone(),
            });
            files.push(StudioArtifactManifestFile {
                path: "artifact-manifest.json".to_string(),
                mime: "application/json".to_string(),
                role: StudioArtifactFileRole::Supporting,
                renderable: false,
                downloadable: true,
                artifact_id: None,
                external_url: None,
            });
        }
        return files;
    }
    Vec::new()
}

pub(super) fn navigator_nodes_for_manifest(
    manifest: &StudioArtifactManifest,
) -> Vec<StudioArtifactNavigatorNode> {
    manifest
        .tabs
        .iter()
        .map(|tab| StudioArtifactNavigatorNode {
            id: tab.id.clone(),
            label: tab.label.clone(),
            kind: match tab.kind {
                StudioArtifactTabKind::Workspace => "workspace".to_string(),
                StudioArtifactTabKind::Render => "render".to_string(),
                StudioArtifactTabKind::Source => "source".to_string(),
                StudioArtifactTabKind::Download => "download".to_string(),
                StudioArtifactTabKind::Evidence => "evidence".to_string(),
            },
            description: Some(
                match tab.kind {
                    StudioArtifactTabKind::Workspace => {
                        "Open the workspace renderer for implementation and verification."
                    }
                    StudioArtifactTabKind::Render => {
                        "Interact with the artifact through its renderer-specific presentation."
                    }
                    StudioArtifactTabKind::Source => "Inspect the source form of the artifact.",
                    StudioArtifactTabKind::Download => "Download the produced artifact.",
                    StudioArtifactTabKind::Evidence => {
                        "Inspect verification state, receipts, and evidence."
                    }
                }
                .to_string(),
            ),
            badge: None,
            status: None,
            lens: Some(tab.id.clone()),
            path: tab.file_path.clone(),
            children: Vec::new(),
        })
        .collect()
}

pub(super) fn verified_reply_from_manifest(
    title: &str,
    manifest: &StudioArtifactManifest,
) -> StudioVerifiedReply {
    let mut evidence = manifest
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    if let Some(provenance) = manifest.verification.production_provenance.as_ref() {
        evidence.push(format!(
            "production provenance: {}{}",
            provenance.label,
            provenance
                .model
                .as_ref()
                .map(|model| format!(" ({model})"))
                .unwrap_or_default()
        ));
    }
    if let Some(provenance) = manifest.verification.acceptance_provenance.as_ref() {
        evidence.push(format!(
            "acceptance provenance: {}{}",
            provenance.label,
            provenance
                .model
                .as_ref()
                .map(|model| format!(" ({model})"))
                .unwrap_or_default()
        ));
    }
    if let Some(failure) = manifest.verification.failure.as_ref() {
        evidence.push(format!("failure: {} ({})", failure.message, failure.code));
    }

    StudioVerifiedReply {
        status: manifest.verification.status,
        lifecycle_state: manifest.verification.lifecycle_state,
        title: format!("Studio outcome: {}", title),
        summary: format!("{} {}", title, manifest.verification.summary),
        evidence,
        production_provenance: manifest.verification.production_provenance.clone(),
        acceptance_provenance: manifest.verification.acceptance_provenance.clone(),
        failure: manifest.verification.failure.clone(),
        updated_at: now_iso(),
    }
}
