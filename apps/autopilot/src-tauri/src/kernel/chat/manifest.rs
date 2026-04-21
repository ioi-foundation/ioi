use crate::models::{
    BuildArtifactSession, ChatVerifiedReply, ChatArtifactFileRole, ChatArtifactLifecycleState,
    ChatArtifactManifest, ChatArtifactManifestFile, ChatArtifactManifestStorage,
    ChatArtifactManifestTab, ChatArtifactManifestVerification, ChatArtifactNavigatorNode,
    ChatArtifactPersistenceMode, ChatArtifactTabKind, ChatOutcomeArtifactRequest,
    ChatRendererKind, ChatRendererSession,
};
pub(super) use ioi_api::runtime_harness::verification_status_for_lifecycle;
use ioi_api::runtime_harness::verified_reply_evidence_for_manifest;
use uuid::Uuid;

use super::{mime_for_workspace_entry, now_iso};

pub(super) fn manifest_tabs_for_request(
    request: &ChatOutcomeArtifactRequest,
    build_session: Option<&BuildArtifactSession>,
) -> Vec<ChatArtifactManifestTab> {
    match request.renderer {
        ChatRendererKind::WorkspaceSurface => vec![
            ChatArtifactManifestTab {
                id: "preview".to_string(),
                label: "Preview".to_string(),
                kind: ChatArtifactTabKind::Render,
                renderer: Some(ChatRendererKind::HtmlIframe),
                file_path: None,
                lens: Some("preview".to_string()),
            },
            ChatArtifactManifestTab {
                id: "workspace".to_string(),
                label: "Workspace".to_string(),
                kind: ChatArtifactTabKind::Workspace,
                renderer: Some(ChatRendererKind::WorkspaceSurface),
                file_path: build_session.map(|session| session.entry_document.clone()),
                lens: Some("code".to_string()),
            },
            ChatArtifactManifestTab {
                id: "evidence".to_string(),
                label: "Evidence".to_string(),
                kind: ChatArtifactTabKind::Evidence,
                renderer: None,
                file_path: None,
                lens: Some("evidence".to_string()),
            },
        ],
        ChatRendererKind::DownloadCard => vec![
            ChatArtifactManifestTab {
                id: "download".to_string(),
                label: "Download".to_string(),
                kind: ChatArtifactTabKind::Download,
                renderer: Some(ChatRendererKind::DownloadCard),
                file_path: None,
                lens: Some("download".to_string()),
            },
            ChatArtifactManifestTab {
                id: "evidence".to_string(),
                label: "Evidence".to_string(),
                kind: ChatArtifactTabKind::Evidence,
                renderer: None,
                file_path: None,
                lens: Some("evidence".to_string()),
            },
        ],
        _ => vec![
            ChatArtifactManifestTab {
                id: "render".to_string(),
                label: "Render".to_string(),
                kind: ChatArtifactTabKind::Render,
                renderer: Some(request.renderer),
                file_path: None,
                lens: Some("render".to_string()),
            },
            ChatArtifactManifestTab {
                id: "source".to_string(),
                label: "Source".to_string(),
                kind: ChatArtifactTabKind::Source,
                renderer: None,
                file_path: None,
                lens: Some("source".to_string()),
            },
            ChatArtifactManifestTab {
                id: "evidence".to_string(),
                label: "Evidence".to_string(),
                kind: ChatArtifactTabKind::Evidence,
                renderer: None,
                file_path: None,
                lens: Some("evidence".to_string()),
            },
        ],
    }
}

pub(super) fn artifact_manifest_for_request(
    title: &str,
    request: &ChatOutcomeArtifactRequest,
    attached_artifact_ids: &[String],
    build_session: Option<&BuildArtifactSession>,
    renderer_session: Option<&ChatRendererSession>,
    lifecycle_state: ChatArtifactLifecycleState,
) -> ChatArtifactManifest {
    let verification = ChatArtifactManifestVerification {
        status: verification_status_for_lifecycle(lifecycle_state),
        lifecycle_state,
        summary: if request.renderer == ChatRendererKind::WorkspaceSurface {
            "Chat is materializing the workspace renderer and running verification.".to_string()
        } else {
            "Chat materialized the artifact and verified the render contract.".to_string()
        },
        production_provenance: None,
        acceptance_provenance: None,
        failure: None,
    };

    let primary_tab = if request.renderer == ChatRendererKind::WorkspaceSurface {
        renderer_session
            .map(|session| session.current_tab.clone())
            .or_else(|| build_session.map(|session| session.current_lens.clone()))
            .unwrap_or_else(|| "workspace".to_string())
    } else if request.renderer == ChatRendererKind::DownloadCard {
        "download".to_string()
    } else {
        "render".to_string()
    };

    ChatArtifactManifest {
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
            ChatArtifactPersistenceMode::ArtifactScoped
            | ChatArtifactPersistenceMode::SharedArtifactScoped => {
                Some(ChatArtifactManifestStorage {
                    mode: request.persistence,
                    api_label: Some("artifact storage".to_string()),
                })
            }
            _ => None,
        },
    }
}

pub(super) fn manifest_files_for_request(
    request: &ChatOutcomeArtifactRequest,
    build_session: Option<&BuildArtifactSession>,
) -> Vec<ChatArtifactManifestFile> {
    if request.renderer == ChatRendererKind::WorkspaceSurface {
        let mut files = Vec::new();
        if let Some(session) = build_session {
            files.push(ChatArtifactManifestFile {
                path: session.entry_document.clone(),
                mime: mime_for_workspace_entry(&session.entry_document),
                role: ChatArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                artifact_id: None,
                external_url: session.preview_url.clone(),
            });
            files.push(ChatArtifactManifestFile {
                path: "artifact-manifest.json".to_string(),
                mime: "application/json".to_string(),
                role: ChatArtifactFileRole::Supporting,
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
    manifest: &ChatArtifactManifest,
) -> Vec<ChatArtifactNavigatorNode> {
    manifest
        .tabs
        .iter()
        .map(|tab| ChatArtifactNavigatorNode {
            id: tab.id.clone(),
            label: tab.label.clone(),
            kind: match tab.kind {
                ChatArtifactTabKind::Workspace => "workspace".to_string(),
                ChatArtifactTabKind::Render => "render".to_string(),
                ChatArtifactTabKind::Source => "source".to_string(),
                ChatArtifactTabKind::Download => "download".to_string(),
                ChatArtifactTabKind::Evidence => "evidence".to_string(),
            },
            description: Some(
                match tab.kind {
                    ChatArtifactTabKind::Workspace => {
                        "Open the workspace renderer for implementation and verification."
                    }
                    ChatArtifactTabKind::Render => {
                        "Interact with the artifact through its renderer-specific presentation."
                    }
                    ChatArtifactTabKind::Source => "Inspect the source form of the artifact.",
                    ChatArtifactTabKind::Download => "Download the produced artifact.",
                    ChatArtifactTabKind::Evidence => {
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
    manifest: &ChatArtifactManifest,
) -> ChatVerifiedReply {
    ChatVerifiedReply {
        status: manifest.verification.status,
        lifecycle_state: manifest.verification.lifecycle_state,
        title: format!("Chat outcome: {}", title),
        summary: format!("{} {}", title, manifest.verification.summary),
        evidence: verified_reply_evidence_for_manifest(&manifest.verification, manifest),
        production_provenance: manifest.verification.production_provenance.clone(),
        acceptance_provenance: manifest.verification.acceptance_provenance.clone(),
        failure: manifest.verification.failure.clone(),
        updated_at: now_iso(),
    }
}
