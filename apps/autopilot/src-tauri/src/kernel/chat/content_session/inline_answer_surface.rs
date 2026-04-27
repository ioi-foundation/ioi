//! Chat-shell non-artifact presentation.
//!
//! This module is intentionally product-local. It owns renderer-facing HTML /
//! Markdown surface construction, manifest shaping, and shell-specific verified
//! reply assembly for non-artifact routes.
//!
//! If a helper here becomes provenance-free runtime policy, move it into
//! `ioi_api::runtime_harness`. If it exists to support Chat session rendering or
//! manifest/navigation behavior, it should stay here.

use super::*;
use crate::models::ChatArtifactFileRole;
use base64::Engine as _;
use ioi_api::runtime_harness::{
    derive_chat_domain_policy_bundle, inline_answer_verified_reply_evidence,
    verification_status_for_lifecycle,
};
use ioi_types::app::ChatDomainPolicyBundle;

pub(super) fn verified_reply_for_inline_answer_route(
    title: &str,
    summary: &str,
    lifecycle_state: ChatArtifactLifecycleState,
    provenance: &crate::models::ChatRuntimeProvenance,
    outcome_request: &ChatOutcomeRequest,
) -> ChatVerifiedReply {
    let status = verification_status_for_lifecycle(lifecycle_state);

    ChatVerifiedReply {
        status,
        lifecycle_state,
        title: title.to_string(),
        summary: summary.to_string(),
        evidence: inline_answer_verified_reply_evidence(outcome_request, &provenance.label),
        production_provenance: Some(provenance.clone()),
        acceptance_provenance: Some(provenance.clone()),
        failure: None,
        updated_at: now_iso(),
    }
}

pub(super) fn inline_answer_domain_policy_bundle(
    outcome_request: &ChatOutcomeRequest,
    widget_state: Option<&ChatRetainedWidgetState>,
) -> ChatDomainPolicyBundle {
    derive_chat_domain_policy_bundle(
        outcome_request.lane_request.as_ref(),
        outcome_request.normalized_request.as_ref(),
        outcome_request.source_decision.as_ref(),
        outcome_request.outcome_kind,
        &outcome_request.decision_evidence,
        outcome_request.needs_clarification,
        widget_state,
    )
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn text_data_url(mime: &str, content: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(content.as_bytes());
    format!("data:{mime};base64,{encoded}")
}

fn extract_mermaid_block(content: &str) -> Option<String> {
    let trimmed = content.trim();
    let stripped = trimmed.strip_prefix("```mermaid")?;
    let stripped = stripped.strip_suffix("```")?;
    let block = stripped.trim();
    if block.is_empty() {
        None
    } else {
        Some(block.to_string())
    }
}

fn inline_answer_surface_html(
    title: &str,
    summary: &str,
    domain_policy_bundle: &ChatDomainPolicyBundle,
    outcome_request: &ChatOutcomeRequest,
) -> String {
    let summary_html = summary
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| format!("<p>{}</p>", escape_html(line)))
        .collect::<Vec<_>>()
        .join("");
    let clarification_html = if outcome_request.needs_clarification
        && !outcome_request.clarification_questions.is_empty()
    {
        format!(
            "<section><h3>Clarification</h3><ul>{}</ul></section>",
            outcome_request
                .clarification_questions
                .iter()
                .map(|question| format!("<li>{}</li>", escape_html(question)))
                .collect::<Vec<_>>()
                .join("")
        )
    } else {
        String::new()
    };
    let retained_widget_state = domain_policy_bundle
        .retained_widget_state
        .as_ref()
        .map(|state| serde_json::to_string(state).unwrap_or_else(|_| "null".to_string()))
        .unwrap_or_else(|| "null".to_string());
    format!(
        "<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>{title}</title>
    <style>
      :root {{
        color-scheme: dark;
        --bg: #0d1117;
        --panel: #111821;
        --muted: #8b99ad;
        --text: #ecf1f7;
        --line: rgba(255,255,255,0.08);
        --accent: #59b3ff;
      }}
      body {{
        margin: 0;
        padding: 24px;
        font-family: ui-sans-serif, system-ui, sans-serif;
        background: radial-gradient(circle at top, #182334 0%, var(--bg) 60%);
        color: var(--text);
      }}
      .shell {{
        max-width: 920px;
        margin: 0 auto;
        background: rgba(10, 14, 20, 0.8);
        border: 1px solid var(--line);
        border-radius: 20px;
        padding: 24px;
        box-shadow: 0 24px 60px rgba(0, 0, 0, 0.28);
      }}
      .eyebrow {{
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.12em;
        color: var(--muted);
      }}
      h1 {{
        margin: 8px 0 0;
        font-size: 28px;
      }}
      .chips {{
        display: none;
      }}
      section {{
        margin-top: 22px;
        padding-top: 18px;
        border-top: 1px solid var(--line);
      }}
      h3 {{
        margin: 0 0 10px;
        font-size: 14px;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        color: var(--muted);
      }}
      p, li {{
        line-height: 1.55;
      }}
      code {{
        color: var(--accent);
      }}
    </style>
  </head>
  <body>
    <main class=\"shell\">
      <div class=\"eyebrow\">Answer</div>
      <h1>{title_html}</h1>
      <section>
        <h3>Outcome</h3>
        {summary_html}
      </section>
      {clarification_html}
    </main>
    <script>
      const widgetState = {retained_widget_state};
      if (widgetState) {{
        window.parent.postMessage({{
          __chatWidgetState: true,
          widgetState,
        }}, \"*\");
      }}
    </script>
  </body>
</html>",
        title = escape_html(title),
        title_html = escape_html(title),
        summary_html = summary_html,
        clarification_html = clarification_html,
        retained_widget_state = retained_widget_state,
    )
}

pub(super) fn inline_answer_manifest(
    artifact_id: &str,
    title: &str,
    summary: &str,
    lifecycle_state: ChatArtifactLifecycleState,
    provenance: &crate::models::ChatRuntimeProvenance,
    outcome_request: &ChatOutcomeRequest,
    widget_state: Option<&ChatRetainedWidgetState>,
) -> ChatArtifactManifest {
    let domain_policy_bundle = inline_answer_domain_policy_bundle(outcome_request, widget_state);
    let (renderer, render_path, render_mime, render_content) = if outcome_request.outcome_kind
        == ChatOutcomeKind::Visualizer
    {
        if let Some(mermaid) = extract_mermaid_block(summary) {
            (
                ChatRendererKind::Mermaid,
                "surface/diagram.mmd".to_string(),
                "text/plain".to_string(),
                mermaid,
            )
        } else {
            (
                ChatRendererKind::HtmlIframe,
                "surface/index.html".to_string(),
                "text/html".to_string(),
                inline_answer_surface_html(title, summary, &domain_policy_bundle, outcome_request),
            )
        }
    } else {
        (
            ChatRendererKind::HtmlIframe,
            "surface/index.html".to_string(),
            "text/html".to_string(),
            inline_answer_surface_html(title, summary, &domain_policy_bundle, outcome_request),
        )
    };

    ChatArtifactManifest {
        artifact_id: artifact_id.to_string(),
        title: title.to_string(),
        artifact_class: match outcome_request.outcome_kind {
            ChatOutcomeKind::Visualizer => ChatArtifactClass::Visual,
            ChatOutcomeKind::ToolWidget => ChatArtifactClass::InteractiveSingleFile,
            _ => ChatArtifactClass::Document,
        },
        renderer,
        primary_tab: "render".to_string(),
        tabs: vec![ChatArtifactManifestTab {
            id: "render".to_string(),
            label: "Render".to_string(),
            kind: ChatArtifactTabKind::Render,
            renderer: Some(renderer),
            file_path: Some(render_path.clone()),
            lens: Some("render".to_string()),
        }],
        files: vec![ChatArtifactManifestFile {
            path: render_path,
            mime: render_mime.clone(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            artifact_id: None,
            external_url: Some(text_data_url(&render_mime, &render_content)),
        }],
        verification: ChatArtifactManifestVerification {
            status: if outcome_request.needs_clarification {
                ChatArtifactVerificationStatus::Blocked
            } else {
                ChatArtifactVerificationStatus::Ready
            },
            lifecycle_state,
            summary: summary.to_string(),
            production_provenance: Some(provenance.clone()),
            acceptance_provenance: Some(provenance.clone()),
            failure: None,
        },
        storage: None,
    }
}

pub(in crate::kernel::chat) fn refresh_inline_answer_chat_surface(
    chat_session: &mut ChatArtifactSession,
) {
    if chat_session.outcome_request.outcome_kind == ChatOutcomeKind::Artifact {
        return;
    }
    let title = chat_session.title.clone();
    let summary = chat_session.verified_reply.summary.clone();
    let lifecycle_state = chat_session.lifecycle_state;
    let provenance = chat_session
        .verified_reply
        .production_provenance
        .clone()
        .or_else(|| chat_session.verified_reply.acceptance_provenance.clone())
        .unwrap_or(crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable,
            label: "inference unavailable".to_string(),
            model: None,
            endpoint: None,
        });
    if chat_session.widget_state.is_none() {
        chat_session.widget_state =
            inline_answer_domain_policy_bundle(&chat_session.outcome_request, None)
                .retained_widget_state;
    }
    let manifest = inline_answer_manifest(
        &chat_session.artifact_id,
        &title,
        &summary,
        lifecycle_state,
        &provenance,
        &chat_session.outcome_request,
        chat_session.widget_state.as_ref(),
    );
    chat_session.artifact_manifest = manifest;
    chat_session.current_lens = "render".to_string();
    chat_session.available_lenses = vec!["render".to_string()];
    chat_session.navigator_nodes = navigator_nodes_for_manifest(&chat_session.artifact_manifest);
}
