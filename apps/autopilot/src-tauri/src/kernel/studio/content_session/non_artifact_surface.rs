//! Studio-shell non-artifact presentation.
//!
//! This module is intentionally product-local. It owns renderer-facing HTML /
//! Markdown surface construction, manifest shaping, and shell-specific verified
//! reply assembly for non-artifact routes.
//!
//! If a helper here becomes provenance-free runtime policy, move it into
//! `ioi_api::studio`. If it exists to support Studio session rendering or
//! manifest/navigation behavior, it should stay here.

use super::*;
use crate::models::StudioArtifactFileRole;
use base64::Engine as _;
use ioi_api::studio::{
    derive_studio_domain_policy_bundle, non_artifact_verified_reply_evidence,
    route_decision_for_outcome_request, verification_status_for_lifecycle,
};
use ioi_types::app::StudioDomainPolicyBundle;

pub(super) fn verified_reply_for_non_artifact_route(
    title: &str,
    summary: &str,
    lifecycle_state: StudioArtifactLifecycleState,
    provenance: &crate::models::StudioRuntimeProvenance,
    outcome_request: &StudioOutcomeRequest,
) -> StudioVerifiedReply {
    let status = verification_status_for_lifecycle(lifecycle_state);

    StudioVerifiedReply {
        status,
        lifecycle_state,
        title: title.to_string(),
        summary: summary.to_string(),
        evidence: non_artifact_verified_reply_evidence(outcome_request, &provenance.label),
        production_provenance: Some(provenance.clone()),
        acceptance_provenance: Some(provenance.clone()),
        failure: None,
        updated_at: now_iso(),
    }
}

pub(super) fn non_artifact_domain_policy_bundle(
    outcome_request: &StudioOutcomeRequest,
    widget_state: Option<&StudioRetainedWidgetState>,
) -> StudioDomainPolicyBundle {
    derive_studio_domain_policy_bundle(
        outcome_request.lane_frame.as_ref(),
        outcome_request.request_frame.as_ref(),
        outcome_request.source_selection.as_ref(),
        outcome_request.outcome_kind,
        &outcome_request.routing_hints,
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

fn non_artifact_surface_markdown(
    title: &str,
    summary: &str,
    route_decision: &RoutingRouteDecision,
    domain_policy_bundle: &StudioDomainPolicyBundle,
    outcome_request: &StudioOutcomeRequest,
) -> String {
    let mut sections = vec![
        format!("# {title}"),
        String::new(),
        summary.trim().to_string(),
        String::new(),
        "## Route contract".to_string(),
        format!("- route family: {}", route_decision.route_family),
        format!("- output intent: {}", route_decision.output_intent),
        format!(
            "- direct answer allowed: {}",
            route_decision.direct_answer_allowed
        ),
    ];
    if let Some(policy) = domain_policy_bundle.presentation_policy.as_ref() {
        sections.push(format!(
            "- presentation surface: {}",
            policy.primary_surface
        ));
    }
    if !domain_policy_bundle.source_ranking.is_empty() {
        sections.push(String::new());
        sections.push("## Source ranking".to_string());
        for entry in &domain_policy_bundle.source_ranking {
            sections.push(format!(
                "- {}. {:?}: {}",
                entry.rank, entry.source, entry.rationale
            ));
        }
    }
    if let Some(widget_state) = domain_policy_bundle.retained_widget_state.as_ref() {
        if !widget_state.bindings.is_empty() {
            sections.push(String::new());
            sections.push("## Retained widget state".to_string());
            for binding in &widget_state.bindings {
                sections.push(format!(
                    "- {} = {} ({})",
                    binding.key, binding.value, binding.source
                ));
            }
        }
    }
    if outcome_request.needs_clarification && !outcome_request.clarification_questions.is_empty() {
        sections.push(String::new());
        sections.push("## Clarification".to_string());
        for question in &outcome_request.clarification_questions {
            sections.push(format!("- {question}"));
        }
    }
    sections.join("\n")
}

fn non_artifact_surface_html(
    title: &str,
    summary: &str,
    route_decision: &RoutingRouteDecision,
    domain_policy_bundle: &StudioDomainPolicyBundle,
    outcome_request: &StudioOutcomeRequest,
) -> String {
    let summary_html = summary
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| format!("<p>{}</p>", escape_html(line)))
        .collect::<Vec<_>>()
        .join("");
    let chips = [
        Some(format!("Route: {}", route_decision.route_family)),
        Some(format!("Output: {}", route_decision.output_intent)),
        domain_policy_bundle
            .presentation_policy
            .as_ref()
            .map(|policy| format!("Surface: {}", policy.primary_surface)),
        domain_policy_bundle
            .risk_profile
            .as_ref()
            .map(|risk| format!("Risk: {:?}", risk.sensitivity).to_ascii_lowercase()),
    ]
    .into_iter()
    .flatten()
    .map(|label: String| {
        format!(
            "<span class=\"chip\">{}</span>",
            escape_html(label.as_str())
        )
    })
    .collect::<Vec<_>>()
    .join("");
    let ranking_html = if domain_policy_bundle.source_ranking.is_empty() {
        String::new()
    } else {
        format!(
            "<section><h3>Source ranking</h3><ol>{}</ol></section>",
            domain_policy_bundle
                .source_ranking
                .iter()
                .map(|entry| format!(
                    "<li><strong>{:?}</strong> · {}</li>",
                    entry.source,
                    escape_html(&entry.rationale)
                ))
                .collect::<Vec<_>>()
                .join("")
        )
    };
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
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin: 18px 0 20px;
      }}
      .chip {{
        font-size: 12px;
        padding: 6px 10px;
        border-radius: 999px;
        border: 1px solid var(--line);
        background: rgba(255,255,255,0.04);
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
      <div class=\"eyebrow\">Studio parity surface</div>
      <h1>{title_html}</h1>
      <div class=\"chips\">{chips}</div>
      <section>
        <h3>Outcome</h3>
        {summary_html}
      </section>
      {ranking_html}
      {clarification_html}
    </main>
    <script>
      const widgetState = {retained_widget_state};
      if (widgetState) {{
        window.parent.postMessage({{
          __studioWidgetState: true,
          widgetState,
        }}, \"*\");
      }}
    </script>
  </body>
</html>",
        title = escape_html(title),
        title_html = escape_html(title),
        chips = chips,
        summary_html = summary_html,
        ranking_html = ranking_html,
        clarification_html = clarification_html,
        retained_widget_state = retained_widget_state,
    )
}

pub(super) fn non_artifact_manifest(
    artifact_id: &str,
    title: &str,
    summary: &str,
    lifecycle_state: StudioArtifactLifecycleState,
    provenance: &crate::models::StudioRuntimeProvenance,
    outcome_request: &StudioOutcomeRequest,
    widget_state: Option<&StudioRetainedWidgetState>,
) -> StudioArtifactManifest {
    let route_decision = route_decision_for_outcome_request(outcome_request);
    let domain_policy_bundle = non_artifact_domain_policy_bundle(outcome_request, widget_state);
    let source_markdown = non_artifact_surface_markdown(
        title,
        summary,
        &route_decision,
        &domain_policy_bundle,
        outcome_request,
    );
    let (renderer, render_path, render_mime, render_content) =
        if outcome_request.outcome_kind == StudioOutcomeKind::Visualizer {
            if let Some(mermaid) = extract_mermaid_block(summary) {
                (
                    StudioRendererKind::Mermaid,
                    "surface/diagram.mmd".to_string(),
                    "text/plain".to_string(),
                    mermaid,
                )
            } else {
                (
                    StudioRendererKind::HtmlIframe,
                    "surface/index.html".to_string(),
                    "text/html".to_string(),
                    non_artifact_surface_html(
                        title,
                        summary,
                        &route_decision,
                        &domain_policy_bundle,
                        outcome_request,
                    ),
                )
            }
        } else {
            (
                StudioRendererKind::HtmlIframe,
                "surface/index.html".to_string(),
                "text/html".to_string(),
                non_artifact_surface_html(
                    title,
                    summary,
                    &route_decision,
                    &domain_policy_bundle,
                    outcome_request,
                ),
            )
        };

    StudioArtifactManifest {
        artifact_id: artifact_id.to_string(),
        title: title.to_string(),
        artifact_class: match outcome_request.outcome_kind {
            StudioOutcomeKind::Visualizer => StudioArtifactClass::Visual,
            StudioOutcomeKind::ToolWidget => StudioArtifactClass::InteractiveSingleFile,
            _ => StudioArtifactClass::Document,
        },
        renderer,
        primary_tab: "render".to_string(),
        tabs: vec![
            StudioArtifactManifestTab {
                id: "render".to_string(),
                label: "Render".to_string(),
                kind: StudioArtifactTabKind::Render,
                renderer: Some(renderer),
                file_path: Some(render_path.clone()),
                lens: Some("render".to_string()),
            },
            StudioArtifactManifestTab {
                id: "source".to_string(),
                label: "Source".to_string(),
                kind: StudioArtifactTabKind::Source,
                renderer: None,
                file_path: Some("surface/route.md".to_string()),
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
        files: vec![
            StudioArtifactManifestFile {
                path: render_path,
                mime: render_mime.clone(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: false,
                artifact_id: None,
                external_url: Some(text_data_url(&render_mime, &render_content)),
            },
            StudioArtifactManifestFile {
                path: "surface/route.md".to_string(),
                mime: "text/markdown".to_string(),
                role: StudioArtifactFileRole::Source,
                renderable: false,
                downloadable: false,
                artifact_id: None,
                external_url: Some(text_data_url("text/markdown", &source_markdown)),
            },
        ],
        verification: StudioArtifactManifestVerification {
            status: if outcome_request.needs_clarification {
                StudioArtifactVerificationStatus::Blocked
            } else {
                StudioArtifactVerificationStatus::Ready
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

pub(in crate::kernel::studio) fn refresh_non_artifact_studio_surface(
    studio_session: &mut StudioArtifactSession,
) {
    if studio_session.outcome_request.outcome_kind == StudioOutcomeKind::Artifact {
        return;
    }
    let title = studio_session.title.clone();
    let summary = studio_session.verified_reply.summary.clone();
    let lifecycle_state = studio_session.lifecycle_state;
    let provenance = studio_session
        .verified_reply
        .production_provenance
        .clone()
        .or_else(|| studio_session.verified_reply.acceptance_provenance.clone())
        .unwrap_or(crate::models::StudioRuntimeProvenance {
            kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
            label: "inference unavailable".to_string(),
            model: None,
            endpoint: None,
        });
    if studio_session.widget_state.is_none() {
        studio_session.widget_state =
            non_artifact_domain_policy_bundle(&studio_session.outcome_request, None)
                .retained_widget_state;
    }
    let manifest = non_artifact_manifest(
        &studio_session.artifact_id,
        &title,
        &summary,
        lifecycle_state,
        &provenance,
        &studio_session.outcome_request,
        studio_session.widget_state.as_ref(),
    );
    studio_session.artifact_manifest = manifest;
    studio_session.current_lens = "render".to_string();
    studio_session.available_lenses = vec![
        "render".to_string(),
        "source".to_string(),
        "evidence".to_string(),
    ];
    studio_session.navigator_nodes =
        navigator_nodes_for_manifest(&studio_session.artifact_manifest);
}
