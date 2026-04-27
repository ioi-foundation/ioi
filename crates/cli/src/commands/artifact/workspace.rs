use ioi_api::chat::{
    plan_chat_artifact_brief_with_runtime, plan_chat_artifact_edit_intent_with_runtime,
    validate_chat_artifact_candidate_with_runtime, ChatArtifactBrief, ChatArtifactEditIntent,
    ChatArtifactGenerationBundle, ChatArtifactRefinementContext, ChatArtifactUxLifecycle,
    ChatGeneratedArtifactFile, ChatGeneratedArtifactPayload,
};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::app::{ChatArtifactFileRole, ChatOutcomeArtifactRequest};
use std::sync::Arc;

use super::runtime::{runtime_model_label, runtime_origin_label};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkspaceRecipe {
    ReactVite,
    StaticHtmlVite,
}

impl WorkspaceRecipe {
    pub(super) fn entry_document(self) -> &'static str {
        match self {
            Self::ReactVite => "src/App.tsx",
            Self::StaticHtmlVite => "index.html",
        }
    }
}

pub(super) async fn generate_workspace_artifact_bundle_with_runtimes(
    runtime: Arc<dyn InferenceRuntime>,
    acceptance_runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
) -> Result<ChatArtifactGenerationBundle, String> {
    let brief =
        plan_chat_artifact_brief_with_runtime(runtime.clone(), title, intent, request, refinement)
            .await?;
    let edit_intent = match refinement {
        Some(context) => Some(
            plan_chat_artifact_edit_intent_with_runtime(
                runtime.clone(),
                intent,
                request,
                &brief,
                context,
            )
            .await?,
        ),
        None => None,
    };
    let winner =
        materialize_workspace_artifact_payload(title, request, &brief, edit_intent.as_ref());
    let validation = validate_chat_artifact_candidate_with_runtime(
        acceptance_runtime.clone(),
        title,
        request,
        &brief,
        edit_intent.as_ref(),
        &winner,
    )
    .await?;
    let candidate_id = "candidate-1".to_string();
    let production_provenance = runtime.chat_runtime_provenance();
    let acceptance_provenance = acceptance_runtime.chat_runtime_provenance();
    let origin = runtime_origin_label(&production_provenance);
    let summary = ioi_api::chat::ChatArtifactCandidateSummary {
        candidate_id: candidate_id.clone(),
        seed: workspace_candidate_seed(title, intent),
        model: runtime_model_label(&runtime),
        temperature: 0.0,
        strategy: "workspace-scaffold".to_string(),
        origin,
        provenance: Some(production_provenance.clone()),
        summary: winner.summary.clone(),
        renderable_paths: winner
            .files
            .iter()
            .filter(|file| file.renderable)
            .map(|file| file.path.clone())
            .collect(),
        selected: true,
        fallback: false,
        failure: None,
        raw_output_preview: None,
        convergence: None,
        render_evaluation: None,
        validation: validation.clone(),
    };

    Ok(ChatArtifactGenerationBundle {
        brief,
        blueprint: None,
        artifact_ir: None,
        selected_skills: Vec::new(),
        edit_intent,
        candidate_summaries: vec![summary],
        winning_candidate_id: Some(candidate_id),
        winning_candidate_rationale: Some(validation.rationale.clone()),
        execution_envelope: None,
        swarm_plan: None,
        swarm_execution: None,
        swarm_worker_receipts: Vec::new(),
        swarm_change_receipts: Vec::new(),
        swarm_merge_receipts: Vec::new(),
        swarm_verification_receipts: Vec::new(),
        winner,
        render_evaluation: None,
        validation,
        origin,
        production_provenance,
        acceptance_provenance,
        runtime_policy: None,
        adaptive_search_budget: None,
        degraded_path_used: false,
        ux_lifecycle: ChatArtifactUxLifecycle::Validated,
        taste_memory: refinement.and_then(|context| context.taste_memory.clone()),
        failure: None,
    })
}

pub(super) fn workspace_candidate_seed(title: &str, intent: &str) -> u64 {
    title.bytes().chain(intent.bytes()).fold(1u64, |acc, byte| {
        acc.wrapping_mul(16777619).wrapping_add(byte as u64)
    })
}

pub(super) fn workspace_recipe_for_request(
    request: &ChatOutcomeArtifactRequest,
) -> WorkspaceRecipe {
    match request.workspace_recipe_id.as_deref() {
        Some("react-vite") => WorkspaceRecipe::ReactVite,
        _ => WorkspaceRecipe::StaticHtmlVite,
    }
}

pub(super) fn package_name_for_title(title: &str) -> String {
    let mut slug = title
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        "chat-artifact".to_string()
    } else if slug.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        format!("chat-{slug}")
    } else {
        slug
    }
}

pub(super) fn materialize_workspace_artifact_payload(
    title: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    edit_intent: Option<&ChatArtifactEditIntent>,
) -> ChatGeneratedArtifactPayload {
    let recipe = workspace_recipe_for_request(request);
    let package_name = package_name_for_title(title);
    let subject = fallback_if_empty(brief.subject_domain.as_str(), title);
    let focus_points = workspace_focus_points(brief);
    let files = match recipe {
        WorkspaceRecipe::StaticHtmlVite => workspace_static_html_files(
            title,
            &package_name,
            subject,
            &focus_points,
            brief,
            edit_intent,
        ),
        WorkspaceRecipe::ReactVite => workspace_react_vite_files(
            title,
            &package_name,
            subject,
            &focus_points,
            brief,
            edit_intent,
        ),
    };

    ChatGeneratedArtifactPayload {
        summary: match edit_intent {
            Some(intent) if intent.patch_existing_artifact => format!(
                "Patched the workspace scaffold for {subject} while preserving the current implementation surface."
            ),
            _ => format!(
                "Scaffolded a workspace_surface artifact for {subject} with request-grounded implementation files."
            ),
        },
        notes: vec![
            format!(
                "Workspace recipe: {}",
                match recipe {
                    WorkspaceRecipe::ReactVite => "react-vite",
                    WorkspaceRecipe::StaticHtmlVite => "vite-static-html",
                }
            ),
            format!("Primary subject: {subject}"),
        ],
        files,
    }
}

pub(super) fn workspace_focus_points(brief: &ChatArtifactBrief) -> Vec<String> {
    let mut points = brief.required_concepts.clone();
    if points.is_empty() {
        points.push(brief.subject_domain.clone());
    }
    points.truncate(4);
    points
}

pub(super) fn workspace_file(
    path: impl Into<String>,
    mime: impl Into<String>,
    role: ChatArtifactFileRole,
    renderable: bool,
    body: impl Into<String>,
) -> ChatGeneratedArtifactFile {
    ChatGeneratedArtifactFile {
        path: path.into(),
        mime: mime.into(),
        role,
        renderable,
        downloadable: true,
        encoding: None,
        body: body.into(),
    }
}

pub(super) fn workspace_static_html_files(
    title: &str,
    package_name: &str,
    subject: &str,
    focus_points: &[String],
    brief: &ChatArtifactBrief,
    edit_intent: Option<&ChatArtifactEditIntent>,
) -> Vec<ChatGeneratedArtifactFile> {
    let tone = if brief
        .visual_tone
        .iter()
        .any(|tone| tone.eq_ignore_ascii_case("enterprise"))
    {
        "Enterprise controls"
    } else {
        "Operational controls"
    };
    let patch_note = edit_intent.map(|intent| intent.summary.as_str()).unwrap_or(
        "Create a first-pass workspace implementation that is ready to build and refine.",
    );
    let metrics = focus_points
        .iter()
        .enumerate()
        .map(|(index, point)| {
            format!(
                "<article class=\"metric-card\"><span>Focus {}</span><strong>{}</strong><p>{}</p></article>",
                index + 1,
                html_escape(point),
                html_escape(&format!("Use this lane to keep {} grounded in {}.", title, point))
            )
        })
        .collect::<Vec<_>>()
        .join("\n          ");
    let focus_buttons = focus_points
        .iter()
        .enumerate()
        .map(|(index, point)| {
            format!(
                "<button type=\"button\" class=\"focus-chip{}\" data-focus=\"{}\">{}</button>",
                if index == 0 { " is-active" } else { "" },
                index,
                html_escape(point)
            )
        })
        .collect::<Vec<_>>()
        .join("\n            ");
    let focus_panels = focus_points
        .iter()
        .enumerate()
        .map(|(index, point)| {
            format!(
                "<article class=\"focus-panel{}\" data-panel=\"{}\"><h3>{}</h3><p>{}</p><ul><li>{}</li><li>{}</li></ul></article>",
                if index == 0 { " is-active" } else { "" },
                index,
                html_escape(point),
                html_escape(&format!(
                    "{} should feel explicitly designed for {} instead of a generic admin shell.",
                    title, point
                )),
                html_escape(&format!("Audience: {}", brief.audience)),
                html_escape(&format!("Directive: {}", patch_note))
            )
        })
        .collect::<Vec<_>>()
        .join("\n            ");
    let html = format!(
        "<!doctype html>\n<html lang=\"en\">\n  <head>\n    <meta charset=\"UTF-8\" />\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n    <title>{title}</title>\n    <link rel=\"stylesheet\" href=\"/styles.css\" />\n  </head>\n  <body>\n    <main class=\"app-shell\">\n      <section class=\"hero\">\n        <div>\n          <p class=\"eyebrow\">workspace_surface</p>\n          <h1>{title}</h1>\n          <p class=\"lede\">{tone} for {subject}. This workspace scaffold is request-faithful, buildable, and ready for follow-up refinement.</p>\n        </div>\n        <aside class=\"hero-card\">\n          <span>Artifact thesis</span>\n          <strong>{thesis}</strong>\n          <p>{patch_note}</p>\n        </aside>\n      </section>\n\n      <section class=\"metrics\">\n          {metrics}\n      </section>\n\n      <section class=\"workbench\">\n        <div class=\"section-copy\">\n          <p class=\"eyebrow\">Implementation lanes</p>\n          <h2>{subject}</h2>\n          <p>{job}</p>\n        </div>\n        <div class=\"focus-switcher\">\n          <div class=\"chip-row\">\n            {focus_buttons}\n          </div>\n          <div class=\"panel-stack\">\n            {focus_panels}\n          </div>\n        </div>\n      </section>\n    </main>\n    <script type=\"module\" src=\"/script.js\"></script>\n  </body>\n</html>\n",
        thesis = html_escape(&brief.artifact_thesis),
        job = html_escape(&brief.job_to_be_done),
        patch_note = html_escape(patch_note),
        subject = html_escape(subject),
        title = html_escape(title),
        tone = html_escape(tone),
    );
    let styles = format!(
        ":root {{\n  color-scheme: light;\n  --bg: #f2f5f9;\n  --panel: #ffffff;\n  --ink: #162033;\n  --muted: #5e6b82;\n  --line: rgba(22, 32, 51, 0.12);\n  --accent: #1e6bff;\n  --accent-soft: rgba(30, 107, 255, 0.12);\n  --success: #1d8b5f;\n  font-family: \"Segoe UI\", \"Helvetica Neue\", Arial, sans-serif;\n}}\n* {{ box-sizing: border-box; }}\nbody {{ margin: 0; min-width: 320px; background: radial-gradient(circle at top left, rgba(30, 107, 255, 0.10), transparent 22%), var(--bg); color: var(--ink); }}\n.app-shell {{ width: min(1180px, calc(100vw - 32px)); margin: 0 auto; padding: 32px 0 64px; }}\n.hero {{ display: grid; grid-template-columns: minmax(0, 1.2fr) 320px; gap: 20px; align-items: stretch; }}\n.hero, .metric-card, .hero-card, .focus-switcher {{ border: 1px solid var(--line); border-radius: 24px; background: var(--panel); box-shadow: 0 18px 50px rgba(22, 32, 51, 0.08); }}\n.hero {{ padding: 28px; }}\n.hero-card {{ padding: 22px; background: linear-gradient(180deg, rgba(30, 107, 255, 0.08), rgba(255,255,255,0.96)); }}\n.eyebrow {{ margin: 0 0 10px; font-size: 0.78rem; font-weight: 700; letter-spacing: 0.18em; text-transform: uppercase; color: var(--accent); }}\nh1, h2, h3 {{ margin: 0; letter-spacing: -0.03em; }}\nh1 {{ font-size: clamp(2.6rem, 6vw, 4.8rem); line-height: 0.94; }}\n.lede, .hero-card p, .section-copy p, .focus-panel p, .metric-card p {{ color: var(--muted); line-height: 1.65; }}\n.metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-top: 18px; }}\n.metric-card {{ padding: 18px; }}\n.metric-card span {{ display: block; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--success); }}\n.metric-card strong {{ display: block; margin-top: 8px; font-size: 1.15rem; }}\n.workbench {{ display: grid; grid-template-columns: 320px minmax(0, 1fr); gap: 20px; margin-top: 18px; }}\n.section-copy {{ padding: 10px 4px; }}\n.focus-switcher {{ padding: 24px; }}\n.chip-row {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 18px; }}\n.focus-chip {{ border: 1px solid var(--line); background: #f8fbff; color: var(--ink); border-radius: 999px; padding: 0.7rem 1rem; font: inherit; cursor: pointer; }}\n.focus-chip.is-active {{ background: var(--accent); color: #fff; border-color: var(--accent); }}\n.focus-panel {{ display: none; border-top: 1px solid var(--line); padding-top: 18px; }}\n.focus-panel.is-active {{ display: block; }}\n.focus-panel ul {{ margin: 14px 0 0; padding-left: 1.1rem; color: var(--muted); line-height: 1.65; }}\n@media (max-width: 920px) {{ .hero, .workbench {{ grid-template-columns: 1fr; }} .app-shell {{ width: min(100vw - 20px, 1180px); }} }}\n"
    );
    let script = "const chips = Array.from(document.querySelectorAll('[data-focus]'));\nconst panels = Array.from(document.querySelectorAll('[data-panel]'));\nfunction activate(index) {\n  chips.forEach((chip) => chip.classList.toggle('is-active', chip.dataset.focus === String(index)));\n  panels.forEach((panel) => panel.classList.toggle('is-active', panel.dataset.panel === String(index)));\n}\nchips.forEach((chip) => chip.addEventListener('click', () => activate(chip.dataset.focus)));\nactivate(0);\n".to_string();

    vec![
        workspace_file("index.html", "text/html", ChatArtifactFileRole::Primary, true, html),
        workspace_file(
            "styles.css",
            "text/css",
            ChatArtifactFileRole::Supporting,
            false,
            styles,
        ),
        workspace_file(
            "script.js",
            "application/javascript",
            ChatArtifactFileRole::Supporting,
            false,
            script,
        ),
        workspace_file(
            "package.json",
            "application/json",
            ChatArtifactFileRole::Supporting,
            false,
            format!(
                "{{\n  \"name\": \"{package_name}\",\n  \"private\": true,\n  \"version\": \"0.1.0\",\n  \"type\": \"module\",\n  \"scripts\": {{\n    \"dev\": \"vite\",\n    \"build\": \"vite build\",\n    \"preview\": \"vite preview\"\n  }},\n  \"devDependencies\": {{\n    \"vite\": \"^6.0.5\"\n  }}\n}}\n"
            ),
        ),
        workspace_file(
            "README.md",
            "text/markdown",
            ChatArtifactFileRole::Supporting,
            false,
            format!(
                "# {title}\n\nSubject: {subject}\n\nAudience: {}\n\nBuild:\n\n```bash\nnpm install\nnpm run build\n```\n",
                brief.audience
            ),
        ),
    ]
}

pub(super) fn workspace_react_vite_files(
    title: &str,
    package_name: &str,
    subject: &str,
    focus_points: &[String],
    brief: &ChatArtifactBrief,
    edit_intent: Option<&ChatArtifactEditIntent>,
) -> Vec<ChatGeneratedArtifactFile> {
    let focus_cards = focus_points
        .iter()
        .map(|point| {
            format!(
                "        <article className=\"focus-card\">\n          <h3>{}</h3>\n          <p>{}</p>\n        </article>",
                jsx_escape(point),
                jsx_escape(&format!("Keep the implementation grounded in {}.", point))
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let patch_note = edit_intent
        .map(|intent| intent.summary.as_str())
        .unwrap_or("Shape the starter surface around the actual request, not a canned dashboard.");
    let app = format!(
        "import './App.css'\n\nexport default function App() {{\n  return (\n    <main className=\"shell\">\n      <section className=\"hero\">\n        <div>\n          <p className=\"eyebrow\">workspace_surface</p>\n          <h1>{}</h1>\n          <p className=\"lede\">{} for {}.</p>\n        </div>\n        <aside className=\"brief-card\">\n          <span>Artifact thesis</span>\n          <strong>{}</strong>\n          <p>{}</p>\n        </aside>\n      </section>\n      <section className=\"focus-grid\">\n{}\n      </section>\n    </main>\n  )\n}}\n",
        jsx_escape(title),
        jsx_escape(&brief.job_to_be_done),
        jsx_escape(subject),
        jsx_escape(&brief.artifact_thesis),
        jsx_escape(patch_note),
        focus_cards
    );
    let app_css = ".shell { min-height: 100vh; padding: 3rem clamp(1.5rem, 4vw, 4rem); background: linear-gradient(180deg, #f4f7fb, #e9eef8); color: #162033; font-family: \"Segoe UI\", \"Helvetica Neue\", Arial, sans-serif; }\n.hero { display: grid; grid-template-columns: minmax(0, 1.2fr) 320px; gap: 20px; }\n.hero, .brief-card, .focus-card { border: 1px solid rgba(22,32,51,0.12); border-radius: 24px; background: white; box-shadow: 0 18px 50px rgba(22,32,51,0.08); }\n.hero { padding: 24px; }\n.brief-card { padding: 20px; background: linear-gradient(180deg, rgba(30,107,255,0.08), rgba(255,255,255,0.98)); }\n.eyebrow { margin: 0 0 10px; font-size: 0.78rem; font-weight: 700; letter-spacing: 0.18em; text-transform: uppercase; color: #1e6bff; }\nh1, h3 { margin: 0; letter-spacing: -0.03em; }\nh1 { font-size: clamp(2.6rem, 6vw, 4.6rem); line-height: 0.94; }\n.lede, .brief-card p, .focus-card p { color: #5e6b82; line-height: 1.65; }\n.focus-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-top: 18px; }\n.focus-card { padding: 18px; }\n@media (max-width: 920px) { .hero { grid-template-columns: 1fr; } }\n".to_string();

    vec![
        workspace_file("src/App.tsx", "text/tsx", ChatArtifactFileRole::Primary, true, app),
        workspace_file(
            "src/main.tsx",
            "text/tsx",
            ChatArtifactFileRole::Supporting,
            false,
            "import React from 'react'\nimport ReactDOM from 'react-dom/client'\nimport App from './App'\nimport './index.css'\n\nReactDOM.createRoot(document.getElementById('root')!).render(\n  <React.StrictMode>\n    <App />\n  </React.StrictMode>,\n)\n",
        ),
        workspace_file(
            "src/App.css",
            "text/css",
            ChatArtifactFileRole::Supporting,
            false,
            app_css,
        ),
        workspace_file(
            "src/index.css",
            "text/css",
            ChatArtifactFileRole::Supporting,
            false,
            ":root { color-scheme: light; font-family: \"Segoe UI\", \"Helvetica Neue\", Arial, sans-serif; line-height: 1.5; font-weight: 400; background: #f4f7fb; color: #162033; }\n* { box-sizing: border-box; }\nhtml, body, #root { margin: 0; min-height: 100%; }\nbody { min-width: 320px; }\n".to_string(),
        ),
        workspace_file(
            "index.html",
            "text/html",
            ChatArtifactFileRole::Supporting,
            false,
            format!(
                "<!doctype html>\n<html lang=\"en\">\n  <head>\n    <meta charset=\"UTF-8\" />\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n    <title>{}</title>\n  </head>\n  <body>\n    <div id=\"root\"></div>\n    <script type=\"module\" src=\"/src/main.tsx\"></script>\n  </body>\n</html>\n",
                html_escape(title)
            ),
        ),
        workspace_file(
            "vite.config.ts",
            "text/typescript",
            ChatArtifactFileRole::Supporting,
            false,
            "import { defineConfig } from 'vite'\nimport react from '@vitejs/plugin-react'\n\nexport default defineConfig({\n  plugins: [react()],\n})\n",
        ),
        workspace_file(
            "tsconfig.json",
            "application/json",
            ChatArtifactFileRole::Supporting,
            false,
            "{\n  \"files\": [],\n  \"references\": [\n    { \"path\": \"./tsconfig.app.json\" },\n    { \"path\": \"./tsconfig.node.json\" }\n  ]\n}\n",
        ),
        workspace_file(
            "tsconfig.app.json",
            "application/json",
            ChatArtifactFileRole::Supporting,
            false,
            "{\n  \"compilerOptions\": {\n    \"target\": \"ES2020\",\n    \"useDefineForClassFields\": true,\n    \"lib\": [\"ES2020\", \"DOM\", \"DOM.Iterable\"],\n    \"skipLibCheck\": true,\n    \"esModuleInterop\": true,\n    \"allowSyntheticDefaultImports\": true,\n    \"strict\": true,\n    \"module\": \"ESNext\",\n    \"moduleResolution\": \"Node\",\n    \"resolveJsonModule\": true,\n    \"isolatedModules\": true,\n    \"noEmit\": true,\n    \"jsx\": \"react-jsx\"\n  },\n  \"include\": [\"src\"]\n}\n",
        ),
        workspace_file(
            "tsconfig.node.json",
            "application/json",
            ChatArtifactFileRole::Supporting,
            false,
            "{\n  \"compilerOptions\": {\n    \"composite\": true,\n    \"skipLibCheck\": true,\n    \"module\": \"ESNext\",\n    \"moduleResolution\": \"Node\",\n    \"allowSyntheticDefaultImports\": true\n  },\n  \"include\": [\"vite.config.ts\"]\n}\n",
        ),
        workspace_file(
            "package.json",
            "application/json",
            ChatArtifactFileRole::Supporting,
            false,
            format!(
                "{{\n  \"name\": \"{package_name}\",\n  \"private\": true,\n  \"version\": \"0.1.0\",\n  \"type\": \"module\",\n  \"scripts\": {{\n    \"dev\": \"vite\",\n    \"build\": \"tsc -b && vite build\",\n    \"preview\": \"vite preview\"\n  }},\n  \"dependencies\": {{\n    \"react\": \"^18.3.1\",\n    \"react-dom\": \"^18.3.1\"\n  }},\n  \"devDependencies\": {{\n    \"@types/react\": \"^18.3.18\",\n    \"@types/react-dom\": \"^18.3.5\",\n    \"@vitejs/plugin-react\": \"^4.3.4\",\n    \"typescript\": \"^5.6.2\",\n    \"vite\": \"^6.0.5\"\n  }}\n}}\n"
            ),
        ),
        workspace_file(
            "README.md",
            "text/markdown",
            ChatArtifactFileRole::Supporting,
            false,
            format!(
                "# {title}\n\nSubject: {subject}\n\nAudience: {}\n\nBuild:\n\n```bash\nnpm install\nnpm run build\n```\n",
                brief.audience
            ),
        ),
    ]
}

pub(super) fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub(super) fn jsx_escape(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
}

fn fallback_if_empty<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.trim().is_empty() {
        fallback
    } else {
        value
    }
}
