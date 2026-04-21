use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct ChatHtmlPromotedDesignSkillSpine {
    pub visual_thesis: String,
    #[serde(default)]
    pub content_plan: Vec<String>,
    #[serde(default)]
    pub interaction_thesis: Vec<String>,
    pub typography_pairing: String,
    pub accent_strategy: String,
    #[serde(default)]
    pub reinforced_need_kinds: Vec<String>,
    #[serde(default)]
    pub avoidances: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct ChatHtmlScaffoldContract {
    pub family: String,
    pub variant_id: String,
    pub font_embed_href: String,
    pub font_pairing: String,
    #[serde(default)]
    pub css_variables: Vec<String>,
    #[serde(default)]
    pub shell_outline: Vec<String>,
    #[serde(default)]
    pub section_wrappers: Vec<String>,
    pub control_bar_pattern: String,
    pub detail_panel_pattern: String,
    #[serde(default)]
    pub motion_hooks: Vec<String>,
    #[serde(default)]
    pub utility_js_hooks: Vec<String>,
    #[serde(default)]
    pub slot_contracts: Vec<String>,
    #[serde(default)]
    pub component_families: Vec<String>,
    pub example_shell: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct ChatHtmlComponentPackContract {
    pub family: String,
    pub role: String,
    #[serde(default)]
    pub section_ids: Vec<String>,
    #[serde(default)]
    pub interaction_ids: Vec<String>,
    #[serde(default)]
    pub first_paint_contract: Vec<String>,
    pub markup_signature: String,
    pub behavior_signature: String,
    pub styling_signature: String,
}

fn html_skill_kind_label(kind: ChatArtifactSkillNeedKind) -> String {
    serde_json::to_string(&kind)
        .unwrap_or_else(|_| "\"unknown\"".to_string())
        .trim_matches('"')
        .to_string()
}

fn html_component_pack_template(
    family: &str,
) -> (
    &'static str,
    Vec<&'static str>,
    &'static str,
    &'static str,
    &'static str,
) {
    match family {
        "hero_frame" => (
            "orientation",
            vec![
                "Full-bleed hero section with a thesis line, dominant heading, and one calm support sentence.",
                "Expose the active control state or primary evidence cue in the first viewport.",
            ],
            "<section class=\"hero-frame\"><p class=\"eyebrow\">...</p><h1>...</h1><p>...</p></section>",
            "Entrance sequence reveals heading, support copy, and the primary control rail without changing layout ownership.",
            "Poster-like composition with one dominant visual plane, restrained chrome, and a narrow text column.",
        ),
        "shared_detail_panel" => (
            "shared_explanation",
            vec![
                "Persistent visible detail region with populated default text before any interaction.",
                "The same region updates from both control clicks and mark hover/focus when required.",
            ],
            "<aside class=\"detail-panel\"><h2>Detail</h2><p id=\"detail-copy\">...</p></aside>",
            "One updateDetail(detailText) path rewrites the shared copy instead of rebuilding the entire panel.",
            "Pinned or visually anchored aside with quieter surface treatment than the primary evidence plane.",
        ),
        "mapped_view_switcher" => (
            "panel_switching",
            vec![
                "At least two pre-rendered panels with literal data-view-panel attributes.",
                "Exactly one mapped panel is visible before the script runs.",
            ],
            "<nav class=\"control-bar\"><button data-view=\"overview\" aria-controls=\"overview-panel\">Overview</button>...</nav>",
            "Controls toggle hidden, aria-hidden, and aria-selected state on existing panel wrappers.",
            "Compact segmented control rail with strong active state and minimal decorative chrome.",
        ),
        "tabbed_evidence_rail" => (
            "evidence_navigation",
            vec![
                "Renderable evidence tabs or buttons with visible labels tied to different concepts or anchors.",
                "Non-selected views remain legible as previews or titles rather than disappearing into an empty shell.",
            ],
            "<div class=\"evidence-rail\"><button data-view=\"compare\">Compare</button><button data-view=\"timeline\">Timeline</button></div>",
            "Tabs or segmented buttons switch among pre-rendered evidence views while preserving the shared detail region.",
            "Low-chrome rail with clear active state, mono annotations, and strong spacing rhythm.",
        ),
        "comparison_table" => (
            "structured_comparison",
            vec![
                "At least three labeled rows or comparison criteria visible on first paint.",
                "Highlight the differentiating concept rather than repeating generic prose.",
            ],
            "<table class=\"comparison-table\"><tr><th>Property</th><th>Current</th><th>Target</th></tr>...</table>",
            "Hover, focus, or click states may update the detail panel, but the comparison remains readable without interaction.",
            "Editorial table treatment with generous row spacing, sparse rules, and accent-led emphasis.",
        ),
        "metric_card_grid" => (
            "evidence_summary",
            vec![
                "At least three labeled metrics, milestones, or evidence chips with concrete copy on first paint.",
                "Values and labels must map to different concepts or anchors, not three variants of the same phrase.",
            ],
            "<section class=\"metric-grid\"><article><span>Metric</span><strong>72%</strong><p>...</p></article>...</section>",
            "Cards or tiles may feed the detail panel, but each tile still carries meaningful first-paint content.",
            "Card-light grid with typographic scale doing most of the hierarchy work.",
        ),
        "guided_stepper" => (
            "progression",
            vec![
                "Visible step list, current step state, and next/previous controls or scrubber on first paint.",
                "Each step owns a distinct evidence payload rather than only renumbered headings.",
            ],
            "<section class=\"guided-stepper\"><ol><li class=\"is-active\">Step 1</li>...</ol><div class=\"step-actions\">...</div></section>",
            "Stepper updates active state inline and swaps or reveals the corresponding pre-rendered step payload.",
            "Linear narrative scaffold with strong numerals, rhythm, and subdued motion cues.",
        ),
        "timeline" => (
            "chronology",
            vec![
                "At least three dated or sequenced milestones on first paint.",
                "Milestones should surface concrete evidence or state changes, not decorative filler.",
            ],
            "<section class=\"timeline\"><article><span class=\"kicker\">01</span><h3>Milestone</h3><p>...</p></article>...</section>",
            "Timeline nodes may coordinate with the detail panel, but chronology remains readable without script execution.",
            "Vertical or horizontal rhythm-led layout with restrained rules and asymmetry.",
        ),
        "labeled_svg_chart_shell" => (
            "data_visualization",
            vec![
                "Inline SVG includes at least three visible marks plus axis, legend, labels, or aria naming.",
                "Marks already exist in the static document before any script wiring occurs.",
            ],
            "<svg viewBox=\"0 0 320 200\" role=\"img\" aria-label=\"Evidence chart\">...</svg>",
            "SVG marks update shared detail or active state without depending on blank mount divs or remote chart libraries.",
            "Diagram-first surface with accent-led labels, thin rules, and quiet grid framing.",
        ),
        "state_space_visualizer" => (
            "state_demo",
            vec![
                "Primary interactive state surface plus visible current-state readout on first paint.",
                "Preset controls or manipulation affordances already exist before script execution.",
            ],
            "<section class=\"state-space\"><canvas id=\"state-surface\"></canvas><p class=\"state-readout\">...</p></section>",
            "State controls mutate one existing visualization surface and readout instead of replacing the shell.",
            "High-contrast demo plane with one dominant surface and compact control grouping.",
        ),
        "distribution_comparator" => (
            "distribution",
            vec![
                "At least two contrasted distributions, percentages, or bar groups visible on first paint.",
                "Comparison labels must make the contrast legible without relying on narration alone.",
            ],
            "<section class=\"distribution-comparator\"><div class=\"bar-row\">...</div><div class=\"bar-row\">...</div></section>",
            "Controls or hover states adjust highlight and shared detail while leaving the baseline comparison visible.",
            "Data-forward row layout with strong labels, limited colors, and measured density.",
        ),
        "paired_state_correlation_demo" => (
            "correlation",
            vec![
                "Two coupled state surfaces or readouts are simultaneously visible on first paint.",
                "Interaction with one side produces an explicit correlated update on the other.",
            ],
            "<section class=\"paired-state\"><button data-entity=\"left\">...</button><button data-entity=\"right\">...</button></section>",
            "One interaction path updates both paired readouts to make the relationship visible rather than implied in prose.",
            "Split-plane composition with a strong connective line or shared axis.",
        ),
        "transform_diagram_surface" => (
            "transformation",
            vec![
                "Labeled source, transform, and result stages are visible on first paint.",
                "The surface reads as a process or gate diagram, not as a decorative poster.",
            ],
            "<section class=\"transform-diagram\"><svg viewBox=\"0 0 420 160\">...</svg></section>",
            "Selection updates the highlighted stage or transform explanation without rebuilding the diagram from scratch.",
            "Diagrammatic treatment with measured spacing, directional cues, and mono annotations.",
        ),
        _ => (
            "supporting",
            vec!["Keep the supporting surface populated and request-faithful on first paint."],
            "<section class=\"support-surface\">...</section>",
            "Supporting components refine an existing surface instead of injecting the only visible content late.",
            "Quiet supporting treatment that does not steal hierarchy from the primary evidence plane.",
        ),
    }
}

fn jsxify_markup_signature(markup: &str) -> String {
    markup.replace("class=\"", "className=\"")
}

fn html_font_embed_href(family: &str) -> &'static str {
    match family {
        "comparison_story" => "https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@500;600;700&family=IBM+Plex+Sans:wght@300;400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap",
        "data_forward_walkthrough" => "https://fonts.googleapis.com/css2?family=Sora:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&family=Source+Serif+4:wght@400;600&display=swap",
        "guided_tutorial" => "https://fonts.googleapis.com/css2?family=Newsreader:opsz,wght@6..72,500;6..72,600&family=Instrument+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap",
        "launch_page" => "https://fonts.googleapis.com/css2?family=Syne:wght@500;700;800&family=Manrope:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap",
        _ => "https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,500;9..144,600&family=Manrope:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap",
    }
}

fn html_font_pairing(family: &str) -> &'static str {
    match family {
        "comparison_story" => {
            "Cormorant Garamond for display, IBM Plex Sans for body, IBM Plex Mono for annotations"
        }
        "data_forward_walkthrough" => {
            "Sora for display, Source Serif 4 for narrative body, IBM Plex Mono for metrics"
        }
        "guided_tutorial" => {
            "Newsreader for display, Instrument Sans for body, JetBrains Mono for controls"
        }
        "launch_page" => "Syne for display, Manrope for body, IBM Plex Mono for system labels",
        _ => "Fraunces for display, Manrope for body, JetBrains Mono for annotations",
    }
}

fn scaffold_visual_thesis(
    family: &str,
    design_system: &ChatArtifactDesignSystem,
) -> &'static str {
    match family {
        "comparison_story" => {
            "Editorial comparison spread with a calm evidence rail, serif authority, and measured contrast."
        }
        "data_forward_walkthrough" => {
            "Data-led walkthrough where the numbers own the hierarchy and narrative support stays restrained."
        }
        "guided_tutorial" => {
            "Guided explainer with clear sequential rhythm, strong wayfinding, and one dominant learning surface."
        }
        "launch_page" => {
            "Launch-grade poster energy with one commanding headline plane and disciplined support evidence."
        }
        _ if design_system.motion_style.contains("staged") => {
            "Poster-led explainer with tactile typography, quiet depth, and a staged reveal sequence."
        }
        _ => {
            "Editorial explainer with deliberate typography, a single accent system, and low-chrome evidence framing."
        }
    }
}

fn scaffold_variant_id(family: &str, candidate_seed: u64) -> &'static str {
    match family {
        "comparison_story" => match candidate_seed % 3 {
            0 => "split-rail",
            1 => "offset-spread",
            _ => "stacked-comparison",
        },
        "data_forward_walkthrough" => match candidate_seed % 3 {
            0 => "signal-board",
            1 => "metric-ledger",
            _ => "staggered-statute",
        },
        "guided_tutorial" => match candidate_seed % 3 {
            0 => "chapter-rail",
            1 => "sticky-lab",
            _ => "step-sequence",
        },
        "launch_page" => match candidate_seed % 3 {
            0 => "poster-hero",
            1 => "angled-proof",
            _ => "signal-launch",
        },
        _ => match candidate_seed % 3 {
            0 => "poster-left-rail",
            1 => "split-hero-evidence",
            _ => "staggered-editorial",
        },
    }
}

pub(super) fn chat_html_promoted_design_skill_spine(
    brief: &ChatArtifactBrief,
    blueprint: &ChatArtifactBlueprint,
    artifact_ir: &ChatArtifactIR,
    selected_skills: &[ChatArtifactSelectedSkill],
) -> Option<ChatHtmlPromotedDesignSkillSpine> {
    if blueprint.renderer != ChatRendererKind::HtmlIframe {
        return None;
    }

    let mut reinforced_need_kinds = BTreeSet::new();
    for skill in selected_skills {
        for kind in &skill.matched_need_kinds {
            reinforced_need_kinds.insert(html_skill_kind_label(*kind));
        }
    }

    let content_plan = vec![
        format!(
            "Hero: frame '{}' for {} and surface the active control state immediately.",
            brief.artifact_thesis, brief.audience
        ),
        "Support: keep one evidence rail or metric summary visible before any click."
            .to_string(),
        "Detail: anchor a persistent explanation panel beside the primary evidence surface."
            .to_string(),
        "Final takeaway: close with a concise request-faithful conclusion rather than a generic CTA."
            .to_string(),
    ];
    let interaction_thesis = vec![
        format!(
            "Use {} as the entrance and progression mood, with the first viewport reading like a poster instead of a document.",
            blueprint.design_system.motion_style
        ),
        "Make state changes obvious through active control styling, panel visibility changes, and one shared detail update path."
            .to_string(),
        "Treat hover, focus, or step transitions as hierarchy tools rather than ornamental motion."
            .to_string(),
    ];

    Some(ChatHtmlPromotedDesignSkillSpine {
        visual_thesis: scaffold_visual_thesis(&blueprint.scaffold_family, &blueprint.design_system)
            .to_string(),
        content_plan,
        interaction_thesis,
        typography_pairing: html_font_pairing(&blueprint.scaffold_family).to_string(),
        accent_strategy: format!(
            "{} with {} density and emphasis modes: {}",
            blueprint.design_system.color_strategy,
            blueprint.design_system.density,
            artifact_ir
                .design_tokens
                .iter()
                .filter(|token| token.category == "motion" || token.category == "typography")
                .map(|token| token.value.clone())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        reinforced_need_kinds: reinforced_need_kinds.into_iter().collect(),
        avoidances: vec![
            "Do not fall back to Arial, Inter, Roboto, or system-only typography for the primary hierarchy."
                .to_string(),
            "Do not lead with dashboard-card mosaics or generic bordered tiles as the entire composition."
                .to_string(),
            "Do not treat the first viewport like a document stack when the scaffold expects a poster-like hero."
                .to_string(),
        ],
    })
}

pub(super) fn chat_html_scaffold_contract(
    blueprint: &ChatArtifactBlueprint,
    artifact_ir: &ChatArtifactIR,
    candidate_seed: u64,
) -> Option<ChatHtmlScaffoldContract> {
    if blueprint.renderer != ChatRendererKind::HtmlIframe {
        return None;
    }

    let component_families = blueprint
        .component_plan
        .iter()
        .map(|component| component.component_family.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let section_wrappers = blueprint
        .section_plan
        .iter()
        .map(|section| {
            format!(
                "{} -> <section data-section=\"{}\">",
                section.role, section.id
            )
        })
        .collect::<Vec<_>>();
    let slot_contracts = blueprint
        .section_plan
        .iter()
        .flat_map(|section| {
            section
                .first_paint_requirements
                .iter()
                .map(move |requirement| format!("{}: {}", section.id, requirement))
        })
        .collect::<Vec<_>>();
    let render_contracts = artifact_ir
        .render_eval_checklist
        .iter()
        .take(2)
        .cloned()
        .collect::<Vec<_>>();
    let variant_id = scaffold_variant_id(&blueprint.scaffold_family, candidate_seed).to_string();
    let example_shell = format!(
        "<!doctype html><html><head><link rel=\"stylesheet\" href=\"{}\"></head><body><main class=\"chat-shell {} {}\"><section class=\"hero-frame\">...</section><nav class=\"control-bar\"><button data-view=\"overview\" aria-controls=\"overview-panel\" aria-selected=\"true\">Overview</button><button data-view=\"compare\" aria-controls=\"compare-panel\" aria-selected=\"false\">Compare</button></nav><section id=\"overview-panel\" data-view-panel=\"overview\">...</section><section id=\"compare-panel\" data-view-panel=\"compare\" hidden>...</section><aside class=\"detail-panel\"><p id=\"detail-copy\">...</p></aside><footer>...</footer></main><script>const controls = Array.from(document.querySelectorAll('button[data-view]'));</script></body></html>",
        html_font_embed_href(&blueprint.scaffold_family),
        blueprint.scaffold_family,
        variant_id,
    );

    Some(ChatHtmlScaffoldContract {
        family: blueprint.scaffold_family.clone(),
        variant_id,
        font_embed_href: html_font_embed_href(&blueprint.scaffold_family).to_string(),
        font_pairing: html_font_pairing(&blueprint.scaffold_family).to_string(),
        css_variables: vec![
            "--page-bg".to_string(),
            "--surface".to_string(),
            "--surface-strong".to_string(),
            "--text-primary".to_string(),
            "--text-secondary".to_string(),
            "--accent".to_string(),
            "--border-soft".to_string(),
            "--display-font".to_string(),
            "--body-font".to_string(),
            "--mono-font".to_string(),
        ],
        shell_outline: vec![
            "Poster-led hero plane with one dominant headline and a narrow support column."
                .to_string(),
            "Primary evidence grid that keeps the shared detail panel visible beside the current surface."
                .to_string(),
            "Footer or takeaway band that closes the narrative without another hero treatment."
                .to_string(),
        ],
        section_wrappers,
        control_bar_pattern:
            "Use button[data-view] controls with aria-selected plus literal data-view-panel wrappers."
                .to_string(),
        detail_panel_pattern:
            "Use one persistent <aside> with #detail-copy as the shared explanation target."
                .to_string(),
        utility_js_hooks: vec![
            "const controls = Array.from(document.querySelectorAll('button[data-view]'));"
                .to_string(),
            "const panels = Array.from(document.querySelectorAll('[data-view-panel]'));"
                .to_string(),
            "const detailCopy = document.getElementById('detail-copy');".to_string(),
        ],
        slot_contracts,
        component_families,
        motion_hooks: vec![
            blueprint.design_system.motion_style.clone(),
            "staggered first-view reveal".to_string(),
            "active control underline or contrast shift".to_string(),
            render_contracts.join(" / "),
        ]
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .collect(),
        example_shell,
    })
}

pub(super) fn chat_html_component_pack_contracts(
    blueprint: &ChatArtifactBlueprint,
) -> Vec<ChatHtmlComponentPackContract> {
    if blueprint.renderer != ChatRendererKind::HtmlIframe {
        return Vec::new();
    }

    let mut seen = BTreeSet::new();
    let mut packs = Vec::new();
    for component in &blueprint.component_plan {
        if !seen.insert(component.component_family.clone()) {
            continue;
        }
        let (role, first_paint_contract, markup_signature, behavior_signature, styling_signature) =
            html_component_pack_template(&component.component_family);
        packs.push(ChatHtmlComponentPackContract {
            family: component.component_family.clone(),
            role: role.to_string(),
            section_ids: component.section_ids.clone(),
            interaction_ids: component.interaction_ids.clone(),
            first_paint_contract: first_paint_contract
                .into_iter()
                .map(|value| value.to_string())
                .collect(),
            markup_signature: markup_signature.to_string(),
            behavior_signature: behavior_signature.to_string(),
            styling_signature: styling_signature.to_string(),
        });
    }
    packs
}

pub(super) fn chat_jsx_promoted_design_skill_spine(
    brief: &ChatArtifactBrief,
    blueprint: &ChatArtifactBlueprint,
    artifact_ir: &ChatArtifactIR,
    selected_skills: &[ChatArtifactSelectedSkill],
) -> Option<ChatHtmlPromotedDesignSkillSpine> {
    if blueprint.renderer != ChatRendererKind::JsxSandbox {
        return None;
    }

    let mut reinforced_need_kinds = BTreeSet::new();
    for skill in selected_skills {
        for kind in &skill.matched_need_kinds {
            reinforced_need_kinds.insert(html_skill_kind_label(*kind));
        }
    }

    let content_plan = vec![
        format!(
            "Default export: frame '{}' as a stateful surface for {} with the initial pricing state already visible.",
            brief.artifact_thesis, brief.audience
        ),
        "Controls: keep the primary selector, slider, or plan switcher inside the default render tree instead of deferring it behind late DOM work."
            .to_string(),
        "Summary: derive one persistent evidence tray, comparison card, or detail panel from component state."
            .to_string(),
        "Close: finish with a concise request-faithful next-step or plan rationale block rather than a generic CTA."
            .to_string(),
    ];
    let interaction_thesis = vec![
        "Drive visible changes through explicit component state, derived values, or reducers instead of direct DOM mutation."
            .to_string(),
        format!(
            "Let {} set the rhythm through component reveal order, active control emphasis, and restrained transitions.",
            blueprint.design_system.motion_style
        ),
        "Keep every state transition legible from the rendered JSX tree: selected plan, changed metric, or revealed comparison should all be visible without devtools."
            .to_string(),
    ];

    Some(ChatHtmlPromotedDesignSkillSpine {
        visual_thesis: format!(
            "{} Compose it as a React/JSX surface with a strong default render, not as HTML pasted into one component.",
            scaffold_visual_thesis(&blueprint.scaffold_family, &blueprint.design_system)
        ),
        content_plan,
        interaction_thesis,
        typography_pairing: html_font_pairing(&blueprint.scaffold_family).to_string(),
        accent_strategy: format!(
            "{} with {} density and JSX-side emphasis modes: {}",
            blueprint.design_system.color_strategy,
            blueprint.design_system.density,
            artifact_ir
                .design_tokens
                .iter()
                .filter(|token| token.category == "motion" || token.category == "typography")
                .map(|token| token.value.clone())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        reinforced_need_kinds: reinforced_need_kinds.into_iter().collect(),
        avoidances: vec![
            "Do not collapse the JSX artifact into one generic form stack with no visible computed output."
                .to_string(),
            "Do not use document.querySelector, direct DOM mutation, or imperative innerHTML as the primary interaction model."
                .to_string(),
            "Do not hide the only pricing or configurator evidence behind an unopened modal, drawer, or collapsed panel."
                .to_string(),
        ],
    })
}

pub(super) fn chat_jsx_scaffold_contract(
    blueprint: &ChatArtifactBlueprint,
    artifact_ir: &ChatArtifactIR,
    candidate_seed: u64,
) -> Option<ChatHtmlScaffoldContract> {
    if blueprint.renderer != ChatRendererKind::JsxSandbox {
        return None;
    }

    let component_families = blueprint
        .component_plan
        .iter()
        .map(|component| component.component_family.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let section_wrappers = blueprint
        .section_plan
        .iter()
        .map(|section| {
            format!(
                "{} -> <section data-section=\"{}\">",
                section.role, section.id
            )
        })
        .collect::<Vec<_>>();
    let slot_contracts = blueprint
        .section_plan
        .iter()
        .flat_map(|section| {
            section
                .first_paint_requirements
                .iter()
                .map(move |requirement| format!("{}: {}", section.id, requirement))
        })
        .collect::<Vec<_>>();
    let render_contracts = artifact_ir
        .render_eval_checklist
        .iter()
        .take(2)
        .cloned()
        .collect::<Vec<_>>();
    let variant_id = scaffold_variant_id(&blueprint.scaffold_family, candidate_seed).to_string();
    let example_shell = format!(
        "import {{ useMemo, useState }} from \"react\";\n\nexport default function ChatArtifact() {{\n  const [activeView, setActiveView] = useState(\"overview\");\n  const detailCopy = useMemo(() => activeView === \"overview\" ? \"Default comparison is visible.\" : \"Alternate pricing evidence is visible.\", [activeView]);\n  return (\n    <main className=\"chat-shell {} {}\">\n      <section className=\"hero-frame\">...</section>\n      <nav className=\"control-bar\">\n        <button type=\"button\" data-view=\"overview\" aria-selected={{activeView === \"overview\"}} onClick={{() => setActiveView(\"overview\")}}>Overview</button>\n        <button type=\"button\" data-view=\"compare\" aria-selected={{activeView === \"compare\"}} onClick={{() => setActiveView(\"compare\")}}>Compare</button>\n      </nav>\n      {{activeView === \"overview\" ? <section data-view-panel=\"overview\">...</section> : <section data-view-panel=\"compare\">...</section>}}\n      <aside className=\"detail-panel\"><p id=\"detail-copy\">{{detailCopy}}</p></aside>\n    </main>\n  );\n}}",
        blueprint.scaffold_family, variant_id,
    );

    Some(ChatHtmlScaffoldContract {
        family: blueprint.scaffold_family.clone(),
        variant_id,
        font_embed_href: html_font_embed_href(&blueprint.scaffold_family).to_string(),
        font_pairing: html_font_pairing(&blueprint.scaffold_family).to_string(),
        css_variables: vec![
            "--page-bg".to_string(),
            "--surface".to_string(),
            "--surface-strong".to_string(),
            "--text-primary".to_string(),
            "--text-secondary".to_string(),
            "--accent".to_string(),
            "--border-soft".to_string(),
            "--display-font".to_string(),
            "--body-font".to_string(),
            "--mono-font".to_string(),
        ],
        shell_outline: vec![
            "Default-export hero plane with one dominant headline, visible configurator controls, and a computed summary rail."
                .to_string(),
            "Primary evidence section keeps the current state, pricing output, or comparison card visible beside the detail panel."
                .to_string(),
            "Closing takeaway block explains the selected scenario or next-step implication without another hero treatment."
                .to_string(),
        ],
        section_wrappers,
        control_bar_pattern:
            "Use button controls bound to component state (for example useState or a reducer) and reflect active state via aria-selected and visible output."
                .to_string(),
        detail_panel_pattern:
            "Use one persistent aside or summary region derived from current component state; keep default detail content visible on first render."
                .to_string(),
        utility_js_hooks: vec![
            "const [activeView, setActiveView] = useState(\"overview\");".to_string(),
            "const detailCopy = useMemo(() => ..., [activeView]);".to_string(),
            "Map over predeclared scenario or metric arrays instead of mutating the DOM directly."
                .to_string(),
        ],
        slot_contracts,
        component_families,
        motion_hooks: vec![
            blueprint.design_system.motion_style.clone(),
            "state-driven panel reveal".to_string(),
            "active control contrast shift".to_string(),
            render_contracts.join(" / "),
        ]
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .collect(),
        example_shell,
    })
}

pub(super) fn chat_jsx_component_pack_contracts(
    blueprint: &ChatArtifactBlueprint,
) -> Vec<ChatHtmlComponentPackContract> {
    if blueprint.renderer != ChatRendererKind::JsxSandbox {
        return Vec::new();
    }

    let mut seen = BTreeSet::new();
    let mut packs = Vec::new();
    for component in &blueprint.component_plan {
        if !seen.insert(component.component_family.clone()) {
            continue;
        }
        let (role, first_paint_contract, markup_signature, behavior_signature, styling_signature) =
            html_component_pack_template(&component.component_family);
        packs.push(ChatHtmlComponentPackContract {
            family: component.component_family.clone(),
            role: role.to_string(),
            section_ids: component.section_ids.clone(),
            interaction_ids: component.interaction_ids.clone(),
            first_paint_contract: first_paint_contract
                .into_iter()
                .map(|value| value.to_string())
                .collect(),
            markup_signature: jsxify_markup_signature(markup_signature),
            behavior_signature: format!(
                "Drive this pack through JSX state and derived props. {}",
                behavior_signature
            ),
            styling_signature: format!(
                "Compose this inside the React surface without generic utility clutter. {}",
                styling_signature
            ),
        });
    }
    packs
}

pub(super) fn chat_svg_promoted_design_skill_spine(
    brief: &ChatArtifactBrief,
    blueprint: &ChatArtifactBlueprint,
    artifact_ir: &ChatArtifactIR,
    selected_skills: &[ChatArtifactSelectedSkill],
) -> Option<ChatHtmlPromotedDesignSkillSpine> {
    if blueprint.renderer != ChatRendererKind::Svg {
        return None;
    }

    let mut reinforced_need_kinds = BTreeSet::new();
    for skill in selected_skills {
        for kind in &skill.matched_need_kinds {
            reinforced_need_kinds.insert(html_skill_kind_label(*kind));
        }
    }

    Some(ChatHtmlPromotedDesignSkillSpine {
        visual_thesis: format!(
            "{} Build it as a poster-grade SVG with a stable viewBox, layered marks, and visible labeling on first paint.",
            scaffold_visual_thesis(&blueprint.scaffold_family, &blueprint.design_system)
        ),
        content_plan: vec![
            format!(
                "Poster plane: make '{}' legible for {} without relying on fallback prose outside the SVG.",
                brief.artifact_thesis, brief.audience
            ),
            "Layer the composition into background field, focal motif, supporting labels, and one grounded evidence or anchor region."
                .to_string(),
            "Keep request-specific nouns and anchors inside visible labels, captions, or diagram annotations."
                .to_string(),
        ],
        interaction_thesis: vec![
            "Even without runtime interactivity, preserve visible hierarchy through grouped marks, label contrast, and directional composition."
                .to_string(),
            "Treat every mark as part of a coherent graphic system instead of a headline floating over one decorative shape."
                .to_string(),
            format!(
                "Reinforce {} through line weight, negative space, and a deliberate caption rhythm.",
                artifact_ir
                    .design_tokens
                    .iter()
                    .filter(|token| token.category == "typography" || token.category == "motion")
                    .map(|token| token.value.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ],
        typography_pairing:
            "High-contrast display serif or geometric sans for the focal label, with mono or restrained sans for annotations."
                .to_string(),
        accent_strategy: format!(
            "{} with {} density and one accent family reused across labels, key marks, and diagram emphasis.",
            blueprint.design_system.color_strategy, blueprint.design_system.density
        ),
        reinforced_need_kinds: reinforced_need_kinds.into_iter().collect(),
        avoidances: vec![
            "Do not collapse into one background rectangle plus one headline.".to_string(),
            "Do not leave the SVG without a stable viewBox, title, desc, or supporting labels."
                .to_string(),
            "Do not rely on foreignObject, remote scripts, or hidden HTML wrappers for the primary graphic."
                .to_string(),
        ],
    })
}

pub(super) fn chat_svg_scaffold_contract(
    blueprint: &ChatArtifactBlueprint,
    artifact_ir: &ChatArtifactIR,
    candidate_seed: u64,
) -> Option<ChatHtmlScaffoldContract> {
    if blueprint.renderer != ChatRendererKind::Svg {
        return None;
    }

    let component_families = blueprint
        .component_plan
        .iter()
        .map(|component| component.component_family.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let section_wrappers = blueprint
        .section_plan
        .iter()
        .map(|section| format!("{} -> <g data-section=\"{}\">", section.role, section.id))
        .collect::<Vec<_>>();
    let slot_contracts = blueprint
        .section_plan
        .iter()
        .flat_map(|section| {
            section
                .first_paint_requirements
                .iter()
                .map(move |requirement| format!("{}: {}", section.id, requirement))
        })
        .collect::<Vec<_>>();
    let render_contracts = artifact_ir
        .render_eval_checklist
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>();
    let variant_id = scaffold_variant_id(&blueprint.scaffold_family, candidate_seed).to_string();

    Some(ChatHtmlScaffoldContract {
        family: blueprint.scaffold_family.clone(),
        variant_id,
        font_embed_href: "inline-svg-font-stack".to_string(),
        font_pairing:
            "Display-first SVG typography with one strong headline stack, one annotation stack, and no remote dependency.".to_string(),
        css_variables: vec![
            "--poster-bg".to_string(),
            "--poster-accent".to_string(),
            "--poster-ink".to_string(),
            "--poster-muted".to_string(),
            "--poster-grid".to_string(),
        ],
        shell_outline: vec![
            "Stable <svg viewBox> root with title, desc, and grouped planes for background, focal motif, supporting labels, and evidence marks."
                .to_string(),
            "At least one label or annotation cluster must stay visible near the focal motif instead of moving all context into a footer."
                .to_string(),
            "Use grouped marks and contrast bands so the artifact reads as a composed poster rather than clip-art on a flat background."
                .to_string(),
        ],
        section_wrappers,
        control_bar_pattern:
            "Do not simulate HTML chrome; express navigation or emphasis through grouped marks, paths, and labeled clusters inside the SVG."
                .to_string(),
        detail_panel_pattern:
            "If detail is needed, anchor it as an integrated SVG annotation block or caption band instead of a detached side panel."
                .to_string(),
        motion_hooks: render_contracts,
        utility_js_hooks: vec![
            "No runtime JavaScript required; spend complexity on grouped marks, labeling, and viewBox discipline."
                .to_string(),
        ],
        slot_contracts,
        component_families,
        example_shell:
            "<svg viewBox=\"0 0 960 640\" xmlns=\"http://www.w3.org/2000/svg\"><title>...</title><desc>...</desc><rect width=\"960\" height=\"640\"/><g data-section=\"hero\">...</g><g data-section=\"evidence-surface\">...</g><g data-section=\"takeaways\">...</g></svg>"
                .to_string(),
    })
}

pub(super) fn chat_svg_component_pack_contracts(
    blueprint: &ChatArtifactBlueprint,
) -> Vec<ChatHtmlComponentPackContract> {
    if blueprint.renderer != ChatRendererKind::Svg {
        return Vec::new();
    }

    let mut seen = BTreeSet::new();
    let mut packs = Vec::new();
    for component in &blueprint.component_plan {
        if !seen.insert(component.component_family.clone()) {
            continue;
        }
        let (role, first_paint_contract, markup_signature, behavior_signature, styling_signature) =
            html_component_pack_template(&component.component_family);
        packs.push(ChatHtmlComponentPackContract {
            family: component.component_family.clone(),
            role: role.to_string(),
            section_ids: component.section_ids.clone(),
            interaction_ids: component.interaction_ids.clone(),
            first_paint_contract: first_paint_contract
                .into_iter()
                .map(|value| value.to_string())
                .collect(),
            markup_signature: markup_signature.to_string(),
            behavior_signature: format!(
                "Translate this pack into grouped SVG marks, text labels, and alignment cues. {}",
                behavior_signature
            ),
            styling_signature: format!(
                "Render this pack as a coherent vector layer with consistent stroke, fill, and label logic. {}",
                styling_signature
            ),
        });
    }
    packs
}

pub(super) fn chat_pdf_promoted_design_skill_spine(
    brief: &ChatArtifactBrief,
    blueprint: &ChatArtifactBlueprint,
    artifact_ir: &ChatArtifactIR,
    selected_skills: &[ChatArtifactSelectedSkill],
) -> Option<ChatHtmlPromotedDesignSkillSpine> {
    if blueprint.renderer != ChatRendererKind::PdfEmbed {
        return None;
    }

    let mut reinforced_need_kinds = BTreeSet::new();
    for skill in selected_skills {
        for kind in &skill.matched_need_kinds {
            reinforced_need_kinds.insert(html_skill_kind_label(*kind));
        }
    }

    Some(ChatHtmlPromotedDesignSkillSpine {
        visual_thesis: format!(
            "{} Shape it as a compact briefing PDF with crisp section rhythm, tables, and visible evidence density on every page-sized block.",
            scaffold_visual_thesis(&blueprint.scaffold_family, &blueprint.design_system)
        ),
        content_plan: vec![
            format!(
                "Open with '{}' framed for {} in one concise summary block.",
                brief.artifact_thesis, brief.audience
            ),
            "Distribute anchors into short sections, bullet lists, and compact tables instead of one uninterrupted wall of prose."
                .to_string(),
            "End with a concrete next-step or risk summary so the PDF reads like an actionable artifact, not a transcript."
                .to_string(),
        ],
        interaction_thesis: vec![
            "There is no runtime interactivity, so hierarchy must come from section order, heading contrast, and table density."
                .to_string(),
            "Use short blocks, bullet clusters, and compact matrix layouts so key signals remain scannable after export."
                .to_string(),
            format!(
                "Let {} steer the briefing rhythm through text contrast, spacing, and restrained emphasis.",
                artifact_ir
                    .design_tokens
                    .iter()
                    .filter(|token| token.category == "typography" || token.category == "layout")
                    .map(|token| token.value.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ],
        typography_pairing:
            "Document-first pairing with one authoritative heading face and one highly legible body face using embeddable PDF-safe fonts."
                .to_string(),
        accent_strategy: format!(
            "{} with {} density and restrained emphasis so metric tables stay legible in export.",
            blueprint.design_system.color_strategy, blueprint.design_system.density
        ),
        reinforced_need_kinds: reinforced_need_kinds.into_iter().collect(),
        avoidances: vec![
            "Do not emit LaTeX, markdown fences, or placeholder tokens as PDF source.".to_string(),
            "Do not rely on a single paragraph block where bullets, tables, or subsections are required."
                .to_string(),
            "Do not pad the PDF with generic executive-summary filler that ignores the requested anchors."
                .to_string(),
        ],
    })
}

pub(super) fn chat_pdf_scaffold_contract(
    blueprint: &ChatArtifactBlueprint,
    artifact_ir: &ChatArtifactIR,
    candidate_seed: u64,
) -> Option<ChatHtmlScaffoldContract> {
    if blueprint.renderer != ChatRendererKind::PdfEmbed {
        return None;
    }

    let component_families = blueprint
        .component_plan
        .iter()
        .map(|component| component.component_family.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let section_wrappers = blueprint
        .section_plan
        .iter()
        .map(|section| {
            format!(
                "{} -> heading + paragraph/list/table block for '{}'",
                section.role, section.id
            )
        })
        .collect::<Vec<_>>();
    let slot_contracts = blueprint
        .section_plan
        .iter()
        .flat_map(|section| {
            section
                .first_paint_requirements
                .iter()
                .map(move |requirement| format!("{}: {}", section.id, requirement))
        })
        .collect::<Vec<_>>();
    let variant_id = scaffold_variant_id(&blueprint.scaffold_family, candidate_seed).to_string();

    Some(ChatHtmlScaffoldContract {
        family: blueprint.scaffold_family.clone(),
        variant_id,
        font_embed_href: "pdf-core-font-stack".to_string(),
        font_pairing:
            "PDF-safe heading and body fonts with one mono or tabular treatment reserved for metrics and compact tables."
                .to_string(),
        css_variables: vec![
            "--page-margin".to_string(),
            "--section-gap".to_string(),
            "--heading-scale".to_string(),
            "--table-rule".to_string(),
        ],
        shell_outline: vec![
            "Page-sized briefing with title block, summary, concept sections, compact evidence table, and closing risks/next steps."
                .to_string(),
            "Use short sections that can survive PDF export as searchable text with visible headings and list rhythm."
                .to_string(),
            "At least one compact table or metric matrix must stay visible as part of the document evidence surface."
                .to_string(),
        ],
        section_wrappers,
        control_bar_pattern:
            "No runtime controls; use section ordering, callouts, and compact tables as the document's navigation spine."
                .to_string(),
        detail_panel_pattern:
            "Fold explanatory detail into inline callouts, risk boxes, or footnote-style sections rather than detached panels."
                .to_string(),
        motion_hooks: artifact_ir
            .render_eval_checklist
            .iter()
            .take(2)
            .cloned()
            .collect(),
        utility_js_hooks: vec![
            "No JavaScript. Keep the output as plain searchable document text structured for PDF export."
                .to_string(),
        ],
        slot_contracts,
        component_families,
        example_shell:
            "Executive Summary\n\n- Anchor 1\n- Anchor 2\n\nKey Metrics\n\nMetric | Value | Note\n--- | --- | ---\nReadiness | 82% | ...\n\nRisks\n\n- ...".to_string(),
    })
}

pub(super) fn chat_pdf_component_pack_contracts(
    blueprint: &ChatArtifactBlueprint,
) -> Vec<ChatHtmlComponentPackContract> {
    if blueprint.renderer != ChatRendererKind::PdfEmbed {
        return Vec::new();
    }

    let mut seen = BTreeSet::new();
    let mut packs = Vec::new();
    for component in &blueprint.component_plan {
        if !seen.insert(component.component_family.clone()) {
            continue;
        }
        let (role, first_paint_contract, markup_signature, behavior_signature, styling_signature) =
            html_component_pack_template(&component.component_family);
        packs.push(ChatHtmlComponentPackContract {
            family: component.component_family.clone(),
            role: role.to_string(),
            section_ids: component.section_ids.clone(),
            interaction_ids: component.interaction_ids.clone(),
            first_paint_contract: first_paint_contract
                .into_iter()
                .map(|value| value.to_string())
                .collect(),
            markup_signature: markup_signature.to_string(),
            behavior_signature: format!(
                "Translate this pack into structured document sections, bullets, and compact tables. {}",
                behavior_signature
            ),
            styling_signature: format!(
                "Keep the document dense but legible with typographic contrast rather than decorative chrome. {}",
                styling_signature
            ),
        });
    }
    packs
}

pub(super) fn chat_html_scaffold_execution_digest(
    brief: &ChatArtifactBrief,
    blueprint: &ChatArtifactBlueprint,
    artifact_ir: &ChatArtifactIR,
    selected_skills: &[ChatArtifactSelectedSkill],
    candidate_seed: u64,
) -> Option<String> {
    let design_spine =
        chat_html_promoted_design_skill_spine(brief, blueprint, artifact_ir, selected_skills)?;
    let scaffold = chat_html_scaffold_contract(blueprint, artifact_ir, candidate_seed)?;
    let component_packs = chat_html_component_pack_contracts(blueprint);
    let component_inventory = component_packs
        .iter()
        .map(|pack| pack.family.clone())
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "- Visual thesis: {}\n- Content plan: {}\n- Interaction thesis: {}\n- Font pairing: {}\n- Scaffold family + variant: {} / {}\n- Scaffold shell: {}\n- Utility JS hooks: {}\n- Component packs to compose: {}",
        design_spine.visual_thesis,
        design_spine.content_plan.join(" | "),
        design_spine.interaction_thesis.join(" | "),
        scaffold.font_pairing,
        scaffold.family,
        scaffold.variant_id,
        scaffold.shell_outline.join(" | "),
        scaffold.utility_js_hooks.join(" | "),
        component_inventory,
    ))
}

pub(super) fn chat_jsx_scaffold_execution_digest(
    brief: &ChatArtifactBrief,
    blueprint: &ChatArtifactBlueprint,
    artifact_ir: &ChatArtifactIR,
    selected_skills: &[ChatArtifactSelectedSkill],
    candidate_seed: u64,
) -> Option<String> {
    let design_spine =
        chat_jsx_promoted_design_skill_spine(brief, blueprint, artifact_ir, selected_skills)?;
    let scaffold = chat_jsx_scaffold_contract(blueprint, artifact_ir, candidate_seed)?;
    let component_packs = chat_jsx_component_pack_contracts(blueprint);
    let component_inventory = component_packs
        .iter()
        .map(|pack| pack.family.clone())
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "- Visual thesis: {}\n- Content plan: {}\n- Interaction thesis: {}\n- Font pairing: {}\n- Scaffold family + variant: {} / {}\n- JSX shell: {}\n- Utility hooks: {}\n- Component packs to compose: {}",
        design_spine.visual_thesis,
        design_spine.content_plan.join(" | "),
        design_spine.interaction_thesis.join(" | "),
        scaffold.font_pairing,
        scaffold.family,
        scaffold.variant_id,
        scaffold.shell_outline.join(" | "),
        scaffold.utility_js_hooks.join(" | "),
        component_inventory,
    ))
}

pub(super) fn chat_svg_scaffold_execution_digest(
    brief: &ChatArtifactBrief,
    blueprint: &ChatArtifactBlueprint,
    artifact_ir: &ChatArtifactIR,
    selected_skills: &[ChatArtifactSelectedSkill],
    candidate_seed: u64,
) -> Option<String> {
    let design_spine =
        chat_svg_promoted_design_skill_spine(brief, blueprint, artifact_ir, selected_skills)?;
    let scaffold = chat_svg_scaffold_contract(blueprint, artifact_ir, candidate_seed)?;
    let component_packs = chat_svg_component_pack_contracts(blueprint);
    let component_inventory = component_packs
        .iter()
        .map(|pack| pack.family.clone())
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "- Visual thesis: {}\n- Content plan: {}\n- Interaction thesis: {}\n- Font pairing: {}\n- Scaffold family + variant: {} / {}\n- SVG shell: {}\n- Structural hooks: {}\n- Component packs to compose: {}",
        design_spine.visual_thesis,
        design_spine.content_plan.join(" | "),
        design_spine.interaction_thesis.join(" | "),
        scaffold.font_pairing,
        scaffold.family,
        scaffold.variant_id,
        scaffold.shell_outline.join(" | "),
        scaffold.utility_js_hooks.join(" | "),
        component_inventory,
    ))
}

pub(super) fn chat_pdf_scaffold_execution_digest(
    brief: &ChatArtifactBrief,
    blueprint: &ChatArtifactBlueprint,
    artifact_ir: &ChatArtifactIR,
    selected_skills: &[ChatArtifactSelectedSkill],
    candidate_seed: u64,
) -> Option<String> {
    let design_spine =
        chat_pdf_promoted_design_skill_spine(brief, blueprint, artifact_ir, selected_skills)?;
    let scaffold = chat_pdf_scaffold_contract(blueprint, artifact_ir, candidate_seed)?;
    let component_packs = chat_pdf_component_pack_contracts(blueprint);
    let component_inventory = component_packs
        .iter()
        .map(|pack| pack.family.clone())
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "- Visual thesis: {}\n- Content plan: {}\n- Interaction thesis: {}\n- Font pairing: {}\n- Scaffold family + variant: {} / {}\n- Document shell: {}\n- Structural hooks: {}\n- Component packs to compose: {}",
        design_spine.visual_thesis,
        design_spine.content_plan.join(" | "),
        design_spine.interaction_thesis.join(" | "),
        scaffold.font_pairing,
        scaffold.family,
        scaffold.variant_id,
        scaffold.shell_outline.join(" | "),
        scaffold.utility_js_hooks.join(" | "),
        component_inventory,
    ))
}
