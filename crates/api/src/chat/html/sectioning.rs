#[derive(Clone, Copy, PartialEq, Eq)]
enum HtmlTopLevelSectioningGroupKind {
    Narrative,
    Control,
    Panel,
    DetailMarks,
    SharedDetail,
}

fn html_fragment_sectioning_group_kind(fragment: &str) -> HtmlTopLevelSectioningGroupKind {
    let lower = fragment.to_ascii_lowercase();
    if lower.contains("shared-detail")
        || lower.contains("detail-copy")
        || lower.contains("data-chat-shared-detail=")
    {
        HtmlTopLevelSectioningGroupKind::SharedDetail
    } else if lower.contains("data-detail=")
        || lower.contains("class=\"data-detail\"")
        || lower.contains("class='data-detail'")
    {
        HtmlTopLevelSectioningGroupKind::DetailMarks
    } else if lower.contains("data-view-panel=")
        || lower.contains("data-panel=")
        || lower.contains("role=\"tabpanel\"")
        || lower.contains("role='tabpanel'")
        || lower.contains("class=\"evidence\"")
        || lower.contains("class='evidence'")
    {
        HtmlTopLevelSectioningGroupKind::Panel
    } else if lower.contains("<button")
        || lower.contains("data-view=")
        || lower.contains("aria-controls=")
        || lower.contains("control-bar")
    {
        HtmlTopLevelSectioningGroupKind::Control
    } else {
        HtmlTopLevelSectioningGroupKind::Narrative
    }
}

fn flush_html_sectioning_group(normalized: &mut String, pending_section: &mut String) {
    if pending_section.trim().is_empty() {
        normalized.push_str(pending_section);
        pending_section.clear();
        return;
    }

    normalized.push_str("<section data-chat-normalized=\"true\">");
    normalized.push_str(pending_section);
    normalized.push_str("</section>");
    pending_section.clear();
}

pub(super) fn split_top_level_html_fragments(inner: &str) -> Vec<String> {
    let mut fragments = Vec::new();
    let mut depth = 0usize;
    let mut start = None;
    let mut index = 0usize;

    while index < inner.len() {
        let rest = &inner[index..];
        if rest.starts_with("<!--") {
            let end = rest
                .find("-->")
                .map(|offset| index + offset + 3)
                .unwrap_or(inner.len());
            if depth == 0 && start.is_none() {
                start = Some(index);
            }
            index = end;
            if depth == 0 {
                if let Some(fragment_start) = start.take() {
                    fragments.push(inner[fragment_start..index].to_string());
                }
            }
            continue;
        }

        if rest.starts_with('<') {
            let Some(tag_close_offset) = rest.find('>') else {
                break;
            };
            let tag_end = index + tag_close_offset + 1;
            let tag_source = &inner[index + 1..tag_end - 1];
            let trimmed = tag_source.trim();

            if trimmed.starts_with('!') || trimmed.starts_with('?') {
                if depth == 0 && start.is_none() {
                    start = Some(index);
                }
                index = tag_end;
                if depth == 0 {
                    if let Some(fragment_start) = start.take() {
                        fragments.push(inner[fragment_start..index].to_string());
                    }
                }
                continue;
            }

            let closing = trimmed.starts_with('/');
            let tag_name = html_tag_name_from_source(trimmed);

            if depth == 0 && start.is_none() {
                start = Some(index);
            }

            if !closing && matches!(tag_name.as_deref(), Some("script") | Some("style")) {
                let Some(name) = tag_name.as_deref() else {
                    break;
                };
                let closing_tag = format!("</{name}>");
                let rest_lower = rest.to_ascii_lowercase();
                let end = rest_lower
                    .find(&closing_tag)
                    .map(|offset| index + offset + closing_tag.len())
                    .unwrap_or(tag_end);
                index = end;
                if depth == 0 {
                    if let Some(fragment_start) = start.take() {
                        fragments.push(inner[fragment_start..index].to_string());
                    }
                }
                continue;
            }

            let self_closing =
                trimmed.ends_with('/') || tag_name.as_deref().is_some_and(is_html_void_tag);
            if closing {
                depth = depth.saturating_sub(1);
                index = tag_end;
                if depth == 0 {
                    if let Some(fragment_start) = start.take() {
                        fragments.push(inner[fragment_start..index].to_string());
                    }
                }
                continue;
            }

            index = tag_end;
            if self_closing {
                if depth == 0 {
                    if let Some(fragment_start) = start.take() {
                        fragments.push(inner[fragment_start..index].to_string());
                    }
                }
                continue;
            }

            depth += 1;
            continue;
        }

        let advance = rest.chars().next().map(|ch| ch.len_utf8()).unwrap_or(1);
        if !rest.chars().next().is_some_and(char::is_whitespace) && start.is_none() {
            start = Some(index);
        }
        index += advance;
    }

    if let Some(fragment_start) = start {
        fragments.push(inner[fragment_start..].to_string());
    }

    fragments
}

pub(super) fn html_fragment_has_sectioning_root(fragment: &str) -> bool {
    matches!(
        html_fragment_root_tag_name(fragment).as_deref(),
        Some("section" | "article" | "nav" | "aside" | "footer")
    )
}

pub(super) fn html_fragment_is_script_like(fragment: &str) -> bool {
    matches!(
        html_fragment_root_tag_name(fragment).as_deref(),
        Some("script" | "style")
    )
}

pub(super) fn html_fragment_root_tag_name(fragment: &str) -> Option<String> {
    let trimmed = fragment.trim_start();
    if !trimmed.starts_with('<') || trimmed.starts_with("</") {
        return None;
    }
    let tag_end = trimmed.find('>')?;
    html_tag_name_from_source(trimmed.get(1..tag_end)?.trim())
}

pub(super) fn html_fragment_inner_for_resection(fragment: &str) -> Option<&str> {
    let tag_name = html_fragment_root_tag_name(fragment)?;
    if tag_name != "div" {
        return None;
    }
    let (content_start, content_end) = html_tag_content_range(fragment, &tag_name)?;
    if content_end >= fragment.len() {
        return None;
    }
    let closing = fragment[content_end..].trim();
    if !closing.eq_ignore_ascii_case("</div>") {
        return None;
    }
    Some(&fragment[content_start..content_end])
}

pub(super) fn html_tag_content_range(html: &str, tag: &str) -> Option<(usize, usize)> {
    let lower = html.to_ascii_lowercase();
    let opening = format!("<{tag}");
    let closing = format!("</{tag}>");
    let open_start = lower.find(&opening)?;
    let open_end = lower[open_start..].find('>')?;
    let content_start = open_start + open_end + 1;
    let close_start = lower[content_start..].rfind(&closing)?;
    Some((content_start, content_start + close_start))
}

pub(super) fn html_tag_name_from_source(source: &str) -> Option<String> {
    let trimmed = source.trim_start_matches('/').trim();
    let name: String = trimmed
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == ':')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name.to_ascii_lowercase())
    }
}

pub(super) fn is_html_void_tag(tag_name: &str) -> bool {
    matches!(
        tag_name,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

pub(super) fn chat_artifact_materialization_failure_directives(
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    failure: &str,
) -> String {
    if request.renderer != ChatRendererKind::HtmlIframe {
        let mut directives = vec![
            "- Repair only the cited schema failures while preserving the strongest request-specific content.".to_string(),
        ];
        let failure_lower = failure.to_ascii_lowercase();
        if failure_lower.contains("missing json payload") {
            directives.push(
                "- Return the artifact inside the exact JSON schema; do not answer with raw document text or prose outside the JSON object.".to_string(),
            );
        }
        if request.renderer == ChatRendererKind::PdfEmbed {
            directives.push(
                "- For pdf_embed, keep the full document text inside files[0].body and keep the primary path ending in .pdf.".to_string(),
            );
            if failure_lower.contains("clearer sections") {
                directives.push(
                    "- Use at least five short standalone section headings on their own lines, separated by blank lines, so the rendered PDF keeps visible section breaks."
                        .to_string(),
                );
                directives.push(
                    "- Keep headings concrete and compact, such as Executive Summary, Project Scope, Target Audience, Marketing Strategy, Timeline and Milestones, and Next Steps and Risks."
                        .to_string(),
                );
            }
            if failure_lower.contains("placeholder") {
                directives.push(
                    "- Replace every bracketed template token with concrete request-grounded bullets, milestones, owners, risks, or decisions; do not leave [Detailed description]-style filler anywhere in the document."
                        .to_string(),
                );
            }
        }
        return directives.join("\n");
    }

    let mut directives = vec![
        "- Return one complete self-contained .html file with inline CSS and inline JS only.".to_string(),
        "- Keep the strongest request-specific copy, labels, chart concepts, and interaction intent from the prior attempt.".to_string(),
        "- If several controls, cards, or marks share behavior, select them as a real collection before iterating and only target views that already exist in the markup.".to_string(),
    ];
    let exact_view_scaffold = html_prompt_exact_view_scaffold(brief);
    let rollover_mark_example = html_prompt_rollover_mark_example(brief);
    let two_view_example = html_prompt_two_view_example(brief);
    let view_mapping_pattern = html_prompt_view_mapping_pattern(brief);
    let failure_lower = failure.to_ascii_lowercase();
    if failure_lower.contains("missing json payload") {
        directives.push(
            "- Return the artifact inside the exact JSON schema; do not answer with raw HTML, raw JSX, raw SVG, or prose outside the JSON object."
                .to_string(),
        );
        directives.push(
            "- Keep the complete HTML document in files[0].body with the existing primary file path and mime instead of emitting a naked document."
                .to_string(),
        );
    }
    if failure_lower.contains("sectioning elements") {
        directives.push(
            "- Ensure <main> contains at least three sectioning elements with visible first-paint content. A valid pattern is hero <section>, detail <section>, and either <aside> or <footer>."
                .to_string(),
        );
        directives.push(
            "- Give every sectioning region its own heading plus visible body content, data marks, scorecards, or explanatory detail before any script runs; do not leave a section as a control-only wrapper or empty chart mount."
                .to_string(),
        );
    }
    if failure_lower.contains("<main> region") {
        directives.push(
            "- Include a real <main> region that contains the primary artifact composition."
                .to_string(),
        );
        directives.push(
            "- Start from a safe scaffold like <!doctype html><html><body><main>...visible sections, articles, asides, and footers...</main><script>...interactive wiring...</script></body></html>."
                .to_string(),
        );
        directives.push(
            "- Keep visible artifact markup inside <main> before the script tag; do not spend the head on a long script block before the first surfaced section."
                .to_string(),
        );
    }
    if failure_lower.contains("alert()") {
        directives.push(
            "- Replace alert-only controls with on-page state changes, revealed details, filtering, comparison, or step transitions."
                .to_string(),
        );
    }
    if failure_lower.contains("external libraries") || failure_lower.contains("undefined globals") {
        directives.push(
            "- Replace external libraries or undefined globals with inline SVG, canvas, or DOM/CSS implementations."
                .to_string(),
        );
    }
    if failure_lower.contains("placeholder-grade")
        || failure_lower.contains("placeholder copy")
        || failure_lower.contains("placeholder comments")
    {
        directives.push(
            "- Remove placeholder comments, TODO markers, and filler labels entirely; every visible mark, comment-free region, and handler must be production-ready."
                .to_string(),
        );
        directives.push(
            "- Do not emit the literal words placeholder, placeholders, TODO, or TBD anywhere in the final HTML, CSS, JavaScript, comments, ids, classes, or visible copy."
                .to_string(),
        );
    }
    if failure_lower.contains("real svg marks or labels on first paint") {
        directives.push(
            "- Replace empty chart shells with inline SVG that already contains bars, lines, labels, legends, or callout text on first paint."
                .to_string(),
        );
    }
    if failure_lower.contains("visible labels, legends, or aria labels") {
        directives.push(
            "- Replace decorative SVG geometry with labeled charts or diagrams. Include <text>, legend copy, or aria-label/title metadata tied to the visible marks."
                .to_string(),
        );
    }
    if failure_lower.contains("visible chart content on first paint")
        || failure_lower.contains("chart containers are empty placeholder shells")
    {
        directives.push(
            "- Replace empty chart containers or blank canvases with visible first-paint content such as inline SVG marks, labels, legends, tables, or explanatory callouts."
                .to_string(),
        );
        directives.push(
            "- Put the default chart and supporting detail directly in the markup before the script tag, then let interaction handlers switch or annotate that visible state."
                .to_string(),
        );
        directives.push(
            "- Do not use DOMContentLoaded, innerHTML, appendChild, createElement, or canvas drawing to create the very first visible chart or comparison content from an empty region."
                .to_string(),
        );
    }
    if failure_lower.contains("shared detail or comparison regions are empty")
        || failure_lower.contains("populate them on first paint")
    {
        directives.push(
            "- Populate the shared detail, comparison, or explanation panel with meaningful default copy before any interaction occurs."
                .to_string(),
        );
        directives.push(
            "- Update that same populated panel inline when controls, marks, or cards are activated; do not leave it empty or comment-only."
                .to_string(),
        );
    }
    if failure_lower.contains(
        "required interactions must include a populated shared detail or comparison region",
    ) {
        directives.push(
            "- Add a shared detail, comparison, or explanation panel with meaningful default copy on first paint. Buttons, marks, or cards should update that same panel inline."
                .to_string(),
        );
        directives.push(
            "- Keep the shared detail region visible beside the controls and evidence views instead of hiding it behind a later interaction."
                .to_string(),
        );
    }
    if failure_lower.contains("charted evidence must surface at least two populated evidence views")
    {
        directives.push(
            "- Surface at least two populated evidence views on first paint: a primary chart or evidence article plus a secondary comparison card, legend table, supporting chart, or evidence article."
                .to_string(),
        );
        directives.push(
            "- Do not collapse the artifact into one chart and a footer. Keep the secondary evidence region visible before any click."
                .to_string(),
        );
        directives.push(
            "- Empty mount divs like <div id=\"usage-chart\"></div> or placeholder chart wrappers do not count as evidence views; populate the secondary surface with inline SVG marks, a comparison table, metric cards, or labeled evidence rows."
                .to_string(),
        );
        directives.push(
            "- A single sentence paragraph does not count as the secondary evidence surface; give it multiple labeled rows, bullets, cards, or a second SVG tied to a different brief concept."
                .to_string(),
        );
        directives.push(format!(
            "- A concrete repair shape is one visible {} Keep the sibling comparison rail, score table, or evidence article visible on first paint.",
            two_view_example
        ));
    }
    if failure_lower.contains("call for clickable view switching")
        || failure_lower.contains("controls to pre-rendered view panels")
        || failure_lower.contains("controls to pre-rendered views")
    {
        directives.push(
            "- Use explicit static mappings for clickable navigation: buttons or tabs with data-view/aria-controls/data-target values and pre-rendered panels that already exist in the markup."
                .to_string(),
        );
        directives.push(format!(
            "- Prefer a pattern like {}, then toggle hidden, data-active, or aria-selected state.",
            view_mapping_pattern
        ));
        directives.push(
            "- Keep data-view-panel as a literal HTML attribute on the panel element itself; a CSS class like class=\"data-view-panel\" does not satisfy the mapped-panel contract."
                .to_string(),
        );
        directives.push(
            "- Prefer dataset comparisons such as panel.dataset.viewPanel !== button.dataset.view instead of building a querySelector string with nested quotes."
                .to_string(),
        );
        directives.push(
            "- Static data-view, aria-controls, or data-target attributes do not count on their own; wire button or tab click handlers that toggle hidden, aria-selected, aria-hidden, or comparable panel state."
                .to_string(),
        );
        directives.push(
            "- Do not use class names like class=\"overview-panel\" or class=\"data-view-panel\" as a substitute for actual panel ids or data-view-panel attributes on the panel wrapper."
                .to_string(),
        );
        directives.push(
            "- A reliable scaffold is a control bar with buttons[data-view], a matching pre-rendered panel for each view such as <section data-view-panel=\"satisfaction\">...</section> and <section data-view-panel=\"usage\" hidden>...</section>, one shared detail aside like #detail-copy, and a script that selects all [data-view-panel] nodes before toggling hidden state."
                .to_string(),
        );
        directives.push(format!(
            "- A safe exact scaffold is {}.",
            exact_view_scaffold
        ));
        directives.push(
            "- If you use aria-controls, point it at a section, article, div, aside, or figure panel wrapper in the markup, not directly at an SVG, canvas, or inner chart node."
                .to_string(),
        );
        directives.push(
            "- Keep exactly one mapped panel visibly selected in the raw HTML before any script runs; the other mapped panels may start hidden."
                .to_string(),
        );
        directives.push(
            "- Do not point every button at the shared detail panel with aria-controls alone; the shared detail panel complements the per-view panels and does not replace them."
                .to_string(),
        );
        directives.push(
            "- Do not synthesize target ids by concatenating button ids or other runtime strings."
                .to_string(),
        );
    }
    if failure_lower.contains("call for rollover detail must wire hover or focus handlers")
        || failure_lower.contains("keyboard-focusable")
        || failure_lower.contains("focus-based detail behavior")
    {
        directives.push(
            "- Patch the existing scaffold in place: keep the current <main>, populated sectioning regions, mapped view panels, and shared detail aside while you repair focusability."
                .to_string(),
        );
        directives.push(
            "- Add at least three visible marks or cards with data-detail text plus mouseenter, mouseover, or focus handlers that rewrite the shared detail panel inline."
                .to_string(),
        );
        directives.push(
            "- Preserve a meaningful default detail state on first paint, then replace it when a user hovers or focuses a specific evidence mark."
                .to_string(),
        );
        directives.push(
            "- Select those marks as a real collection such as querySelectorAll('[data-detail]') and make non-focusable marks focusable with tabindex=\"0\" before attaching focus handlers."
                .to_string(),
        );
        if brief_requires_view_switching(brief) {
            directives.push(
                "- Do not delete or replace the mapped panel scaffold while fixing focusability; preserve the existing buttons[data-view], [data-view-panel] containers, and #detail-copy region."
                    .to_string(),
            );
        }
        directives.push(format!(
            "- A concrete repair shape is {} inside a visible chart plus const detailCopy = document.getElementById('detail-copy'); document.querySelectorAll('[data-detail]').forEach((mark) => {{ mark.addEventListener('mouseenter', () => {{ detailCopy.textContent = mark.dataset.detail; }}); mark.addEventListener('focus', () => {{ detailCopy.textContent = mark.dataset.detail; }}); }});",
            rollover_mark_example
        ));
    }
    if failure_lower
        .contains("call for rollover detail must surface at least three visible data-detail marks")
    {
        directives.push(
            "- Surface at least three visible rollover targets on first paint; a single generic bar, dot, or heading is not enough."
                .to_string(),
        );
        directives.push(
            "- Use request-grounded labels from factual anchors, required concepts, or reference hints for those data-detail values instead of generic labels like Overview."
                .to_string(),
        );
        directives.push(
            "- If the chart only has one mark, add a visible chip rail, comparison list, or evidence card group with data-detail payloads so hover/focus still exposes multiple editorial details."
                .to_string(),
        );
    }
    if failure_lower.contains("interactive controls or handlers") {
        directives.push(
            "- Add visible controls with working event handlers and first-paint content so the artifact is actually interactive."
                .to_string(),
        );
        directives.push(
            "- For click interactions, render at least one real <button>, <details>/<summary>, or similarly obvious control on first paint and wire it with click handlers that mutate visible inline state."
                .to_string(),
        );
        directives.push(
            "- For drag-style interactions, prefer a range input, slider, scrubber, or draggable handle that updates labels, diagrams, captions, or comparison state while the user drags; describe the state change in the DOM instead of only animating decoration."
                .to_string(),
        );
        directives.push(
            "- Keep the repair concrete: include the actual control element in the HTML plus inline JavaScript such as addEventListener('click', ...) or addEventListener('input', ...) that rewrites visible text, classes, transforms, or comparison state."
                .to_string(),
        );
    }
    if failure_lower.contains("missing dom ids") {
        directives.push(
            "- Every getElementById or querySelector target used by the script must correspond to an element id that already exists in the HTML markup."
                .to_string(),
        );
        directives.push(
            "- Remove dead selector references instead of pointing interaction handlers at future or nonexistent targets."
                .to_string(),
        );
    }
    if failure_lower.contains("rollover") || failure_lower.contains("tooltip") {
        directives.push(
            "- Add mouseenter, mouseover, focus, or pointerenter handlers on visible marks or cards so rollover detail updates a shared explanation region inline."
                .to_string(),
        );
        directives.push(
            "- Keep the hovered or focused detail region populated on first paint, then rewrite it when the user hovers or focuses a specific chart mark."
                .to_string(),
        );
    }
    if failure_lower.contains("scroll")
        || failure_lower.contains("jump")
        || failure_lower.contains("log")
    {
        directives.push(
            "- Replace scrollIntoView, console-only, or jump-only controls with handlers that update shared detail, comparison, explanation, or chart state inline."
                .to_string(),
        );
        directives.push(
            "- At least one control should rewrite visible on-page copy, labels, chart state, or comparison content rather than only moving the viewport."
                .to_string(),
        );
        directives.push(
            "- If the brief needs sequence browsing or timeline traversal, add a visible progression control such as previous/next buttons, a scrubber, stepper, or scroll-snap rail instead of relying on a static timeline illustration."
                .to_string(),
        );
    }

    directives.join("\n")
}

pub(super) fn chat_artifact_candidate_refinement_directives(
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    validation: &ChatArtifactValidationResult,
) -> String {
    let mut directives = vec![
        "- Patch the current artifact instead of restarting from a new shell.".to_string(),
        "- Preserve working file paths and any strong request-specific copy, labels, and structure already present.".to_string(),
    ];
    let modal_first_html =
        request.renderer == ChatRendererKind::HtmlIframe && chat_modal_first_html_enabled();
    let exact_view_scaffold = html_prompt_exact_view_scaffold(brief);
    let rollover_mark_example = html_prompt_rollover_mark_example(brief);

    if request.renderer == ChatRendererKind::HtmlIframe {
        directives.push(
            "- Keep at least three populated sectioning regions on first paint. Empty wrappers do not count as artifact structure."
                .to_string(),
        );
        directives.push(
            "- Ensure each sectioning region carries its own visible heading plus content, scorecards, labels, chart marks, or explanatory copy on first paint; a section that only mounts future script output is still empty."
                .to_string(),
        );
        if modal_first_html {
            directives.push(
                "- Preserve or strengthen the artifact's chosen interaction grammar instead of forcing a dashboard shell; tabs, sceneboards, steppers, inline simulators, inspectable diagrams, annotated cards, and other truthful patterns are all valid."
                    .to_string(),
            );
            directives.push(
                "- Keep the primary interaction on-page: controls or marks should change inline evidence, simulation state, comparison state, callouts, or explanatory copy. A detached shared-detail panel is optional, not required."
                    .to_string(),
            );
        } else {
            directives.push(
                "- Use a named control bar plus a shared detail or comparison panel; anchor-only navigation is not enough for the primary interaction model."
                    .to_string(),
            );
        }
        directives.push(
            "- Keep the hero request-specific instead of repeating the thesis verbatim, and surface differentiating concepts across section headings and evidence labels."
                .to_string(),
        );
        directives.push(
            "- Replace scrollIntoView, jump-link, or console-only handlers with controls that rewrite visible detail, comparison, or chart state in place."
                .to_string(),
        );
        if modal_first_html {
            directives.push(
                "- Do not regress into anchor-only jumps, generic app chrome, or a left-nav shell; the primary interaction should keep the page feeling authored and request-specific."
                    .to_string(),
            );
        } else {
            directives.push(
                "- Do not regress into anchor-only section jumps or top-nav shells; the primary controls must change inline evidence or detail state."
                    .to_string(),
            );
        }
        directives.push(
            "- Keep the default selected chart, label, and detail state directly in the markup before any script runs; do not bootstrap the only visible content from empty targets."
                .to_string(),
        );
        directives.push(
            "- Avoid DOMContentLoaded, innerHTML, appendChild, or createElement as the only source of first-paint chart/detail content. Use them only to update already-rendered regions."
                .to_string(),
        );
        directives.push(
            "- Keep scripts comment-free and production-ready; do not leave placeholder comments or dead DOM references in the surfaced artifact."
                .to_string(),
        );
    }

    if validation.request_faithfulness <= 3 || validation.concept_coverage <= 3 {
        directives.push(
            "- Surface the requiredConcepts in visible headings, labels, legends, captions, or explanatory copy, not only in the title."
                .to_string(),
        );
    }

    if request.renderer == ChatRendererKind::HtmlIframe && brief.has_required_interaction_goals() {
        directives.push(
            "- Realize requiredInteractions with visible controls that update on-page state, reveal deeper detail, filter views, or compare scenarios."
                .to_string(),
        );
        if brief_requires_sequence_browsing(brief) {
            directives.push(
                "- When a requiredInteraction implies sequence browsing, timeline traversal, or scrolling through staged evidence, expose a visible progression mechanism such as previous/next controls, a scrubber, a stepper, or a scrollable evidence rail. A static chart plus unrelated panel toggles does not satisfy sequence browsing."
                    .to_string(),
            );
        }
        if modal_first_html {
            directives.push(
                "- Prefer controls that update labeled inline evidence, comparison state, captions, callouts, or contextual explanation instead of acting like navigation-only buttons."
                    .to_string(),
            );
        } else {
            directives.push(
                "- Prefer controls that update a shared detail, comparison, or explanation region instead of navigation-only buttons."
                    .to_string(),
            );
        }
        directives.push(
            "- Give the default selected control a fully populated response region on first paint before any user action."
                .to_string(),
        );
        directives.push(
            "- Keep at least one secondary evidence view, comparison card, or preview visible on first paint so the artifact reads as multi-view rather than a single chart with generic prose."
                .to_string(),
        );
        directives.push(
            "- Prefer pre-rendered evidence sections, comparison cards, or detail blocks already present in the DOM; controls should toggle or annotate them instead of rebuilding the only evidence view with innerHTML."
                .to_string(),
        );
        directives.push(
            "- Do not count a one-line paragraph as a secondary evidence view; use structured evidence such as comparison bullets, a score table, a metric-card rail, or a second SVG with labeled marks."
                .to_string(),
        );
        if let Some(primary_anchor) = brief
            .factual_anchors
            .iter()
            .map(|item| item.trim())
            .find(|item| !item.is_empty())
        {
            directives.push(format!(
                "- Dedicate one named first-paint evidence surface directly to this factual anchor: {primary_anchor}. Make it visible through labels, marks, timeline items, metric cards, annotations, or comparison rows rather than generic overview copy."
            ));
        }
        if let Some(secondary_anchor) = brief
            .factual_anchors
            .iter()
            .skip(1)
            .map(|item| item.trim())
            .find(|item| !item.is_empty())
        {
            directives.push(format!(
                "- Dedicate a second named evidence surface, comparison rail, or preview directly to this factual anchor: {secondary_anchor}. Keep it visible on first paint instead of burying it inside one generic shared summary."
            ));
        }
        if brief.required_interaction_goal_count() >= 2 {
            if modal_first_html {
                directives.push(
                    "- Spread multiple interaction requirements across the artifact: keep one explicit authored state-change seam and at least one in-evidence inspection, hover/focus, or input behavior on visible marks, cards, chips, form fields, or list items."
                        .to_string(),
                );
                directives.push(
                    "- Do not satisfy a multi-interaction brief with only one button row and one thin state swap; let interactions change more than one visible region or explanatory surface."
                        .to_string(),
                );
            } else {
                directives.push(
                    "- Spread multiple interaction requirements across the artifact: keep one explicit control-bar behavior and at least one in-evidence inspection or input behavior on visible marks, cards, chips, form fields, or list items."
                        .to_string(),
                );
                directives.push(
                    "- Do not satisfy a multi-interaction brief with only one button row and a single shared panel toggle."
                        .to_string(),
                );
            }
        }
        if brief_requires_view_switching(brief) {
            if modal_first_html {
                directives.push(
                    "- For clickable navigation, keep at least two authored states, scenes, or sections in the markup and make the switch visibly change the page. Mapped panels are allowed, not mandatory."
                        .to_string(),
                );
                directives.push(
                    "- If you do use mapped panels, use explicit identifiers such as data-view plus data-view-panel or aria-controls tied to real authored states rather than synthesized selector math."
                        .to_string(),
                );
                directives.push(
                    "- Keep one authored state clearly active on first paint and make each click reveal a visibly different evidence or explanation state, not just a relabeled pill."
                        .to_string(),
                );
            } else {
                directives.push(
                    "- For clickable navigation, use explicit static control-to-panel mappings such as data-view plus data-view-panel, aria-controls, or data-target tied to pre-rendered views."
                        .to_string(),
                );
                directives.push(
                    "- Keep data-view-panel as a literal HTML attribute on each panel element; a CSS class like class=\"data-view-panel\" does not count as a mapped pre-rendered panel."
                        .to_string(),
                );
                directives.push(
                    "- Keep at least two pre-rendered view panels in the markup and toggle hidden, data-active, or aria-selected state instead of deriving target ids from button ids at runtime."
                        .to_string(),
                );
                directives.push(
                    "- If you need Array methods such as find, map, or filter on queried controls or panels, wrap querySelectorAll results with Array.from first."
                        .to_string(),
                );
                directives.push(
                    "- Static data-view, aria-controls, or data-target attributes do not count on their own; wire click handlers that actually toggle panel visibility or selected state on the mapped panel wrappers."
                        .to_string(),
                );
                directives.push(
                    "- Do not use class names like class=\"overview-panel\" or class=\"data-view-panel\" as a substitute for actual id/data-view-panel attributes on the panel wrapper."
                        .to_string(),
                );
                directives.push(
                    "- Use a concrete scaffold when needed: buttons[data-view], matching <section data-view-panel=\"...\"> containers for each view, one populated default panel, one shared detail aside such as #detail-copy, and a panels collection selected before toggling hidden state."
                        .to_string(),
                );
                directives.push(format!(
                    "- A safe exact scaffold is {}.",
                    exact_view_scaffold
                ));
                directives.push(
                    "- If you use aria-controls, target the enclosing section/article/div panel rather than an inner SVG node or chart mark."
                        .to_string(),
                );
                directives.push(
                    "- Keep exactly one mapped panel visible in the raw markup before any script runs; the remaining mapped panels may start hidden."
                        .to_string(),
                );
                directives.push(
                    "- Do not wire every control only to the shared detail panel; the shared detail panel is supplementary and does not replace the pre-rendered view panels."
                        .to_string(),
                );
            }
        }
        if brief_requires_rollover_detail(brief) {
            if modal_first_html {
                directives.push(
                    "- Implement at least one hover or focus interaction on a visible chart mark, metric card, or timeline item that rewrites inline captioning, a callout, a contextual note, or another authored response region."
                        .to_string(),
                );
            } else {
                directives.push(
                    "- Implement at least one hover or focus interaction on a visible chart mark, metric card, or timeline item that rewrites a shared detail panel inline."
                        .to_string(),
                );
            }
        }
        if brief_requires_view_switching(brief) && brief_requires_rollover_detail(brief) {
            if modal_first_html {
                directives.push(
                    "- Keep both interaction families simultaneously: preserve at least two authored view states for switching and at least three visible inspectable marks or cards whose hover/focus behavior changes a visible response region."
                        .to_string(),
                );
                directives.push(
                    "- Do not satisfy clickable navigation by deleting inspectable detail behavior, and do not satisfy inspection by collapsing the authored view changes."
                        .to_string(),
                );
                directives.push(format!(
                    "- A strong repair shape is a visible view-switching seam plus inspectable marks such as {}, with default explanatory state already visible on first paint.",
                    rollover_mark_example
                ));
            } else {
                directives.push(
                    "- Keep both interaction families simultaneously: use at least two pre-rendered view panels for button-driven switching and at least three visible data-detail marks or cards with hover/focus behavior that update the same shared detail panel."
                        .to_string(),
                );
                directives.push(
                    "- Do not satisfy clickable navigation by deleting rollover detail, and do not satisfy rollover detail by collapsing the pre-rendered view panels."
                        .to_string(),
                );
                directives.push(format!(
                    "- A strong repair shape is buttons[data-view] -> [data-view-panel] plus [data-detail] -> #detail-copy, with one populated default panel, default detail state already visible on first paint, and a visible rollover mark such as {}.",
                    rollover_mark_example
                ));
            }
        }
    }

    if validation.interaction_relevance <= 2 {
        directives.push(
            "- Strengthen interaction density with actual handlers and response regions; a single disclosure or dead control is not enough."
                .to_string(),
        );
        directives.push(
            "- Make click and hover/focus behaviors rewrite meaningful request-grounded detail copy, not only selection labels or view ids."
                .to_string(),
        );
    }

    if validation.layout_coherence <= 3 || validation.completeness <= 3 {
        directives.push(
            "- Increase first-paint completeness by filling each primary region with visible content, not placeholders or deferred shells."
                .to_string(),
        );
    }

    if validation.generic_shell_detected || validation.trivial_shell_detected {
        directives.push(
            "- Remove placeholder-grade filler and generic shell patterns; the artifact should only fit this request, not nearby prompts."
                .to_string(),
        );
        directives.push(
            "- Replace nav-shell behavior with a chart-plus-detail composition that is already useful on first paint."
                .to_string(),
        );
    }

    if let Some(contradiction) = validation.strongest_contradiction.as_ref() {
        let contradiction_lower = contradiction.to_ascii_lowercase();
        directives.push(format!(
            "- Resolve this contradiction directly: {}",
            contradiction
        ));
        if contradiction_lower.contains("interactive elements")
            || contradiction_lower.contains("data visualizations")
            || contradiction_lower.contains("chart")
        {
            if modal_first_html {
                directives.push(
                    "- Add at least one inline SVG or DOM data visualization with visible marks, numeric labels, and a visible explanatory response region that updates inline."
                        .to_string(),
                );
            } else {
                directives.push(
                    "- Add at least one inline SVG or DOM data visualization with visible marks, numeric labels, and a shared detail panel that updates inline."
                        .to_string(),
                );
            }
            directives.push(
                "- Expand the first paint into at least two distinct evidence views or chart families tied to different brief concepts or reference hints; do not collapse everything into one generic chart."
                    .to_string(),
            );
            directives.push(
                "- Keep a secondary evidence view visible before interaction as a comparison card, preview panel, legend table, or supporting article."
                    .to_string(),
            );
            directives.push(
                "- Do not treat a bare sentence or overview paragraph as that secondary evidence view; populate it with multiple labeled rows, bullets, cards, or a second SVG."
                    .to_string(),
            );
            directives.push(
                "- Replace single-mark or unlabeled SVG shells with multiple request-grounded marks, rows, or milestone steps plus visible labels, captions, or legends on first paint."
                    .to_string(),
            );
            if modal_first_html {
                directives.push(
                    "- Update a visible explanatory response region with the selected metric, milestone, or evidence sentence from data-detail or control metadata; do not only echo the raw view id or button label."
                        .to_string(),
                );
            } else {
                directives.push(
                    "- Update the shared detail panel with the selected metric, milestone, or evidence sentence from data-detail or control metadata; do not only echo the raw view id or button label."
                        .to_string(),
                );
            }
        }
        if contradiction_lower.contains("navigation")
            || contradiction_lower.contains("pre-rendered views")
            || contradiction_lower.contains("view switching")
        {
            if modal_first_html {
                directives.push(
                    "- Replace implicit selector math with explicit authored states: controls should target real scenes, sections, or panels that already exist in the markup."
                        .to_string(),
                );
                directives.push(
                    "- If you use mapped panels, keep data-view-panel or aria-controls as literal attributes on the authored state wrappers and toggle visible state directly."
                        .to_string(),
                );
                directives.push(
                    "- Keep at least two authored view states in the DOM and make the click visibly change evidence or explanation rather than only switching a label."
                        .to_string(),
                );
            } else {
                directives.push(
                    "- Replace implicit selector math with explicit static mappings: controls should use data-view, aria-controls, or data-target values that point at pre-rendered panels already present in the markup."
                        .to_string(),
                );
                directives.push(
                    "- Keep data-view-panel as a literal HTML attribute on the panel element itself; a class token like class=\"data-view-panel\" does not satisfy the mapping."
                        .to_string(),
                );
                directives.push(
                    "- Prefer dataset comparisons such as panel.dataset.viewPanel !== button.dataset.view instead of building a querySelector string with nested quotes."
                        .to_string(),
                );
                directives.push(
                    "- If you need Array methods such as find, map, or filter on queried controls or panels, wrap querySelectorAll results with Array.from first."
                        .to_string(),
                );
                directives.push(
                    "- Keep at least two pre-rendered view panels in the DOM and toggle hidden or data-active state instead of calling getElementById on a synthesized id string."
                        .to_string(),
                );
                directives.push(
                    "- Static data-view, aria-controls, or data-target attributes alone are not enough; the click handler must mutate hidden, aria-selected, aria-hidden, or comparable panel state on the mapped panels."
                        .to_string(),
                );
                directives.push(
                    "- Do not substitute class=\"overview-panel\" or class=\"data-view-panel\" for the literal id/data-view-panel mapping on the panel wrapper."
                        .to_string(),
                );
                directives.push(
                    "- Point aria-controls at the panel wrapper itself, not the inner SVG or chart node, and keep one mapped panel visibly selected before any script runs."
                        .to_string(),
                );
            }
        }
        if contradiction_lower.contains("rollover")
            || contradiction_lower.contains("hover")
            || contradiction_lower.contains("tooltip")
        {
            if modal_first_html {
                directives.push(
                    "- Implement hover or focus behavior on visible marks or metric cards so an authored inline response region updates when the user points at or focuses a chart element."
                        .to_string(),
                );
            } else {
                directives.push(
                    "- Implement hover or focus behavior on visible marks or metric cards so a shared detail panel updates inline when the user points at or focuses a chart element."
                        .to_string(),
                );
            }
        }
        if contradiction_lower.contains("missing dom ids") {
            directives.push(
                "- Keep every scripted selector aligned with real ids in the markup; if a view does not exist on first paint, do not reference it."
                    .to_string(),
            );
        }
        if contradiction_lower.contains("placeholder") {
            directives.push(
                "- Remove placeholder comments and replace empty SVGs or shells with labeled first-paint marks and explanatory detail."
                    .to_string(),
            );
        }
        if contradiction_lower.contains("detail") || contradiction_lower.contains("comparison") {
            if modal_first_html {
                directives.push(
                    "- Keep the chosen detail, comparison, or explanatory response region populated with default copy on first paint, then update that same region inline."
                        .to_string(),
                );
            } else {
                directives.push(
                    "- Keep the shared detail or comparison panel populated with default explanatory copy on first paint, then update that same region inline."
                        .to_string(),
                );
            }
        }
    }

    directives.join("\n")
}

pub(super) fn count_html_sectioning_elements(html_lower: &str) -> usize {
    ["<section", "<article", "<nav", "<aside", "<footer"]
        .iter()
        .map(|needle| html_lower.matches(needle).count())
        .sum()
}

pub(super) fn strip_html_tags(fragment: &str) -> String {
    let mut plain = String::with_capacity(fragment.len());
    let mut in_tag = false;
    for ch in fragment.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => plain.push(ch),
            _ => {}
        }
    }
    plain
}
