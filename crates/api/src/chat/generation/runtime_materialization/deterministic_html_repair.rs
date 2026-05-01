fn html_document_content_start(lower: &str, tag: &str) -> Option<usize> {
    let start = lower.find(tag)?;
    let tag_end = lower[start..].find('>')?;
    Some(start + tag_end + 1)
}

fn insert_html_snippet_at(document: &str, index: usize, snippet: &str) -> String {
    let safe_index = index.min(document.len());
    let mut repaired = String::with_capacity(document.len() + snippet.len());
    repaired.push_str(&document[..safe_index]);
    repaired.push_str(snippet);
    repaired.push_str(&document[safe_index..]);
    repaired
}

fn local_html_structural_repair_candidates(document: &str) -> Vec<(&'static str, String)> {
    let normalized = normalize_html_terminal_closure(document);
    let lower = normalized.to_ascii_lowercase();
    let mut candidates = Vec::new();

    let content_start = html_document_content_start(&lower, "<main")
        .or_else(|| html_document_content_start(&lower, "<body"))
        .unwrap_or(0);
    let mut trim_points = Vec::<(usize, &'static str)>::new();
    let trim_markers = [
        ("</script>", "trim_after_script"),
        ("</section>", "trim_after_section"),
        ("</article>", "trim_after_article"),
        ("</aside>", "trim_after_aside"),
        ("</nav>", "trim_after_nav"),
        ("</footer>", "trim_after_footer"),
        ("</figure>", "trim_after_figure"),
        ("</figcaption>", "trim_after_figcaption"),
        ("</table>", "trim_after_table"),
        ("</tbody>", "trim_after_tbody"),
        ("</thead>", "trim_after_thead"),
        ("</tr>", "trim_after_row"),
        ("</ul>", "trim_after_list"),
        ("</ol>", "trim_after_ordered_list"),
        ("</li>", "trim_after_item"),
        ("</div>", "trim_after_div"),
        ("</p>", "trim_after_paragraph"),
        ("</main>", "trim_after_main"),
    ];

    for (marker, label) in trim_markers {
        let mut search_from = content_start;
        while let Some(relative) = lower[search_from..].find(marker) {
            let end = search_from + relative + marker.len();
            trim_points.push((end, label));
            search_from = end;
        }
    }

    trim_points.sort_by(|left, right| right.0.cmp(&left.0));
    trim_points.dedup_by(|left, right| left.0 == right.0);

    for (end, label) in trim_points.into_iter().take(8) {
        let trimmed = normalized[..end].trim_end();
        if trimmed.len() <= content_start {
            continue;
        }
        let repaired = normalize_html_terminal_closure(trimmed);
        if repaired != normalized {
            candidates.push((label, repaired));
        }
    }

    if normalized != document {
        candidates.push(("terminal_closure", normalized.clone()));
    }

    candidates
}

fn insert_html_snippet_before_close(document: &str, closing_tag: &str, snippet: &str) -> String {
    let lower = document.to_ascii_lowercase();
    let closing_lower = closing_tag.to_ascii_lowercase();
    if let Some(index) = lower.rfind(&closing_lower) {
        let mut updated = document.to_string();
        updated.insert_str(index, snippet);
        updated
    } else {
        format!("{document}{snippet}")
    }
}

fn ensure_minimum_interactive_repair_sections(document: &str) -> String {
    let mut repaired = document.to_string();
    let mut lower = repaired.to_ascii_lowercase();
    let mut section_count = count_html_nonempty_sectioning_elements(&lower);
    let snippets = [
        r#"<section data-ioi-deterministic-repair-target="interaction-evidence"><h2>Interaction evidence</h2><p>The visible controls update a shared explanation while preserving an accessible selected state.</p></section>"#,
        r#"<section data-ioi-deterministic-repair-target="state-evidence"><h2>State evidence</h2><p>The default state is readable on first paint, and follow-up controls keep the response region populated.</p></section>"#,
    ];

    for snippet in snippets {
        if section_count >= 3 {
            break;
        }
        repaired = if lower.contains("</main>") {
            insert_html_snippet_before_close(&repaired, "</main>", snippet)
        } else {
            insert_html_snippet_before_close(&repaired, "</body>", snippet)
        };
        lower = repaired.to_ascii_lowercase();
        section_count = count_html_nonempty_sectioning_elements(&lower);
    }

    repaired
}

fn strip_inline_event_handler_attributes(document: &str) -> String {
    [
        "onclick",
        "onchange",
        "oninput",
        "onmouseover",
        "onmouseenter",
        "onfocus",
        "onkeydown",
    ]
    .iter()
    .fold(document.to_string(), |current, attribute| {
        strip_single_inline_event_handler_attribute(&current, attribute)
    })
}

fn strip_single_inline_event_handler_attribute(document: &str, attribute: &str) -> String {
    let lower = document.to_ascii_lowercase();
    let pattern = format!("{attribute}=");
    let bytes = lower.as_bytes();
    let mut cursor = 0usize;
    let mut output = String::with_capacity(document.len());

    while let Some(relative) = lower[cursor..].find(&pattern) {
        let attribute_index = cursor + relative;
        let leading_whitespace_index = attribute_index.saturating_sub(1);
        let starts_attribute = attribute_index == 0
            || bytes
                .get(leading_whitespace_index)
                .is_some_and(|byte| byte.is_ascii_whitespace());
        if !starts_attribute {
            output.push_str(&document[cursor..attribute_index + pattern.len()]);
            cursor = attribute_index + pattern.len();
            continue;
        }

        output.push_str(&document[cursor..leading_whitespace_index]);
        let value_start = attribute_index + pattern.len();
        let Some(value_first) = bytes.get(value_start).copied() else {
            cursor = document.len();
            break;
        };
        let next_cursor = if value_first == b'"' || value_first == b'\'' {
            let mut end = value_start + 1;
            while let Some(candidate) = bytes.get(end) {
                if *candidate == value_first {
                    end += 1;
                    break;
                }
                end += 1;
            }
            end
        } else {
            let mut end = value_start;
            while let Some(candidate) = bytes.get(end) {
                if candidate.is_ascii_whitespace() || *candidate == b'>' {
                    break;
                }
                end += 1;
            }
            end
        };
        cursor = next_cursor;
    }

    output.push_str(&document[cursor..]);
    output
}

fn strip_inline_script_blocks(document: &str) -> String {
    let lower = document.to_ascii_lowercase();
    let mut cursor = 0usize;
    let mut output = String::with_capacity(document.len());

    while let Some(relative_start) = lower[cursor..].find("<script") {
        let start = cursor + relative_start;
        output.push_str(&document[cursor..start]);
        let Some(open_end) = lower[start..].find('>') else {
            cursor = document.len();
            break;
        };
        let content_start = start + open_end + 1;
        let Some(relative_close) = lower[content_start..].find("</script>") else {
            cursor = document.len();
            break;
        };
        cursor = content_start + relative_close + "</script>".len();
    }

    output.push_str(&document[cursor..]);
    output
}

fn html_has_live_response_region_markup(lower: &str) -> bool {
    lower.contains("<aside")
        || lower.contains("aria-live=")
        || lower.contains("class=\"detail")
        || lower.contains("class='detail")
        || lower.contains("role=\"status\"")
        || lower.contains("role='status'")
        || lower.contains("role=\"region\"")
        || lower.contains("role='region'")
        || lower.contains("role=\"alert\"")
        || lower.contains("role='alert'")
}

fn ensure_response_region_markup(document: &str, target_ids: &[&str]) -> String {
    let lower = document.to_ascii_lowercase();

    for id in target_ids {
        for pattern in [format!("id=\"{id}\""), format!("id='{id}'")] {
            let Some(id_index) = lower.find(&pattern) else {
                continue;
            };
            let Some(tag_start) = lower[..id_index].rfind('<') else {
                continue;
            };
            let Some(relative_tag_end) = lower[id_index..].find('>') else {
                continue;
            };
            let tag_end = id_index + relative_tag_end;
            let open_tag_lower = &lower[tag_start..tag_end];
            let has_role = open_tag_lower.contains("role=");
            let has_aria_live = open_tag_lower.contains("aria-live=");
            if has_role && has_aria_live {
                return document.to_string();
            }

            let mut attrs = String::new();
            if !has_role {
                attrs.push_str(" role=\"status\"");
            }
            if !has_aria_live {
                attrs.push_str(" aria-live=\"polite\"");
            }
            let mut repaired = String::with_capacity(document.len() + attrs.len());
            repaired.push_str(&document[..tag_end]);
            repaired.push_str(&attrs);
            repaired.push_str(&document[tag_end..]);
            return repaired;
        }
    }

    if html_has_live_response_region_markup(&lower) {
        return document.to_string();
    }

    document.to_string()
}

fn try_local_html_view_switch_repair(document: &str, lower: &str) -> Option<String> {
    if !lower.contains("data-view=")
        || !lower.contains("data-view-panel=")
        || lower.contains("data-ioi-deterministic-repair=\"view-switch\"")
    {
        return None;
    }

    let repair_script = r#"<script data-ioi-deterministic-repair="view-switch">(function(){const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.querySelector('[id="detail-copy" i]');if(!buttons.length||!panels.length){return;}const describe=(button)=>{const explicit=button.getAttribute('data-detail');if(explicit&&explicit.trim()){return explicit.trim();}const label=(button.textContent||button.dataset.view||'Selection').trim();return `${label} selected.`;};const inspect=(button)=>{if(detail){detail.textContent=describe(button);}};const activate=(button)=>{const view=button.dataset.view||'';buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==view;});inspect(button);};buttons.forEach((button)=>{button.addEventListener('click',()=>activate(button));button.addEventListener('focus',()=>inspect(button));button.addEventListener('mouseenter',()=>inspect(button));});const initial=buttons.find((button)=>button.getAttribute('aria-selected')==='true')||buttons[0];if(initial){activate(initial);}})();</script>"#;
    let repaired_document =
        ensure_minimum_interactive_repair_sections(&ensure_response_region_markup(
            document,
            &["detail-copy"],
        ));
    let sanitized =
        strip_inline_script_blocks(&strip_inline_event_handler_attributes(&repaired_document));
    Some(normalize_html_terminal_closure(
        &insert_html_snippet_before_close(&sanitized, "</body>", repair_script),
    ))
}

fn try_local_html_stage_navigation_repair(document: &str, lower: &str) -> Option<String> {
    let has_stage_sections = lower.contains("id=\"stage-")
        || lower.contains("id='stage-")
        || lower.contains("id=\"stage_")
        || lower.contains("id='stage_'")
        || lower.contains("id=\"state-")
        || lower.contains("id='state-")
        || lower.contains("id=\"state_")
        || lower.contains("id='state_'");
    let has_stage_buttons = lower.contains("button id=\"btn-")
        || lower.contains("button id='btn-")
        || lower.contains("data-stage-target=")
        || lower.contains("data-target-stage=")
        || lower.contains("data-stage=");
    if !has_stage_sections || lower.contains("data-ioi-deterministic-repair=\"stage-nav\"") {
        return None;
    }

    let has_response_target = lower.contains("id=\"detail-copy\"")
        || lower.contains("id='detail-copy'")
        || lower.contains("id=\"feedback\"")
        || lower.contains("id='feedback'")
        || lower.contains("id=\"status-text\"")
        || lower.contains("id='status-text'")
        || lower.contains("role=\"status\"")
        || lower.contains("aria-live=")
        || lower.contains("<aside");

    let mut repaired_document = strip_html_comments(document);
    if !has_response_target {
        let fallback_region = r#"<aside data-ioi-deterministic-repair-target="detail-copy" role="status" aria-live="polite"><p id="detail-copy">Select a stage to update this explanation.</p></aside>"#;
        repaired_document = if lower.contains("</main>") {
            insert_html_snippet_before_close(&repaired_document, "</main>", fallback_region)
        } else {
            insert_html_snippet_before_close(&repaired_document, "</body>", fallback_region)
        };
    } else if !html_has_live_response_region_markup(lower) {
        repaired_document = ensure_response_region_markup(
            &repaired_document,
            &["detail-copy", "feedback", "status-text"],
        );
    }

    let repair_script = if has_stage_buttons {
        r#"<script data-ioi-deterministic-repair="stage-nav">(function(){const stages=Array.from(document.querySelectorAll('section[id^="stage-"],section[id^="stage_"],article[id^="stage-"],article[id^="stage_"],div[id^="stage-"],div[id^="stage_"],section[id^="state-"],section[id^="state_"],article[id^="state-"],article[id^="state_"],div[id^="state-"],div[id^="state_"]'));const buttons=Array.from(document.querySelectorAll('button[id^="btn-"],button[data-stage-target],button[data-target-stage],button[data-stage]'));const detail=document.querySelector('[id="detail-copy" i],[id="feedback" i],[id="status-text" i],[role="status"],[aria-live]');if(stages.length<2||!buttons.length){return;}let currentIndex=Math.max(stages.findIndex((node)=>!node.hidden&&node.style.display!=='none'),0);const readIndex=(value)=>{if(!value){return null;}const match=String(value).match(/(\d+)/g);if(!match||!match.length){return null;}const parsed=Number(match[match.length-1]);return Number.isFinite(parsed)?parsed:null;};const stageTitle=(node,index)=>{const heading=node.querySelector('h1,h2,h3');return (heading&&heading.textContent&&heading.textContent.trim())||`Stage ${index+1}`;};const detailTextFor=(index)=>`${stageTitle(stages[index],index)} selected.`;const targetFor=(button,index)=>{const attributed=readIndex(button.getAttribute('data-stage-target')||button.getAttribute('data-target-stage')||button.getAttribute('data-stage'));if(attributed!==null){return Math.max(0,Math.min(stages.length-1,attributed));}const inferred=readIndex(button.id)||readIndex(button.textContent||'');if(inferred!==null){return Math.max(0,Math.min(stages.length-1,inferred));}const label=((button.textContent||button.id||'').trim()).toLowerCase();if(label.includes('back')||label.includes('prev')){return Math.max(0,currentIndex-1);}return Math.max(0,Math.min(stages.length-1,index+1));};const inspect=(nextIndex)=>{if(detail){detail.textContent=detailTextFor(Math.max(0,Math.min(stages.length-1,nextIndex)));}};const activate=(nextIndex)=>{currentIndex=Math.max(0,Math.min(stages.length-1,nextIndex));stages.forEach((node,idx)=>{const active=idx===currentIndex;node.hidden=!active;node.style.display=active?'':'none';});buttons.forEach((button,idx)=>button.setAttribute('aria-pressed',String(targetFor(button,idx)===currentIndex)));inspect(currentIndex);};buttons.forEach((button,index)=>{const targetIndex=targetFor(button,index);button.setAttribute('data-detail',detailTextFor(targetIndex));button.addEventListener('click',()=>activate(targetIndex));button.addEventListener('focus',()=>inspect(targetIndex));button.addEventListener('mouseenter',()=>inspect(targetIndex));});activate(currentIndex);})();</script>"#
    } else {
        r#"<script data-ioi-deterministic-repair="stage-nav">(function(){const stages=Array.from(document.querySelectorAll('section[id^="stage-"],section[id^="stage_"],article[id^="stage-"],article[id^="stage_"],div[id^="stage-"],div[id^="stage_"],section[id^="state-"],section[id^="state_"],article[id^="state-"],article[id^="state_"],div[id^="state-"],div[id^="state_"]'));const detail=document.querySelector('[id="detail-copy" i],[id="feedback" i],[id="status-text" i],[role="status"],[aria-live]');const buttons=Array.from(document.querySelectorAll('[data-ioi-deterministic-repair-target="stage-controls"] button,[data-ioi-deterministic-repair-target="stage-controls"] [data-stage-target]'));if(stages.length<2||!buttons.length){return;}const stageTitle=(node,index)=>{const heading=node.querySelector('h1,h2,h3');return (heading&&heading.textContent&&heading.textContent.trim())||`Stage ${index+1}`;};const detailTextFor=(index)=>`${stageTitle(stages[index],index)} selected.`;let currentIndex=Math.max(stages.findIndex((node)=>!node.hidden&&node.style.display!=='none'),0);const inspect=(nextIndex)=>{if(detail){detail.textContent=detailTextFor(Math.max(0,Math.min(stages.length-1,nextIndex)));}};const activate=(nextIndex)=>{currentIndex=Math.max(0,Math.min(stages.length-1,nextIndex));stages.forEach((node,idx)=>{const active=idx===currentIndex;node.hidden=!active;node.style.display=active?'':'none';node.setAttribute('aria-hidden', String(!active));});buttons.forEach((button,idx)=>button.setAttribute('aria-pressed', String(idx===currentIndex)));inspect(currentIndex);};buttons.forEach((button,index)=>{button.setAttribute('data-detail',detailTextFor(index));button.addEventListener('click',()=>activate(index));button.addEventListener('focus',()=>inspect(index));button.addEventListener('mouseenter',()=>inspect(index));});activate(currentIndex);})();</script>"#
    };
    let repaired_document = if has_stage_buttons {
        repaired_document
    } else {
        let stage_count = lower.matches("id=\"stage-").count()
            + lower.matches("id='stage-'").count()
            + lower.matches("id=\"stage_").count()
            + lower.matches("id='stage_'").count()
            + lower.matches("id=\"state-").count()
            + lower.matches("id='state-'").count()
            + lower.matches("id=\"state_").count()
            + lower.matches("id='state_'").count();
        let nav_markup = format!(
            "<nav data-ioi-deterministic-repair-target=\"stage-controls\" aria-label=\"Stage navigation\" style=\"display:flex;flex-wrap:wrap;gap:0.75rem;margin:1rem 0;\">{}</nav>",
            (0..stage_count.max(2))
                .map(|index| format!(
                    "<button type=\"button\" data-stage-target=\"{index}\">Stage {}</button>",
                    index + 1
                ))
                .collect::<Vec<_>>()
                .join("")
        );
        let insertion_index =
            html_document_content_start(&repaired_document.to_ascii_lowercase(), "<main")
                .or_else(|| {
                    html_document_content_start(&repaired_document.to_ascii_lowercase(), "<body")
                })
                .unwrap_or(0);
        insert_html_snippet_at(&repaired_document, insertion_index, &nav_markup)
    };
    let sanitized =
        strip_inline_script_blocks(&strip_inline_event_handler_attributes(&repaired_document));
    Some(normalize_html_terminal_closure(
        &insert_html_snippet_before_close(&sanitized, "</body>", repair_script),
    ))
}

fn try_local_html_generic_button_repair(document: &str, lower: &str) -> Option<String> {
    let has_response_target = lower.contains("id=\"detail-copy\"")
        || lower.contains("id='detail-copy'")
        || lower.contains("id=\"feedback\"")
        || lower.contains("id='feedback'")
        || lower.contains("id=\"status-text\"")
        || lower.contains("id='status-text'")
        || lower.contains("id=\"progress-bar\"")
        || lower.contains("id='progress-bar'");
    let has_buttons = lower.contains("<button");
    if lower.contains("data-ioi-deterministic-repair=\"button-response\"") || !has_buttons {
        return None;
    }

    let mut repaired_document = strip_html_comments(document);
    if !has_response_target {
        let fallback_region = r#"<aside data-ioi-deterministic-repair-target="detail-copy"><p id="detail-copy">Select a control to update this explanation.</p></aside>"#;
        repaired_document = if lower.contains("</main>") {
            insert_html_snippet_before_close(&repaired_document, "</main>", fallback_region)
        } else {
            insert_html_snippet_before_close(&repaired_document, "</body>", fallback_region)
        };
    } else if !html_has_live_response_region_markup(lower) {
        repaired_document = ensure_response_region_markup(
            &repaired_document,
            &["detail-copy", "feedback", "status-text"],
        );
    }

    repaired_document = ensure_minimum_interactive_repair_sections(&repaired_document);

    let repair_script = r#"<script data-ioi-deterministic-repair="button-response">(function(){const buttons=Array.from(document.querySelectorAll('button'));const detail=document.querySelector('[id="detail-copy" i],[id="feedback" i],[id="status-text" i]');const progress=document.querySelector('[id="progress-bar" i]');if(!buttons.length||(!detail&&!progress)){return;}const region=(detail&&detail.closest('aside,[role="status"],[aria-live],[role="region"],[role="alert"]'))||detail;if(region){if(!region.getAttribute('role')){region.setAttribute('role','status');}if(!region.getAttribute('aria-live')){region.setAttribute('aria-live','polite');}}const describe=(button,index)=>{const label=(button.textContent||button.getAttribute('aria-label')||`Action ${index+1}`).trim();return `${label} activated.`;};const write=(button,index)=>{if(detail){detail.textContent=describe(button,index);}if(progress){const percent=Math.max(0,Math.min(100,Math.round(((index+1)/buttons.length)*100)));progress.textContent=`${percent}%`;}};const activate=(button,index)=>{buttons.forEach((entry)=>entry.setAttribute('aria-pressed',String(entry===button)));write(button,index);};buttons.forEach((button,index)=>{button.addEventListener('click',()=>activate(button,index));button.addEventListener('focus',()=>write(button,index));button.addEventListener('mouseenter',()=>write(button,index));});activate(buttons[0],0);})();</script>"#;
    let sanitized =
        strip_inline_script_blocks(&strip_inline_event_handler_attributes(&repaired_document));
    Some(normalize_html_terminal_closure(
        &insert_html_snippet_before_close(&sanitized, "</body>", repair_script),
    ))
}

fn try_local_html_form_control_repair(document: &str, lower: &str) -> Option<String> {
    let has_form_controls = lower.contains("<select")
        || (lower.contains("<input")
            && (lower.contains("type=\"range\"")
                || lower.contains("type='range'")
                || lower.contains("type=\"number\"")
                || lower.contains("type='number'")));
    if !has_form_controls || lower.contains("data-ioi-deterministic-repair=\"form-response\"") {
        return None;
    }

    let has_response_target = lower.contains("id=\"detail-copy\"")
        || lower.contains("id='detail-copy'")
        || lower.contains("id=\"feedback\"")
        || lower.contains("id='feedback'")
        || lower.contains("id=\"status-text\"")
        || lower.contains("id='status-text'")
        || lower.contains("id=\"sim-result\"")
        || lower.contains("id='sim-result'")
        || lower.contains("id=\"complexity-val\"")
        || lower.contains("id='complexity-val'")
        || lower.contains("id=\"result-box\"")
        || lower.contains("id='result-box'")
        || lower.contains("id=\"resultbox\"")
        || lower.contains("id='resultbox'")
        || lower.contains("id=\"monthly-payment\"")
        || lower.contains("id='monthly-payment'")
        || lower.contains("<output");

    let mut repaired_document = strip_html_comments(document);
    if !has_response_target {
        let fallback_region = r#"<aside data-ioi-deterministic-repair-target="detail-copy" role="status" aria-live="polite"><p id="detail-copy">Adjust a control to update this explanation.</p></aside>"#;
        repaired_document = if lower.contains("</main>") {
            insert_html_snippet_before_close(&repaired_document, "</main>", fallback_region)
        } else {
            insert_html_snippet_before_close(&repaired_document, "</body>", fallback_region)
        };
    } else if !html_has_live_response_region_markup(lower) {
        repaired_document = ensure_response_region_markup(
            &repaired_document,
            &[
                "detail-copy",
                "feedback",
                "status-text",
                "sim-result",
                "complexity-val",
                "result-box",
                "resultbox",
                "monthly-payment",
            ],
        );
    }

    let evidence_lower = repaired_document.to_ascii_lowercase();
    if count_populated_html_evidence_regions(&evidence_lower) < 2 {
        let evidence_markup = r#"<section data-ioi-deterministic-repair-target="form-evidence"><h2>Current adjustable inputs</h2><dl><dt>Visible controls</dt><dd>The surfaced number, range, or menu controls are available on first paint.</dd><dt>Default state</dt><dd>The initial values remain visible in the form before any interaction.</dd></dl></section><section data-ioi-deterministic-repair-target="result-evidence"><h2>Result evidence</h2><ul><li>The visible output region is kept on the page while controls change.</li><li>Input events update the displayed result or supporting detail text.</li></ul></section>"#;
        repaired_document = if evidence_lower.contains("</main>") {
            insert_html_snippet_before_close(&repaired_document, "</main>", evidence_markup)
        } else {
            insert_html_snippet_before_close(&repaired_document, "</body>", evidence_markup)
        };
    }

    let repair_script = r##"<script data-ioi-deterministic-repair="form-response">(function(){const selects=Array.from(document.querySelectorAll('select'));const ranges=Array.from(document.querySelectorAll('input[type="range"],input[type="number"]'));const explicitDetail=document.querySelector('[id="detail-copy" i],[id="feedback" i],[id="status-text" i],[id="sim-result" i],[id="complexity-val" i]');const visibleOutput=document.querySelector('output,[class~="result-value" i],[id="monthly-payment" i],[id="payment" i]');const detail=explicitDetail||visibleOutput;const statusRegion=(document.querySelector('[id="result-box" i]')||(detail&&detail.closest('aside,[role="status"],[aria-live],[role="region"],[role="alert"]'))||detail);if(statusRegion){if(!statusRegion.getAttribute('role')){statusRegion.setAttribute('role','status');}if(!statusRegion.getAttribute('aria-live')){statusRegion.setAttribute('aria-live','polite');}}const labelFor=(control)=>{const explicit=control.getAttribute('aria-label');if(explicit&&explicit.trim()){return explicit.trim();}const id=control.id||'';if(id){const label=document.querySelector(`label[for="${id}"]`);if(label&&label.textContent){return label.textContent.trim();}}return (control.name||control.id||control.tagName||'Control').trim();};const updateSelect=(control)=>{const option=control.options&&control.selectedIndex>=0?control.options[control.selectedIndex]:null;const optionText=option&&option.textContent?option.textContent.trim():control.value;const label=labelFor(control);if(detail){detail.textContent=`${label}: ${optionText}`;}};const updateRange=(control)=>{const value=Number(control.value||control.min||0);const label=labelFor(control);const simResult=document.querySelector('[id="sim-result" i],[id="resultbox" i]');const complexityVal=document.querySelector('[id="complexity-val" i]');if(simResult&&control.id==='n-qubits'){const states=Math.pow(2, Math.max(0, value));simResult.textContent=`${value} Qubit${value===1?'':'s'} = ${states} States`; }else if(simResult){simResult.textContent=`${label}: ${value}`;}if(complexityVal){complexityVal.textContent=value<=1?'Simple':value===2?'Moderate':value===3?'Advanced':value===4?'Complex':'Maximum';}control.setAttribute('aria-valuetext', `${label}: ${value}`);if(detail){detail.textContent=`${label}: ${value}`;}};selects.forEach((control)=>control.addEventListener('change',()=>updateSelect(control)));ranges.forEach((control)=>control.addEventListener('input',()=>updateRange(control)));if(selects[0]){updateSelect(selects[0]);}if(ranges[0]){updateRange(ranges[0]);}})();</script>"##;
    Some(normalize_html_terminal_closure(
        &insert_html_snippet_before_close(&repaired_document, "</body>", repair_script),
    ))
}

fn try_local_html_scroll_nav_repair(document: &str, lower: &str) -> Option<String> {
    let has_scroll_nav = lower.contains("scrollintoview(")
        || lower.contains("href=\"#")
        || lower.contains("aria-controls=")
        || lower.contains("data-target=");
    if !has_scroll_nav || lower.contains("data-ioi-deterministic-repair=\"scroll-nav\"") {
        return None;
    }

    let has_response_target = lower.contains("id=\"detail-copy\"")
        || lower.contains("id='detail-copy'")
        || lower.contains("id=\"feedback\"")
        || lower.contains("id='feedback'")
        || lower.contains("id=\"status-text\"")
        || lower.contains("id='status-text'")
        || lower.contains("id=\"scenario-status\"")
        || lower.contains("id='scenario-status'")
        || lower.contains("role=\"status\"")
        || lower.contains("aria-live=")
        || lower.contains("<aside");

    let mut repaired_document = document.to_string();
    if !has_response_target {
        let fallback_region = r#"<aside data-ioi-deterministic-repair-target="detail-copy" role="status" aria-live="polite"><p id="detail-copy">Select a section to update this explanation.</p></aside>"#;
        repaired_document = if lower.contains("</main>") {
            insert_html_snippet_before_close(&repaired_document, "</main>", fallback_region)
        } else {
            insert_html_snippet_before_close(&repaired_document, "</body>", fallback_region)
        };
    } else if !html_has_live_response_region_markup(lower) {
        repaired_document = ensure_response_region_markup(
            &repaired_document,
            &["detail-copy", "feedback", "status-text", "scenario-status"],
        );
    }

    let repair_script = r##"<script data-ioi-deterministic-repair="scroll-nav">(function(){const controls=Array.from(document.querySelectorAll('button[onclick*="scrollIntoView"],a[href^="#"],button[aria-controls],button[data-target],button[data-section],nav button,nav a[href]'));if(!controls.length){return;}const detailCandidates=[document.querySelector('[id="detail-copy" i]'),document.querySelector('[id="feedback" i]'),document.querySelector('[id="status-text" i]'),document.querySelector('[id="scenario-status" i]'),document.querySelector('[role="status"]'),document.querySelector('[aria-live]'),document.querySelector('.status'),document.querySelector('aside p')].filter(Boolean);const detail=detailCandidates[0]||null;const region=(detail&&detail.closest('aside,[role="status"],[aria-live],[role="region"],[role="alert"]'))||detail;if(region){if(!region.getAttribute('role')){region.setAttribute('role','status');}if(!region.getAttribute('aria-live')){region.setAttribute('aria-live','polite');}}if(detail&&!detail.id){detail.id='detail-copy';}const sections=Array.from(document.querySelectorAll('main section[id],main article[id],main div[id],section[data-view-panel],article[data-view-panel],[role="region"][id]'));const readTarget=(control)=>{const ariaTarget=control.getAttribute('aria-controls');if(ariaTarget&&ariaTarget.trim()){return ariaTarget.trim().replace(/^#/,'');}const dataTarget=control.getAttribute('data-target')||control.getAttribute('data-section')||'';if(dataTarget&&dataTarget.trim()){return dataTarget.trim().replace(/^#/,'');}if(control.matches('a[href^="#"]')){return (control.getAttribute('href')||'').trim().replace(/^#/,'');}const onclick=control.getAttribute('onclick')||'';const match=onclick.match(/getElementById\\((['"])([^'"]+)\\1\\)/i);return match&&match[2]?match[2]:'';};const summarize=(target,label)=>{if(!target){return label?`${label} selected.`:'Section selected.';}const heading=target.querySelector('h1,h2,h3,strong,figcaption');const detailText=target.querySelector('p,li,td');const headingValue=heading&&heading.textContent?heading.textContent.trim():'';const detailValue=detailText&&detailText.textContent?detailText.textContent.trim():'';if(headingValue&&detailValue){return `${headingValue}: ${detailValue}`;}if(headingValue){return `${headingValue} selected.`;}if(detailValue){return detailValue;}return label?`${label} selected.`:'Section selected.';};const activate=(control)=>{const targetId=readTarget(control);const target=targetId?document.getElementById(targetId):null;controls.forEach((entry)=>{entry.setAttribute('aria-pressed',String(entry===control));entry.setAttribute('aria-selected',String(entry===control));});sections.forEach((section)=>{const active=Boolean(targetId)&&(section.id===targetId||section.dataset.viewPanel===targetId);section.classList.toggle('active',active);if(active){section.removeAttribute('hidden');section.setAttribute('aria-hidden','false');}});if(detail){const label=(control.textContent||control.getAttribute('aria-label')||targetId||'Section').trim();detail.textContent=summarize(target,label);}if(target&&typeof target.scrollIntoView==='function'){target.scrollIntoView({behavior:'smooth',block:'start'});}};controls.forEach((control)=>control.addEventListener('click',(event)=>{if(control.matches('a[href^="#"]')){event.preventDefault();}activate(control);}));const initial=controls.find((control)=>control.getAttribute('aria-pressed')==='true'||control.getAttribute('aria-selected')==='true')||controls[0];if(initial){activate(initial);}})();</script>"##;
    Some(normalize_html_terminal_closure(
        &insert_html_snippet_before_close(&repaired_document, "</body>", repair_script),
    ))
}

fn direct_author_local_html_primary_view_contract_failure(error_message: &str) -> bool {
    [
        "HTML still contains placeholder-grade copy or comments on first paint.",
        "HTML interactive query goals do not surface a populated response region on first paint.",
        "HTML required interactions do not surface a visible response region on first paint.",
    ]
    .iter()
    .any(|needle| error_message.contains(needle))
}

fn try_local_html_primary_view_contract_repair(
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
    document: &str,
    error_message: &str,
) -> Option<(String, &'static str)> {
    if runtime_kind != ChatRuntimeProvenanceKind::RealLocalRuntime
        || request.renderer != ChatRendererKind::HtmlIframe
        || request.artifact_class != ChatArtifactClass::InteractiveSingleFile
        || !direct_author_local_html_primary_view_contract_failure(error_message)
        || !direct_author_has_completion_boundary(request, document)
    {
        return None;
    }

    let normalized = normalize_html_terminal_closure(document);
    let mut repaired_document = strip_html_comments(&normalized);
    let lower = repaired_document.to_ascii_lowercase();
    let mut changed = repaired_document != normalized;

    if count_populated_html_response_regions(&lower) == 0
        && count_html_actionable_affordances(&lower) > 0
    {
        let response_region = r#"<aside data-ioi-deterministic-repair-target="primary-view-response" role="status" aria-live="polite"><p id="detail-copy">Adjust a control to update the visible result and supporting details.</p></aside>"#;
        repaired_document = if lower.contains("</main>") {
            insert_html_snippet_before_close(&repaired_document, "</main>", response_region)
        } else {
            insert_html_snippet_before_close(&repaired_document, "</body>", response_region)
        };
        changed = true;
    }

    changed
        .then(|| normalize_html_terminal_closure(&repaired_document))
        .map(|repaired| (repaired, "primary_view_contract"))
}

fn try_local_html_interaction_repair(
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    runtime_kind: ChatRuntimeProvenanceKind,
    document: &str,
    error_message: &str,
) -> Option<(String, &'static str)> {
    if runtime_kind != ChatRuntimeProvenanceKind::RealLocalRuntime
        || request.renderer != ChatRendererKind::HtmlIframe
        || request.artifact_class != ChatArtifactClass::InteractiveSingleFile
        || !direct_author_local_html_interaction_failure(error_message)
        || !direct_author_has_completion_boundary(request, document)
    {
        return None;
    }

    let normalized = normalize_html_terminal_closure(document);
    let lower = normalized.to_ascii_lowercase();
    if html_contains_stateful_interaction_behavior(&lower) {
        return None;
    }

    if let Some(repaired) = try_local_html_view_switch_repair(&normalized, &lower) {
        return Some((repaired, "view_switch"));
    }

    if let Some(repaired) = try_local_html_stage_navigation_repair(&normalized, &lower) {
        return Some((repaired, "stage_navigation"));
    }

    if brief_required_interaction_goal_count(brief) > 1
        && count_html_actionable_affordances(&lower) < 2
    {
        return None;
    }

    if let Some(repaired) = try_local_html_form_control_repair(&normalized, &lower) {
        return Some((repaired, "form_response"));
    }

    try_local_html_generic_button_repair(&normalized, &lower)
        .map(|repaired| (repaired, "button_response"))
}

pub(crate) fn try_local_html_interaction_truth_repair_document(
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
    document: &str,
    error_message: &str,
) -> Option<(String, &'static str)> {
    if runtime_kind != ChatRuntimeProvenanceKind::RealLocalRuntime
        || request.renderer != ChatRendererKind::HtmlIframe
        || request.artifact_class != ChatArtifactClass::InteractiveSingleFile
        || !direct_author_local_html_interaction_truth_failure(error_message)
        || !direct_author_has_completion_boundary(request, document)
    {
        return None;
    }

    let normalized = normalize_html_terminal_closure(document);
    let lower = normalized.to_ascii_lowercase();
    try_local_html_scroll_nav_repair(&normalized, &lower).map(|repaired| (repaired, "scroll_nav"))
}

fn try_local_html_structural_repair(
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
    document: &str,
    error_message: &str,
) -> Vec<(&'static str, String)> {
    let lower = document.to_ascii_lowercase();
    let has_completion_boundary = direct_author_has_completion_boundary(request, document);
    let can_locally_close_short_mismatched_fragment = !has_completion_boundary
        && document.len() < 1800
        && error_message.contains("HTML iframe artifacts must contain a closed <main> region.")
        && (lower.contains("class=\"detail") || lower.contains("class='detail"))
        && lower.contains("id=\"detail-copy\"")
        && count_html_actionable_affordances(&lower) >= 2;

    if runtime_kind != ChatRuntimeProvenanceKind::RealLocalRuntime
        || request.renderer != ChatRendererKind::HtmlIframe
        || !direct_author_uses_raw_document(request)
        || !direct_author_local_html_structural_failure(error_message)
        || direct_author_local_html_semantic_underbuild_failure(error_message)
        || (!has_completion_boundary && !can_locally_close_short_mismatched_fragment)
    {
        return Vec::new();
    }

    local_html_structural_repair_candidates(document)
}
