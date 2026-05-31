use super::*;

pub(crate) const PROMPT_SECTION_KERNEL_POLICY_MAX_CHARS: usize = 1_200;
pub(crate) const PROMPT_SECTION_STATE_MAX_CHARS: usize = 1_600;
pub(crate) const PROMPT_SECTION_CORE_MEMORY_MAX_CHARS: usize = 1_400;
pub(crate) const PROMPT_SECTION_STRATEGY_MAX_CHARS: usize = 900;
pub(crate) const PROMPT_SECTION_TOOL_ROUTING_MAX_CHARS: usize = 1_800;
pub(crate) const PROMPT_SECTION_VERIFY_MAX_CHARS: usize = 500;
pub(crate) const PROMPT_SECTION_SCOPE_CONTRACT_MAX_CHARS: usize = 2_800;
pub(crate) const PROMPT_SECTION_AVAILABLE_TOOLS_MAX_CHARS: usize = 4_000;
pub(crate) const PROMPT_SECTION_BROWSER_CONTEXT_MAX_CHARS: usize = 2_400;
pub(crate) const PROMPT_SECTION_PENDING_BROWSER_STATE_MAX_CHARS: usize = 1_200;
pub(crate) const PROMPT_SECTION_SUCCESS_SIGNAL_MAX_CHARS: usize = 600;
pub(crate) const PROMPT_SECTION_PENDING_WEB_EVIDENCE_MAX_CHARS: usize = 3_200;
pub(crate) const PROMPT_SECTION_RECENT_EVENTS_MAX_CHARS: usize = 1_800;
pub(crate) const PROMPT_SECTION_COMMAND_HISTORY_MAX_CHARS: usize = 1_600;
pub(crate) const PROMPT_SECTION_WORKSPACE_CONTEXT_MAX_CHARS: usize = 1_200;
pub(crate) const PROMPT_SECTION_OPERATING_RULES_MAX_CHARS: usize = 3_200;
pub(crate) const PROMPT_SECTION_SPECIALIZED_INSTRUCTION_MAX_CHARS: usize = 1_200;
pub(crate) const FINAL_REPLY_MAX_TOKENS: u32 = 2_400;
pub(crate) const FINAL_REPLY_REPAIR_MAX_TOKENS: u32 = 3_200;
pub(crate) const FINAL_REPLY_REPAIR_ATTEMPTS: usize = 2;
pub(crate) const FINAL_REPLY_SOURCE_DOCUMENT_TIMEOUT_SECS: u64 = 240;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromptAssembly {
    pub(crate) system_instructions: String,
    pub(crate) report: PromptAssemblyReport,
    pub(crate) rendered_sections: Vec<RenderedPromptSection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromptAssemblyReport {
    pub(crate) sections: Vec<PromptSectionReport>,
    pub(crate) total_chars: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromptSectionReport {
    pub(crate) name: &'static str,
    pub(crate) included: bool,
    pub(crate) budget_chars: Option<usize>,
    pub(crate) original_chars: usize,
    pub(crate) rendered_chars: usize,
    pub(crate) truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromptSection {
    pub(crate) name: &'static str,
    pub(crate) content: String,
    pub(crate) budget_chars: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RenderedPromptSection {
    pub(crate) name: &'static str,
    pub(crate) content: String,
}

impl PromptSection {
    pub(crate) fn new(name: &'static str, content: impl Into<String>) -> Self {
        Self {
            name,
            content: content.into(),
            budget_chars: None,
        }
    }

    pub(crate) fn with_budget(mut self, budget_chars: usize) -> Self {
        self.budget_chars = Some(budget_chars);
        self
    }
}

pub(crate) fn truncate_prompt_section(content: &str, max_chars: usize) -> (String, bool) {
    if max_chars == 0 {
        return (String::new(), !content.trim().is_empty());
    }

    let trimmed = content.trim();
    let original_chars = trimmed.chars().count();
    if original_chars <= max_chars {
        return (trimmed.to_string(), false);
    }

    if max_chars <= 3 {
        return (trimmed.chars().take(max_chars).collect(), true);
    }

    let mut truncated: String = trimmed.chars().take(max_chars - 3).collect();
    truncated.push_str("...");
    (truncated, true)
}

pub(crate) fn assemble_prompt_sections(sections: Vec<PromptSection>) -> PromptAssembly {
    let mut rendered_sections = Vec::new();
    let mut report_sections = Vec::with_capacity(sections.len());

    for section in sections {
        let original_chars = section.content.trim().chars().count();
        let (rendered, truncated) = match section.budget_chars {
            Some(budget_chars) => truncate_prompt_section(&section.content, budget_chars),
            None => (section.content.trim().to_string(), false),
        };
        let included = !rendered.trim().is_empty();
        let rendered_chars = rendered.chars().count();

        if included {
            rendered_sections.push(RenderedPromptSection {
                name: section.name,
                content: rendered,
            });
        }

        report_sections.push(PromptSectionReport {
            name: section.name,
            included,
            budget_chars: section.budget_chars,
            original_chars,
            rendered_chars,
            truncated,
        });
    }

    let system_instructions = rendered_sections
        .iter()
        .map(|section| section.content.as_str())
        .collect::<Vec<_>>()
        .join("\n\n");
    let total_chars = system_instructions.chars().count();
    PromptAssembly {
        system_instructions,
        report: PromptAssemblyReport {
            sections: report_sections,
            total_chars,
        },
        rendered_sections,
    }
}

pub(crate) fn format_prompt_assembly_report(report: &PromptAssemblyReport) -> String {
    report
        .sections
        .iter()
        .map(|section| {
            format!(
                "{}:included={} chars={}/{} budget={} truncated={}",
                section.name,
                section.included,
                section.rendered_chars,
                section.original_chars,
                section
                    .budget_chars
                    .map(|budget| budget.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                section.truncated
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn stable_prompt_cache_section(section_name: &str) -> bool {
    !matches!(
        section_name,
        "browser_context"
            | "pending_browser_state"
            | "success_signal"
            | "recent_session_events"
            | "command_history"
            | "urgent_feedback"
            | "failure_block"
    )
}

pub(crate) fn prompt_section_hash(content: &str) -> String {
    sha256(content.as_bytes())
        .ok()
        .map(hex::encode)
        .unwrap_or_default()
}

pub(crate) fn build_prompt_memory_diagnostics(
    session_id: [u8; 32],
    assembly: &PromptAssembly,
) -> MemoryPromptDiagnostics {
    let stable_prefix = assembly
        .rendered_sections
        .iter()
        .filter(|section| stable_prompt_cache_section(section.name))
        .map(|section| section.content.as_str())
        .collect::<Vec<_>>()
        .join("\n\n");
    let dynamic_suffix = assembly
        .rendered_sections
        .iter()
        .filter(|section| !stable_prompt_cache_section(section.name))
        .map(|section| section.content.as_str())
        .collect::<Vec<_>>()
        .join("\n\n");

    MemoryPromptDiagnostics {
        updated_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        session_id_hex: hex::encode(session_id),
        total_chars: assembly.report.total_chars,
        prompt_hash: prompt_section_hash(&assembly.system_instructions),
        stable_prefix_hash: prompt_section_hash(&stable_prefix),
        dynamic_suffix_hash: prompt_section_hash(&dynamic_suffix),
        sections: assembly
            .report
            .sections
            .iter()
            .map(|section| MemoryPromptSectionDiagnostic {
                name: section.name.to_string(),
                included: section.included,
                budget_chars: section.budget_chars,
                original_chars: section.original_chars,
                rendered_chars: section.rendered_chars,
                truncated: section.truncated,
            })
            .collect(),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_standard_prompt_assembly(
    kernel_guidance: &str,
    active_window_title: &str,
    goal: &str,
    resolved_intent_summary: &str,
    core_memory_section: &str,
    urgent_feedback: &str,
    failure_block: &str,
    strategy_instruction: &str,
    tool_routing_contract: &str,
    som_instruction: &str,
    verify_instruction: &str,
    command_scope_instruction: &str,
    cognition_tool_desc: &str,
    browser_observation_context: &str,
    pending_browser_state_context: &str,
    success_signal_context: &str,
    pending_web_evidence_context: &str,
    recent_session_events_section: &str,
    command_history_section: &str,
    workspace_context: &str,
    operating_rules: &str,
    mailbox_instruction: Option<&str>,
    selected_parent_playbook_instruction: Option<&str>,
    active_worker_instruction: Option<&str>,
    workspace_scope_instruction: &str,
    automation_monitor_instruction: &str,
) -> PromptAssembly {
    let mut sections = vec![
        PromptSection::new(
            "kernel_policy",
            format!(
                "SYSTEM: You are a local desktop assistant operating inside the IOI runtime.\n\n\
=== LAYER 1: KERNEL POLICY ===\n\
You do NOT have blanket authority. Every action is mediated by the IOI Policy Engine.\n\
Only take actions that directly advance the USER GOAL.\n\n{}",
                kernel_guidance
            ),
        )
        .with_budget(PROMPT_SECTION_KERNEL_POLICY_MAX_CHARS),
        PromptSection::new(
            "state",
            format!(
                "=== LAYER 2: STATE ===\n\
- Active Window: {}\n\
- Goal: {}\n\
- Resolved Intent: {}",
                active_window_title, goal, resolved_intent_summary
            ),
        )
        .with_budget(PROMPT_SECTION_STATE_MAX_CHARS),
        PromptSection::new("core_memory", core_memory_section)
            .with_budget(PROMPT_SECTION_CORE_MEMORY_MAX_CHARS),
        PromptSection::new("urgent_feedback", urgent_feedback)
            .with_budget(PROMPT_SECTION_STATE_MAX_CHARS),
        PromptSection::new("failure_block", failure_block)
            .with_budget(PROMPT_SECTION_STATE_MAX_CHARS),
        PromptSection::new("strategy_instruction", strategy_instruction)
            .with_budget(PROMPT_SECTION_STRATEGY_MAX_CHARS),
        PromptSection::new("tool_routing_contract", tool_routing_contract)
            .with_budget(PROMPT_SECTION_TOOL_ROUTING_MAX_CHARS),
        PromptSection::new("som_instruction", som_instruction)
            .with_budget(PROMPT_SECTION_STRATEGY_MAX_CHARS),
        PromptSection::new("verify_instruction", verify_instruction)
            .with_budget(PROMPT_SECTION_VERIFY_MAX_CHARS),
        PromptSection::new("command_scope_contract", command_scope_instruction)
            .with_budget(PROMPT_SECTION_SCOPE_CONTRACT_MAX_CHARS),
        PromptSection::new(
            "available_tools",
            format!("[AVAILABLE TOOLS]\n{}", cognition_tool_desc),
        )
        .with_budget(PROMPT_SECTION_AVAILABLE_TOOLS_MAX_CHARS),
        PromptSection::new("browser_observation", browser_observation_context)
            .with_budget(PROMPT_SECTION_BROWSER_CONTEXT_MAX_CHARS),
        PromptSection::new("pending_browser_state", pending_browser_state_context)
            .with_budget(PROMPT_SECTION_PENDING_BROWSER_STATE_MAX_CHARS),
        PromptSection::new("success_signal", success_signal_context)
            .with_budget(PROMPT_SECTION_SUCCESS_SIGNAL_MAX_CHARS),
        PromptSection::new("pending_web_evidence", pending_web_evidence_context)
            .with_budget(PROMPT_SECTION_PENDING_WEB_EVIDENCE_MAX_CHARS),
        PromptSection::new("recent_session_events", recent_session_events_section)
            .with_budget(PROMPT_SECTION_RECENT_EVENTS_MAX_CHARS),
        PromptSection::new("command_history", command_history_section)
            .with_budget(PROMPT_SECTION_COMMAND_HISTORY_MAX_CHARS),
        PromptSection::new("workspace_context", workspace_context)
            .with_budget(PROMPT_SECTION_WORKSPACE_CONTEXT_MAX_CHARS),
        PromptSection::new("operating_rules", operating_rules)
            .with_budget(PROMPT_SECTION_OPERATING_RULES_MAX_CHARS),
    ];

    if let Some(mailbox_instruction) = mailbox_instruction {
        sections.push(
            PromptSection::new("mailbox_instruction", mailbox_instruction)
                .with_budget(PROMPT_SECTION_SPECIALIZED_INSTRUCTION_MAX_CHARS),
        );
    }
    if let Some(selected_parent_playbook_instruction) = selected_parent_playbook_instruction {
        sections.push(
            PromptSection::new(
                "selected_parent_playbook_instruction",
                selected_parent_playbook_instruction,
            )
            .with_budget(PROMPT_SECTION_SPECIALIZED_INSTRUCTION_MAX_CHARS),
        );
    }
    if let Some(active_worker_instruction) = active_worker_instruction {
        sections.push(
            PromptSection::new("active_worker_instruction", active_worker_instruction)
                .with_budget(PROMPT_SECTION_SPECIALIZED_INSTRUCTION_MAX_CHARS),
        );
    }

    sections.push(
        PromptSection::new("workspace_scope_contract", workspace_scope_instruction)
            .with_budget(PROMPT_SECTION_SPECIALIZED_INSTRUCTION_MAX_CHARS),
    );
    sections.push(
        PromptSection::new(
            "automation_monitor_contract",
            automation_monitor_instruction,
        )
        .with_budget(PROMPT_SECTION_SPECIALIZED_INSTRUCTION_MAX_CHARS),
    );

    assemble_prompt_sections(sections)
}

pub(crate) fn build_tool_routing_contract(
    prefer_browser_semantics: bool,
    resolved_scope: IntentScopeProfile,
) -> String {
    if prefer_browser_semantics {
        return "TOOL ROUTING CONTRACT:\n\
1. Prefer the most specific grounded browser tool over desktop-wide or shell tools.\n\
2. Ground the page with `browser__inspect` unless RECENT BROWSER OBSERVATION already names the exact target and next action.\n\
3. Prefer `browser__click` with grounded `id` or ordered `ids` for standard controls, `browser__select_option` for native dropdown/list choices, `browser__type` with `selector` for grounded editable fields, and `browser__click_at` only for grounded coordinate-style targets.\n\
4. For retrieval tasks that do not require page interaction, prefer `web__search` / `web__read` over interactive browser navigation.\n\
5. Never route browser-content interaction through `screen__click_at` or `shell__run` while an equivalent browser or web tool is available.\n\
6. If a specialized browser or retrieval tool is available, use it directly instead of escalating."
            .to_string();
    }

    match resolved_scope {
        IntentScopeProfile::WorkspaceOps => {
            "TOOL ROUTING CONTRACT:\n\
1. Prefer the most specific typed workspace tool over generic shell commands.\n\
2. If the exact file path is known, use `file__read`, `file__write`, `file__edit`, or `file__info` directly; use `file__search` only when the path is still unknown.\n\
3. Use `file__info` for timestamps and metadata, not `shell__run` plus ad hoc parsing.\n\
4. Use governed filesystem mutation tools before shell patching when they can express the change cleanly.\n\
5. Escalate only when no equivalent filesystem or workspace tool can perform the required action."
                .to_string()
        }
        IntentScopeProfile::CommandExecution => {
            "TOOL ROUTING CONTRACT:\n\
1. Prefer the most specific typed capability over raw shell when a dedicated tool exists.\n\
2. Use `app__launch` for GUI app launch, `software_install__resolve` and `software_install__execute_plan` for explicit package or desktop app install requests, `model_registry__*` / `backend__*` for model lifecycle, and `monitor__create` for durable watch or notify workflows.\n\
3. Use `shell__run` for bounded single-step command execution and `shell__start` for multi-step command workflows that need continuity.\n\
4. If the task is really retrieval, filesystem work, or media extraction, route to the corresponding typed tools instead of shell scraping.\n\
5. Escalate only when no equivalent typed capability or shell path can achieve the action safely."
                .to_string()
        }
        IntentScopeProfile::Conversation => {
            "TOOL ROUTING CONTRACT:\n\
1. Prefer `chat__reply` for pure conversation, drafting, or summarization requests.\n\
2. Use retrieval, memory, or action tools only when the user asks for facts, sources, or real-world side effects.\n\
3. Do not route simple conversational turns through browser, shell, or desktop tools without a concrete need."
                .to_string()
        }
        _ => {
            "TOOL ROUTING CONTRACT:\n\
1. Prefer the most specific typed tool over generic shell, GUI-coordinate, or fallback tools.\n\
2. Use read/inspect tools to ground the target first when a semantic or exact path-based tool exists.\n\
3. For desktop apps, prefer `app__launch`; for non-browser UI, prefer `screen__inspect` then `screen__click` / `screen__type`; use coordinates only as a last resort.\n\
4. For retrieval, prefer `web__search` / `web__read`; use `http__fetch` only for exact raw endpoints and `media__extract_evidence` for direct media analysis.\n\
5. Do not use `chat__reply` or `agent__escalate` while an equivalent typed action tool is available."
                .to_string()
        }
    }
}

pub(crate) fn browser_rule_relevant(fragment: &str, cues: &[&str]) -> bool {
    let lowered = fragment.to_ascii_lowercase();
    cues.iter().any(|cue| {
        let cue_lower = cue.to_ascii_lowercase();
        if cue_lower.chars().all(|ch| ch.is_ascii_alphanumeric()) {
            lowered
                .split(|ch: char| !ch.is_ascii_alphanumeric())
                .any(|token| token == cue_lower)
        } else {
            lowered.contains(&cue_lower)
        }
    })
}

pub(crate) fn build_browser_operating_rules(
    goal: &str,
    browser_observation_context: &str,
    pending_browser_state_context: &str,
    success_signal_context: &str,
) -> String {
    if goal_prefers_sustained_hover_browser_surface(goal)
        && pending_browser_state_context.trim().is_empty()
        && success_signal_context.trim().is_empty()
    {
        return [
            "OPERATING RULES:",
            "1. Use the grounded browser state and output EXACTLY ONE valid JSON tool call.",
            "2. Prefer one grounded `browser__hover` with `duration_ms` `30000` for a moving target. Do not use a short probe hover that will expire before the task can finish.",
            "3. Use `browser__move_pointer` only if `browser__hover` cannot track the target from the current browser observation. Do not spend the next step on `browser__inspect` unless the target is missing or no longer grounded.",
            "4. Use `agent__escalate` only if the available browser tools cannot reach the target.",
        ]
        .join("\n");
    }

    let browser_context = format!(
        "{}\n{}\n{}",
        browser_observation_context, pending_browser_state_context, success_signal_context
    );
    let mut rules = vec![
        "1. Use the least-privileged browser tool that works and output EXACTLY ONE valid JSON tool call.".to_string(),
        "2. Treat RECENT BROWSER OBSERVATION, RECENT PENDING BROWSER STATE, and RECENT SUCCESS SIGNAL as the grounded state. If they already name a visible control and the next action, do that instead of another `browser__inspect`, `browser__scroll`, or `browser__find_text`. When RECENT PENDING BROWSER STATE gives an exact tool call, emit that exact tool call unless the current browser observation proves it impossible. Preserve numeric arguments exactly as written; do not round, simplify, swap in a nearby id, or substitute alternate coordinates.".to_string(),
        "3. Only use `browser__click` ids that appear verbatim in RECENT BROWSER OBSERVATION or RECENT PENDING BROWSER STATE; never synthesize ids. Prefer numeric `som_id` values from tagged browser observations when available; otherwise use the grounded semantic id exactly as shown.".to_string(),
        "4. Prefer `browser__click` over GUI or desktop-wide input for standard page controls. When RECENT BROWSER OBSERVATION, RECENT PENDING BROWSER STATE, or RECENT SUCCESS SIGNAL already grounds a coordinate-style target or explicitly names `browser__click_at`, follow that tool instead of converting it to `browser__click`. `browser__find_text` is navigation evidence, not proof that a target row, item, or record is visible. If requested text appears in both instructions and the working area, the instruction copy is descriptive only.".to_string(),
        "5. When a precise delay, wait condition, or coordinate-style action must be followed by an already grounded browser action, prefer `browser__wait` or `browser__click_at` with `continue_with` so the executor can act immediately without another inference turn. `browser__click_at` must include a grounded `id` from RECENT BROWSER OBSERVATION or RECENT PENDING BROWSER STATE; do not emit raw coordinate-only clicks. Use `continue_with` only when the follow-up tool name and every required argument are already fully grounded in RECENT BROWSER OBSERVATION, RECENT PENDING BROWSER STATE, or RECENT SUCCESS SIGNAL. If the follow-up action is only implied by the page instruction, take the first action alone and re-evaluate. After a coordinate click's observable browser reaction is known, attach at most a single grounded follow-up control. Do not use `continue_with` for drag setup or pointer button state changes.".to_string(),
        "5b. For `browser__click_at`, use the grounded semantic `id` as the coordinate-space anchor. If explicit `x`/`y` are also supplied, they are viewport CSS pixels associated with that grounded id, not a route to guess raw screen positions.".to_string(),
        "5c. When a grounded editable field is already visible and the next action is to enter text, prefer one `browser__type` with `selector` over a separate focus click plus typing. If the field must be focused first because the click itself is the next grounded browser action, you may use `browser__click` with `continue_with` `browser__type` only when the field target and exact text are already fully grounded.".to_string(),
    ];

    if browser_rule_relevant(
        goal,
        &[
            "select ", "check ", "click ", "ordered", "sequence", " then ",
        ],
    ) || pending_browser_state_context.contains("`ids` [")
    {
        rules.push(
            "5a. When the page instruction already requires an ordered sequence of grounded clicks, prefer one `browser__click` call with ordered `ids` and `delay_ms_between_ids` over separate inference turns. If a visible gate or commit click must happen first, only attach `continue_with` when RECENT PENDING BROWSER STATE or RECENT SUCCESS SIGNAL already provides the complete follow-up `browser__click` arguments; otherwise click the gate first and re-evaluate."
                .to_string(),
        );
    }

    if browser_rule_relevant(
        goal,
        &[
            "keep your mouse",
            "keep the mouse",
            "keep mouse",
            "keep the pointer",
            "keep pointer",
            "keep the cursor",
            "hold the mouse",
            "hold the pointer",
            "hold the cursor",
            "stay inside",
            "stay on",
            "follow",
            "moves around",
            "moving target",
            "as it moves",
        ],
    ) {
        rules.push(
            "5b. When the goal is to keep or hold the pointer on a moving target, prefer one grounded `browser__hover` with `duration_ms` set to the longest safe tracking window (`30000`) unless RECENT PENDING BROWSER STATE gives a shorter grounded deadline. Do not spend the next step on a short probe hover that will expire before the task can finish."
                .to_string(),
        );
    }

    if browser_rule_relevant(&browser_context, &["autocomplete", "listbox", "combobox"]) {
        rules.push(
            "6. Resolve pending autocomplete, listbox, or combobox state before submit or completion. If a navigation key highlighted a candidate, commit it with `browser__press_key` `Enter`."
                .to_string(),
        );
    }

    if browser_rule_relevant(
        &format!("{}\n{}", goal, browser_context),
        &[
            "select ", "choose ", "dropdown", "combobox", "listbox", "option",
        ],
    ) {
        rules.push(
            "6b. When the goal is to choose an option from a native dropdown or list and the control is already grounded as a `combobox`, `listbox`, or `option`, prefer `browser__select_option` with the exact requested `label` or `value` instead of clicking the control just to focus it. Use `browser__list_options` only when the requested option text is not already grounded."
                .to_string(),
        );
    }

    if !success_signal_context.trim().is_empty()
        || browser_rule_relevant(goal, &["submit", "save", "send", "apply", "confirm"])
    {
        rules.push(
            "7. Verify success with browser state before `agent__complete`. If RECENT SUCCESS SIGNAL says a submit already turned over the page and the prior target or selected control are gone, treat the current observation as sufficient. Do not interact with the newly visible page."
                .to_string(),
        );
    }

    if browser_rule_relevant(
        &format!("{}\n{}", goal, browser_context),
        &[
            "scroll",
            "pageup",
            "page up",
            "pagedown",
            "page down",
            "home",
            "end",
            "control+home",
            "control+end",
            "meta+arrowup",
            "meta+arrowdown",
            "can_scroll_",
            "scroll_top",
        ],
    ) {
        rules.push(format!(
            "8. For scroll goals, ground the real scrollable control first. Do not start with page-level `Home` or `End` on `body` when RECENT BROWSER OBSERVATION already exposes the intended control. When that control already has a grounded selector, prefer `browser__press_key` with `selector` over a separate focus click. Prefer control-local `Home`, `End`, `PageUp`, or `PageDown`. Finish only when grounded state shows `can_scroll_up=false`, `scroll_top=0`, or `can_scroll_down=false`. If `Home` or `End` still leaves room to move, do not repeat it blindly: escalate with the same control-local `browser__press_key` plus modifiers (for example {} (`{}`) when the control is already grounded) or the matching bottom-edge chord.",
            top_edge_jump_tool_call_with_grounded_selector(),
            top_edge_jump_name(),
        ));
        rules.push(format!(
            "9. When using `browser__press_key` for a control-local action, include `selector` when the intended control is already grounded. When escalating a grounded control with a modifier chord like `{}`, reuse that same `selector` and include both `key` and `modifiers` in the JSON tool call.",
            top_edge_jump_name(),
        ));
        rules.push(
            "10. If a grounded control-local key is expected to finish the local scroll state and exactly one next visible control is already grounded, you may nest that immediate browser follow-up inside `continue_with` to avoid burning another inference turn."
                .to_string(),
        );
    }

    if browser_rule_relevant(
        &format!("{}\n{}", goal, browser_context),
        &[
            "reply", "delete", "archive", "mark", "toggle", "row", "record", "item", "field",
        ],
    ) {
        rules.push(
            "10. After the target record, item, or field is grounded, prefer the nearby control whose visible name matches the requested action. Do not repeat interactions already confirmed by `postcondition.met=true`, `checked=true`, or `selected=true`."
                .to_string(),
        );
    }

    if browser_rule_relevant(
        goal,
        &[
            "first", "second", "third", "fourth", "fifth", "1st", "2nd", "3rd", "4th", "5th",
        ],
    ) {
        rules.push(
            "11. For ranked lists, ordinal words in the instruction are not the clickable target. Count actual visible result links/items and click the real result item."
                .to_string(),
        );
    }

    if browser_rule_relevant(
        &format!("{}\n{}", goal, browser_context),
        &["no selections", "no selection", "unselected", "unchecked"],
    ) {
        rules.push(
            "12. When the grounded page instruction explicitly requires no selections, treat the all-unchecked / unselected state as already satisfying that requirement."
                .to_string(),
        );
    }

    rules.push(
        "13. Use `window__focus` only to recover browser focus and `agent__escalate` only when the available browser tools cannot reach the target.".to_string(),
    );

    format!("OPERATING RULES:\n{}", rules.join("\n"))
}

pub(crate) fn build_operating_rules(
    prefer_browser_semantics: bool,
    goal: &str,
    browser_observation_context: &str,
    pending_browser_state_context: &str,
    success_signal_context: &str,
) -> String {
    if prefer_browser_semantics {
        return build_browser_operating_rules(
            goal,
            browser_observation_context,
            pending_browser_state_context,
            success_signal_context,
        );
    } else {
        "OPERATING RULES:\n\
1. Prefer retrieval-led reasoning over pre-training-led reasoning.\n\
2. If the context above contains a file index, read the referenced files before guessing APIs.\n\
3. Use the least-privileged tool that works.\n\
4. Output EXACTLY ONE valid JSON tool call.\n\
4a. DESKTOP RELIABILITY PROTOCOL:\n\
    - If you are about to click/type/scroll in a browser, do `browser__inspect` first unless you already have a very recent snapshot in HISTORY.\n\
    - If RECENT BROWSER OBSERVATION already includes the target semantic id or label, use `browser__click` on that id instead of taking another snapshot.\n\
    - If you are about to click/type in a non-browser app, do `screen__inspect` first when an element id is needed; then use `screen__click` / `screen__type`.\n\
    - After any action, verify via the least-cost check (browser snapshot for browser; gui snapshot or active window title for GUI) before claiming success.\n\
5. When goal achieved, call 'agent__complete'.\n\
6. If the current mode fails, output a reason why so the system can escalate to the next tier.\n\
7. CRITICAL: When using 'screen.type', you MUST first CLICK the input field to ensure focus.\n\
8. BROWSER RULE: Never launch browsers via `shell__run`. Treat that as a policy violation. Use `browser__navigate` only for interactive browsing actions that require browser UI state.\n\
8a. WEB RETRIEVAL RULE: For retrieval (look up, latest, sources, citations), use `web__search` and `web__read` first. Do NOT open search engine SERP pages via `browser__navigate` when `web__search` is available. Use `browser__*` only when the page requires interaction (auth/forms/CAPTCHA). If a human-verification challenge appears, stop and ask the user to complete it manually, then retry.\n\
8aa. DIRECT FETCH RULE: Use `http__fetch` only when the user explicitly provides an exact URL/endpoint and asks for raw response text/headers or API diagnostics. For exact webpage/article URLs that the user wants summarized or read, prefer direct `web__read` before `web__search`. For exact audio/video URLs that the user wants summarized or generally analyzed, prefer `media__extract_evidence` before `web__read`. Use `media__extract_transcript` when the user explicitly wants a transcript/transcription. Do not silently replace media-content requests with page-description summaries when direct media evidence extraction is available.\n\
8ab. FETCH HYGIENE RULE: Never invent API keys, placeholder credentials (for example `YOUR_API_KEY`), or auto-IP endpoints. If credentials or endpoint details are missing, switch to source-grounded web retrieval and cite the sources.\n\
8ac. MEMORY RETRIEVAL RULE: For questions about prior durable workflow, remembered constraints, or stored project context, use `memory__search` and `memory__read` before answering. If you need to order candidate snippets by relevance, use `model__rerank`. Use `model__embeddings` only for semantic comparison inputs, not as a final answer.\n\
8b. BROWSER CLICK RULE: In a browser window, never use `screen__click_at` on web content. Prefer `browser__click` with IDs from `browser__inspect`; use `browser__click` with concrete CSS selectors only as fallback. Use GUI clicks only for OS chrome (address bar/system dialogs) when browser tools cannot target it.\n\
8c. SOFTWARE INSTALL RULE: Only use `software_install__resolve` / `software_install__execute_plan` when the user explicitly asked to install something. For desktop apps, let the resolver discover host OS, source candidates, approval details, and verification; do not answer with manual prose unless the resolver reports an installer-resolution blocker.\n\
8d. BROWSER RESILIENCE RULE: If `browser__navigate` fails with CDP/connection errors, retry `browser__navigate` once. If it still fails, switch to visual tools.\n\
8e. SHELL CONTINUITY RULE: For command workflows with more than one command step (build/test/install sequences, iterative probing), prefer `shell__start` for continuity. Use `shell__reset` only when output indicates the session is wedged.\n\
9. APP LAUNCH RULE: To open applications, use `app__launch` as the primary launch mechanism whenever it is available in TOOLS.\n\
   - If `app__launch` is unavailable, choose the best equivalent launch-capable tool available in the current scope and continue execution.\n\
   - Treat `agent__escalate` as a last resort only when no available tool can perform app launch in the current scope.\n\
   - APP LAUNCH VERIFICATION: After launching, verify the app is actually open/focused before calling `agent__complete`.\n\
     If launch cannot be verified, mark the launch as failed and continue recovery.\n\
   - NEVER try to click random ID #1 (the background) hoping it opens a menu.\n\
10. DELEGATION RULE: Do NOT use 'agent__delegate' for simple, atomic actions like opening an app, clicking a button, or typing text. Use the direct tool. When a bounded worker is justified, prefer `researcher` for evidence gathering, `verifier` for postcondition checks, and `coder` for narrow implementation slices.\n\
11. CAPABILITY CHECK: If a preferred tool is unavailable, first use an equivalent available tool (e.g. use `screen__click` when `screen` is unavailable). Only call `agent__escalate` when no equivalent tool can achieve the action.\n\
12. CHAT RULE: Do NOT use 'chat__reply' to announce planned actions (e.g. \"I will now open...\"). Use chat only for final user-facing answers or explicit clarification requests.\n\
13. RECOVERY RULE: If you previously failed with `DELEGATION_REJECTED` or `MISSING_CAPABILITY`, do not retry the same strategy. Use `agent__escalate` to request a tier upgrade.\n\
14. CONTEXT SWITCHING RULE: Check the 'Active Window' in the state above.\n\
    - If Active Window is 'Calculator' (or any non-browser app), DO NOT use 'browser__*' tools. Use `screen__click` first, then `screen.left_click` if needed.\n\
    - If Active Window is 'Chrome' or 'Firefox', prefer 'browser__*' tools for web interaction.\n\
 15. SILENT EXECUTION: For action intents (web/ui/workspace/command), execute the action immediately. For conversation intents (summarize/draft/reply), use `chat__reply` with the requested output.\n\
 16. SEARCH COMPLETION RULE: For search intents, do `web__search` first. If needed, follow with `web__read` on 1-3 top sources. For the final answer, use `chat__reply` with natural Markdown grounded in the typed tool results; do not force briefing/story labels. For current market or investment comparisons, prefer typed quote/read outputs over search snippets, include observed price, market cap, volume, and percentage change for every compared asset when present, and never treat nominal token price as an investment-quality axis.\n\
 17. COMMAND PROBE RULE: If resolved intent_id is `command.probe`, treat this as an environment check (not an install task).\n\
     - Use `shell__run` with a POSIX-sh-safe probe that exits 0 whether the command exists or not.\n\
     - Do NOT execute the target program directly to check existence.\n\
     - Treat `NOT_FOUND_IN_PATH` as a valid final answer (not an error or failure mode).\n\
     - After the probe, summarize `FOUND:`/`NOT_FOUND_IN_PATH` and finish with `agent__complete` (do not attempt remediation).\n\
     - Do NOT install packages unless the user explicitly asked to install.\n\
     - Example (replace <BIN>): `if command -v <BIN> >/dev/null 2>&1; then echo \"FOUND: $(command -v <BIN>)\"; <BIN> --version 2>/dev/null || true; else echo \"NOT_FOUND_IN_PATH\"; fi`.\n\
 18. MATH RULE: For pure arithmetic expressions or numeric calculations (for example `247 * 38`), use `math__eval` when available. Do NOT use `shell__run`/`shell__start` for arithmetic-only tasks."
            .to_string()
    }
}

pub(crate) fn compact_browser_action_prompt_eligible(
    prefer_browser_semantics: bool,
    has_prompt_visual_context: bool,
    goal: &str,
    browser_observation_context: &str,
    pending_browser_state_context: &str,
    success_signal_context: &str,
) -> bool {
    prefer_browser_semantics
        && !has_prompt_visual_context
        && goal_prefers_sustained_hover_browser_surface(goal)
        && !browser_observation_context.trim().is_empty()
        && pending_browser_state_context.trim().is_empty()
        && success_signal_context.trim().is_empty()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_compact_browser_action_prompt_assembly(
    kernel_guidance: &str,
    active_window_title: &str,
    goal: &str,
    resolved_intent_summary: &str,
    core_memory_section: &str,
    urgent_feedback: &str,
    failure_block: &str,
    strategy_instruction: &str,
    tool_routing_contract: &str,
    verify_instruction: &str,
    cognition_tool_desc: &str,
    browser_observation_context: &str,
    pending_browser_state_context: &str,
    success_signal_context: &str,
    operating_rules: &str,
) -> PromptAssembly {
    assemble_prompt_sections(vec![
        PromptSection::new(
            "kernel_policy",
            "SYSTEM: You are a local desktop assistant operating inside the IOI runtime.",
        )
        .with_budget(PROMPT_SECTION_KERNEL_POLICY_MAX_CHARS),
        PromptSection::new(
            "compact_browser_contract",
            "Follow policy. Output exactly one grounded browser tool call that advances the goal.",
        )
        .with_budget(PROMPT_SECTION_STRATEGY_MAX_CHARS),
        PromptSection::new("kernel_guidance", kernel_guidance)
            .with_budget(PROMPT_SECTION_KERNEL_POLICY_MAX_CHARS),
        PromptSection::new(
            "state",
            format!(
                "STATE:\n- Active Window: {}\n- Goal: {}\n- Resolved Intent: {}",
                active_window_title, goal, resolved_intent_summary
            ),
        )
        .with_budget(PROMPT_SECTION_STATE_MAX_CHARS),
        PromptSection::new("core_memory", core_memory_section)
            .with_budget(PROMPT_SECTION_CORE_MEMORY_MAX_CHARS),
        PromptSection::new("urgent_feedback", urgent_feedback)
            .with_budget(PROMPT_SECTION_STATE_MAX_CHARS),
        PromptSection::new("failure_block", failure_block)
            .with_budget(PROMPT_SECTION_STATE_MAX_CHARS),
        PromptSection::new("strategy_instruction", strategy_instruction)
            .with_budget(PROMPT_SECTION_STRATEGY_MAX_CHARS),
        PromptSection::new("tool_routing_contract", tool_routing_contract)
            .with_budget(PROMPT_SECTION_TOOL_ROUTING_MAX_CHARS),
        PromptSection::new("verify_instruction", verify_instruction)
            .with_budget(PROMPT_SECTION_VERIFY_MAX_CHARS),
        PromptSection::new(
            "available_tools",
            format!("[AVAILABLE TOOLS]\n{}", cognition_tool_desc),
        )
        .with_budget(PROMPT_SECTION_AVAILABLE_TOOLS_MAX_CHARS),
        PromptSection::new("browser_observation", browser_observation_context)
            .with_budget(PROMPT_SECTION_BROWSER_CONTEXT_MAX_CHARS),
        PromptSection::new("pending_browser_state", pending_browser_state_context)
            .with_budget(PROMPT_SECTION_PENDING_BROWSER_STATE_MAX_CHARS),
        PromptSection::new("success_signal", success_signal_context)
            .with_budget(PROMPT_SECTION_SUCCESS_SIGNAL_MAX_CHARS),
        PromptSection::new("operating_rules", operating_rules)
            .with_budget(PROMPT_SECTION_OPERATING_RULES_MAX_CHARS),
    ])
}

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(crate) fn build_compact_browser_action_system_instructions(
    kernel_guidance: &str,
    active_window_title: &str,
    goal: &str,
    resolved_intent_summary: &str,
    core_memory_section: &str,
    urgent_feedback: &str,
    failure_block: &str,
    strategy_instruction: &str,
    tool_routing_contract: &str,
    verify_instruction: &str,
    cognition_tool_desc: &str,
    browser_observation_context: &str,
    pending_browser_state_context: &str,
    success_signal_context: &str,
    operating_rules: &str,
) -> String {
    build_compact_browser_action_prompt_assembly(
        kernel_guidance,
        active_window_title,
        goal,
        resolved_intent_summary,
        core_memory_section,
        urgent_feedback,
        failure_block,
        strategy_instruction,
        tool_routing_contract,
        verify_instruction,
        cognition_tool_desc,
        browser_observation_context,
        pending_browser_state_context,
        success_signal_context,
        operating_rules,
    )
    .system_instructions
}
