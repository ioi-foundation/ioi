use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GuessNumberInputPhase {
    Idle,
    TypeGuess(i32),
    SubmitGuess(i32),
}

impl Default for GuessNumberInputPhase {
    fn default() -> Self {
        Self::Idle
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct GuessNumberState {
    pub(super) low: i32,
    pub(super) high: i32,
    pub(super) last_submitted_guess: Option<i32>,
    pub(super) feedback_applied_for: Option<i32>,
    pub(super) input_phase: GuessNumberInputPhase,
}

impl Default for GuessNumberState {
    fn default() -> Self {
        Self {
            low: 0,
            high: 9,
            last_submitted_guess: None,
            feedback_applied_for: None,
            input_phase: GuessNumberInputPhase::Idle,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct FindGreatestState {
    pub(super) pending_observation_index: Option<usize>,
    pub(super) next_probe_index: usize,
    pub(super) best_card_index: Option<usize>,
    pub(super) best_value: i32,
    pub(super) revisit_before_submit: bool,
}

impl Default for FindGreatestState {
    fn default() -> Self {
        Self {
            pending_observation_index: None,
            next_probe_index: 1,
            best_card_index: None,
            best_value: i32::MIN,
            revisit_before_submit: false,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct PendingSocialMediaMenuAction {
    pub(super) row_index: usize,
    pub(super) action_class: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TextEditorPhase {
    SelectTarget,
    ApplyAction,
    Submit,
}

impl Default for TextEditorPhase {
    fn default() -> Self {
        Self::SelectTarget
    }
}

pub(super) struct MiniwobAgentRuntime {
    pub(super) case: ComputerUseCase,
    pub(super) client: BridgeClient,
    pub(super) session_id: String,
    pub(super) url: String,
    pub(super) startup_navigation_issued: Mutex<bool>,
    pub(super) pending_followup: Mutex<Option<String>>,
    pub(super) optimistic_checked_labels: Mutex<BTreeSet<String>>,
    pub(super) last_scroll_action: Mutex<Option<String>>,
    pub(super) last_copy_paste_action: Mutex<Option<String>>,
    pub(super) last_hover_shape_phase: Mutex<Option<String>>,
    pub(super) text_editor_phase: Mutex<TextEditorPhase>,
    pub(super) guess_number_state: Mutex<GuessNumberState>,
    pub(super) find_greatest_state: Mutex<FindGreatestState>,
    pub(super) count_sides_estimate: Mutex<Option<u32>>,
    pub(super) pending_social_media_menu_action: Mutex<Option<PendingSocialMediaMenuAction>>,
}

impl MiniwobAgentRuntime {
    pub(super) fn startup_navigation_issued(&self) -> bool {
        self.startup_navigation_issued
            .lock()
            .map(|issued| *issued)
            .unwrap_or(false)
    }

    fn mark_startup_navigation_issued(&self) {
        if let Ok(mut issued) = self.startup_navigation_issued.lock() {
            *issued = true;
        }
    }

    fn note_pending_followup(&self, phase: &str) {
        if let Ok(mut pending) = self.pending_followup.lock() {
            *pending = Some(phase.to_string());
        }
    }

    fn take_pending_followup(&self) -> Option<String> {
        self.pending_followup
            .lock()
            .ok()
            .and_then(|mut pending| pending.take())
    }

    pub(super) fn note_count_sides_estimate(&self, estimated_sides: u32) {
        if let Ok(mut pending) = self.count_sides_estimate.lock() {
            *pending = Some(estimated_sides);
        }
    }

    fn take_count_sides_estimate(&self) -> Option<u32> {
        self.count_sides_estimate
            .lock()
            .ok()
            .and_then(|mut pending| pending.take())
    }

    pub(super) fn observe_kernel_events(&self, kernel_events: &[KernelEvent]) {
        for event in kernel_events {
            let KernelEvent::AgentActionResult {
                tool_name,
                output,
                error_class,
                ..
            } = event
            else {
                continue;
            };
            if tool_name != "browser__canvas_summary" || error_class.is_some() {
                continue;
            }
            let Some(summary) = extract_canvas_summary(Some(output.as_str())) else {
                continue;
            };
            let Some(estimated_sides) = summary.estimated_sides else {
                continue;
            };
            self.note_count_sides_estimate(estimated_sides);
        }
    }

    fn note_checkbox_click(&self, label: &str) {
        if let Ok(mut labels) = self.optimistic_checked_labels.lock() {
            labels.insert(normalize_label(label));
        }
    }

    fn checkbox_target_satisfied(
        &self,
        elements: &[BridgeInteractiveElement],
        label: &str,
    ) -> bool {
        if bridge_checkbox_checked_for_label(elements, label).unwrap_or(false) {
            return true;
        }
        self.optimistic_checked_labels
            .lock()
            .map(|labels| labels.contains(&normalize_label(label)))
            .unwrap_or(false)
    }

    pub(super) fn note_scroll_action(&self, action: &str) {
        if let Ok(mut last) = self.last_scroll_action.lock() {
            *last = Some(action.to_string());
        }
    }

    fn last_scroll_action(&self) -> Option<String> {
        self.last_scroll_action
            .lock()
            .ok()
            .and_then(|last| last.clone())
    }

    fn note_copy_paste_action(&self, action: &str) {
        if let Ok(mut last) = self.last_copy_paste_action.lock() {
            *last = Some(action.to_string());
        }
    }

    fn last_copy_paste_action(&self) -> Option<String> {
        self.last_copy_paste_action
            .lock()
            .ok()
            .and_then(|last| last.clone())
    }

    fn note_hover_shape_phase(&self, phase: &str) {
        if let Ok(mut last) = self.last_hover_shape_phase.lock() {
            *last = Some(phase.to_string());
        }
    }

    pub(super) fn hover_shape_phase(&self) -> Option<String> {
        self.last_hover_shape_phase
            .lock()
            .ok()
            .and_then(|last| last.clone())
    }

    fn text_editor_phase(&self) -> TextEditorPhase {
        self.text_editor_phase
            .lock()
            .map(|phase| *phase)
            .unwrap_or_default()
    }

    fn set_text_editor_phase(&self, phase: TextEditorPhase) {
        if let Ok(mut current) = self.text_editor_phase.lock() {
            *current = phase;
        }
    }

    pub(super) fn guess_number_state(&self) -> GuessNumberState {
        self.guess_number_state
            .lock()
            .map(|state| *state)
            .unwrap_or_default()
    }

    pub(super) fn update_guess_number_state(&self, update: impl FnOnce(&mut GuessNumberState)) {
        if let Ok(mut state) = self.guess_number_state.lock() {
            update(&mut state);
        }
    }

    fn find_greatest_state(&self) -> FindGreatestState {
        self.find_greatest_state
            .lock()
            .map(|state| *state)
            .unwrap_or_default()
    }

    pub(super) fn update_find_greatest_state(&self, update: impl FnOnce(&mut FindGreatestState)) {
        if let Ok(mut state) = self.find_greatest_state.lock() {
            update(&mut state);
        }
    }

    fn note_pending_social_media_menu_action(&self, row_index: usize, action_class: &str) {
        if let Ok(mut pending) = self.pending_social_media_menu_action.lock() {
            *pending = Some(PendingSocialMediaMenuAction {
                row_index,
                action_class: action_class.to_string(),
            });
        }
    }

    fn take_pending_social_media_menu_action(&self) -> Option<PendingSocialMediaMenuAction> {
        self.pending_social_media_menu_action
            .lock()
            .ok()
            .and_then(|mut pending| pending.take())
    }

    fn fill_text_field_if_needed(
        &self,
        bridge_state: &BridgeState,
        elements: &[BridgeInteractiveElement],
        selector: &str,
        text: &str,
    ) -> Option<Vec<u8>> {
        if bridge_value_by_selector(elements, selector) == text {
            return None;
        }

        Some(if bridge_focus_matches(bridge_state, selector) {
            self.note_pending_followup("form_type");
            inference_tool_call(
                "browser__type",
                json!({ "selector": selector, "text": text }),
            )
        } else {
            inference_tool_call("browser__click", json!({ "selector": selector }))
        })
    }

    fn form_sequence_action(
        &self,
        bridge_state: &BridgeState,
        elements: &[BridgeInteractiveElement],
        query: &str,
    ) -> Vec<u8> {
        let target_value = parse_form_sequence_slider_target(query).unwrap_or_default();
        let checkbox_index = parse_form_sequence_checkbox_index(query).unwrap_or(1);
        let checkbox_selector = format!("#checkbox-{}", checkbox_index);
        let current_value =
            parse_first_integer(bridge_visible_content_after_query(bridge_state, query));
        let checkbox_checked = bridge_element_by_selector(elements, &checkbox_selector)
            .and_then(|element| element.checked)
            .unwrap_or(false);

        match current_value {
            Some(value) if value != target_value => {
                if bridge_state.info.focused_tag.as_deref() == Some("span") {
                    let key = if value < target_value {
                        "ArrowRight"
                    } else {
                        "ArrowLeft"
                    };
                    self.note_pending_followup("form_type");
                    inference_tool_call("browser__key", json!({ "key": key }))
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#slider span" }))
                }
            }
            Some(_) if !checkbox_checked => {
                inference_tool_call("browser__click", json!({ "selector": checkbox_selector }))
            }
            Some(_) => inference_tool_call("browser__click", json!({ "selector": "#subbtn" })),
            None => inference_tool_call("browser__click", json!({ "selector": "#slider span" })),
        }
    }

    fn form_sequence_2_action(
        &self,
        bridge_state: &BridgeState,
        elements: &[BridgeInteractiveElement],
        query: &str,
    ) -> Vec<u8> {
        let radio_index = parse_form_sequence_2_radio_index(query).unwrap_or(1);
        let textbox_index = parse_form_sequence_2_textbox_index(query).unwrap_or(1);
        let number = quoted_values(query).into_iter().next().unwrap_or_default();
        let radio_selector =
            format!("#area > div:nth-of-type(1) > input:nth-of-type({radio_index})");
        let textbox_selector = format!("#input-{textbox_index}");
        let radio_checked = bridge_element_by_selector(elements, &radio_selector)
            .and_then(|element| element.checked)
            .unwrap_or(false);

        if !radio_checked {
            inference_tool_call("browser__click", json!({ "selector": radio_selector }))
        } else if let Some(action) =
            self.fill_text_field_if_needed(bridge_state, elements, &textbox_selector, &number)
        {
            action
        } else {
            inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
        }
    }

    fn form_sequence_3_action(
        &self,
        elements: &[BridgeInteractiveElement],
        query: &str,
    ) -> Vec<u8> {
        let dropdown_label = parse_form_sequence_3_dropdown_label(query).unwrap_or_default();
        let button_label = quoted_values(query).into_iter().next().unwrap_or_default();

        if bridge_value_by_selector(elements, "#dropdown") != dropdown_label {
            self.note_pending_followup("form_type");
            inference_tool_call(
                "browser__select_dropdown",
                json!({ "selector": "#dropdown", "label": dropdown_label }),
            )
        } else if let Some(selector) = bridge_selector_for_label(elements, &button_label) {
            inference_tool_call("browser__click", json!({ "selector": selector }))
        } else {
            let normalized = normalize_label(&button_label);
            inference_tool_call(
                "browser__click",
                json!({ "selector": format!("#{}", normalized.replace(' ', "-")) }),
            )
        }
    }

    fn login_user_popup_action(
        &self,
        bridge_state: &BridgeState,
        elements: &[BridgeInteractiveElement],
        query: &str,
    ) -> Vec<u8> {
        if bridge_element_by_selector(elements, "#popup-cancel")
            .is_some_and(|element| element.visible && !element.disabled)
        {
            return inference_tool_call("browser__click", json!({ "selector": "#popup-cancel" }));
        }

        if let Some(selector) = bridge_selector_for_label(elements, "Cancel") {
            return inference_tool_call("browser__click", json!({ "selector": selector }));
        }

        let quoted = quoted_values(query);
        let username = quoted.first().cloned().unwrap_or_default();
        let password = quoted.get(1).cloned().unwrap_or_default();
        let username_value = bridge_value_by_selector(elements, "#username");
        let password_value = bridge_value_by_selector(elements, "#password");

        if username_value != username {
            self.fill_text_field_if_needed(bridge_state, elements, "#username", &username)
                .unwrap_or_else(|| {
                    inference_tool_call("browser__click", json!({ "selector": "#username" }))
                })
        } else if password_value != password {
            self.fill_text_field_if_needed(bridge_state, elements, "#password", &password)
                .unwrap_or_else(|| {
                    inference_tool_call("browser__click", json!({ "selector": "#password" }))
                })
        } else {
            inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
        }
    }

    fn text_editor_action(&self, bridge_state: &BridgeState, query: &str) -> Vec<u8> {
        const EDITOR_SELECTOR: &str = "#editor .ql-editor";
        const COLOR_SELECTOR: &str = "#area > div:nth-of-type(1) > span:nth-of-type(1) > select";

        let editor_text =
            trim_submit_button_suffix(bridge_visible_content_after_query(bridge_state, query));
        if editor_text.is_empty() {
            return inference_fail("ERROR_CLASS=ObservationGap text-editor content missing");
        }

        let action_token = parse_text_editor_action_token(query).unwrap_or_default();
        let target = parse_text_editor_target(query).unwrap_or(Some(editor_text.to_string()));
        let (start_offset, end_offset) = if let Some(target_text) = target {
            let Some(start_byte) = editor_text.find(&target_text) else {
                return inference_fail("ERROR_CLASS=ObservationGap text-editor target missing");
            };
            let prefix = &editor_text[..start_byte];
            let start = prefix.chars().count() as u32;
            let end = start + target_text.chars().count() as u32;
            (start, end)
        } else {
            (0, editor_text.chars().count() as u32)
        };

        match self.text_editor_phase() {
            TextEditorPhase::SelectTarget => {
                self.set_text_editor_phase(TextEditorPhase::ApplyAction);
                inference_tool_call(
                    "browser__select_text",
                    json!({
                        "selector": EDITOR_SELECTOR,
                        "start_offset": start_offset,
                        "end_offset": end_offset,
                    }),
                )
            }
            TextEditorPhase::ApplyAction => {
                self.set_text_editor_phase(TextEditorPhase::Submit);
                self.note_pending_followup("text_editor_apply");
                match action_token.as_str() {
                    "bold" => inference_tool_call(
                        "browser__key",
                        json!({ "key": "b", "modifiers": [primary_browser_modifier()] }),
                    ),
                    "italics" => inference_tool_call(
                        "browser__key",
                        json!({ "key": "i", "modifiers": [primary_browser_modifier()] }),
                    ),
                    "underlined" => inference_tool_call(
                        "browser__key",
                        json!({ "key": "u", "modifiers": [primary_browser_modifier()] }),
                    ),
                    color_name => {
                        let Some(color_value) = text_editor_color_value(color_name) else {
                            return inference_fail(
                                "ERROR_CLASS=ObservationGap text-editor color unsupported",
                            );
                        };
                        inference_tool_call(
                            "browser__select_dropdown",
                            json!({ "selector": COLOR_SELECTOR, "value": color_value }),
                        )
                    }
                }
            }
            TextEditorPhase::Submit => {
                inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
            }
        }
    }

    fn guess_number_action(
        &self,
        bridge_state: &BridgeState,
        elements: &[BridgeInteractiveElement],
        query: &str,
    ) -> Vec<u8> {
        let visible = bridge_visible_content_after_query(bridge_state, query);
        let current_guess = bridge_value_by_selector(elements, "#tt")
            .parse::<i32>()
            .ok();
        let feedback = parse_guess_number_feedback(visible);
        let mut state = self.guess_number_state();

        if let (Some(last_guess), Some(current_guess)) = (state.last_submitted_guess, current_guess)
        {
            if current_guess == last_guess && state.feedback_applied_for != Some(last_guess) {
                match feedback {
                    Some(GuessNumberFeedback::Higher(pivot)) => {
                        state.low = state.low.max(pivot + 1);
                        state.feedback_applied_for = Some(last_guess);
                    }
                    Some(GuessNumberFeedback::Lower(pivot)) => {
                        state.high = state.high.min(pivot - 1);
                        state.feedback_applied_for = Some(last_guess);
                    }
                    _ => {}
                }
            }
        }

        if state.low > state.high {
            return inference_fail("ERROR_CLASS=PlannerGap guess-number bounds invalid");
        }

        let next_guess = ((state.low + state.high) / 2).clamp(0, 9).to_string();
        let next_guess_number = next_guess.parse::<i32>().ok();
        let current_value = bridge_value_by_selector(elements, "#tt");

        match state.input_phase {
            GuessNumberInputPhase::TypeGuess(pending_guess) => {
                if !bridge_focus_matches(bridge_state, "#tt") {
                    self.update_guess_number_state(|current| *current = state);
                    return inference_tool_call("browser__click", json!({ "selector": "#tt" }));
                } else {
                    state.input_phase = GuessNumberInputPhase::SubmitGuess(pending_guess);
                    self.update_guess_number_state(|current| *current = state);
                    return inference_tool_call(
                        "browser__type",
                        json!({ "selector": "#tt", "text": pending_guess.to_string() }),
                    );
                }
            }
            GuessNumberInputPhase::SubmitGuess(pending_guess) => {
                self.update_guess_number_state(|current| {
                    current.last_submitted_guess = Some(pending_guess);
                    current.feedback_applied_for = None;
                    current.input_phase = GuessNumberInputPhase::Idle;
                });
                return if bridge_focus_matches(bridge_state, "#tt") {
                    inference_tool_call("browser__key", json!({ "key": "Enter" }))
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                };
            }
            GuessNumberInputPhase::Idle => {}
        }

        self.update_guess_number_state(|current| *current = state);

        if current_value != next_guess {
            if !bridge_focus_matches(bridge_state, "#tt") {
                return inference_tool_call("browser__click", json!({ "selector": "#tt" }));
            }
            if !current_value.is_empty() {
                self.update_guess_number_state(|current| {
                    current.input_phase = next_guess_number
                        .map(GuessNumberInputPhase::TypeGuess)
                        .unwrap_or_default();
                });
                return inference_tool_call(
                    "browser__key",
                    json!({ "key": "a", "modifiers": [primary_browser_modifier()] }),
                );
            }
            self.update_guess_number_state(|current| {
                current.input_phase = next_guess_number
                    .map(GuessNumberInputPhase::SubmitGuess)
                    .unwrap_or_default();
            });
            return inference_tool_call(
                "browser__type",
                json!({ "selector": "#tt", "text": next_guess }),
            );
        }

        self.update_guess_number_state(|current| {
            current.last_submitted_guess = next_guess_number;
            current.feedback_applied_for = None;
            current.input_phase = GuessNumberInputPhase::Idle;
        });
        if bridge_focus_matches(bridge_state, "#tt") {
            inference_tool_call("browser__key", json!({ "key": "Enter" }))
        } else {
            inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
        }
    }

    fn find_greatest_action(&self, bridge_state: &BridgeState, query: &str) -> Vec<u8> {
        let mut state = self.find_greatest_state();
        if let Some((best_card_index, best_value)) =
            bridge_find_greatest_dom_card(&bridge_state.info.dom_elements)
        {
            let selected_card_index = bridge_state
                .info
                .dom_elements
                .iter()
                .filter(|element| element.visible)
                .filter(|element| bridge_dom_class_contains(element, "card"))
                .filter(|element| !bridge_dom_class_contains(element, "hidden"))
                .find_map(|element| {
                    let selector = element.selector.as_deref()?;
                    selector_nth_of_type_after_prefix(selector, "#cardholder > div:nth-of-type(")
                });
            if selected_card_index == Some(best_card_index) {
                return inference_tool_call("browser__click", json!({ "selector": "#submit" }));
            }
            self.update_find_greatest_state(|current| {
                current.best_card_index = Some(best_card_index);
                current.best_value = best_value;
                current.pending_observation_index = None;
                current.next_probe_index = 4;
                current.revisit_before_submit = false;
            });
            self.note_pending_followup("find_greatest_submit");
            return inference_tool_call(
                "browser__click",
                json!({ "selector": format!("#cardholder > div:nth-of-type({best_card_index})") }),
            );
        }

        if let Some(card_index) = state.pending_observation_index.take() {
            let visible =
                trim_submit_button_suffix(bridge_visible_content_after_query(bridge_state, query));
            let Some(card_value) = parse_first_integer(visible) else {
                return inference_fail("ERROR_CLASS=ObservationGap find-greatest card missing");
            };
            if card_value > state.best_value {
                state.best_value = card_value;
                state.best_card_index = Some(card_index);
            }
        }

        if state.next_probe_index <= 3 {
            let probe_index = state.next_probe_index;
            state.pending_observation_index = Some(probe_index);
            state.next_probe_index += 1;
            self.update_find_greatest_state(|current| *current = state);
            return inference_tool_call(
                "browser__click",
                json!({ "selector": format!("#cardholder .card:nth-of-type({probe_index})") }),
            );
        }

        if state.revisit_before_submit {
            state.revisit_before_submit = false;
            self.update_find_greatest_state(|current| *current = state);
            return inference_tool_call("browser__click", json!({ "selector": "#submit" }));
        }

        let Some(best_card_index) = state.best_card_index else {
            return inference_fail("ERROR_CLASS=ObservationGap find-greatest best card missing");
        };
        self.update_find_greatest_state(|current| {
            current.best_card_index = state.best_card_index;
            current.best_value = state.best_value;
            current.pending_observation_index = None;
            current.next_probe_index = state.next_probe_index;
            current.revisit_before_submit = best_card_index != 3;
        });
        if best_card_index == 3 {
            inference_tool_call("browser__click", json!({ "selector": "#submit" }))
        } else {
            inference_tool_call(
                "browser__click",
                json!({ "selector": format!("#cardholder .card:nth-of-type({best_card_index})") }),
            )
        }
    }

    fn visual_addition_action(&self, bridge_state: &BridgeState) -> Vec<u8> {
        let addend_a = bridge_state
            .info
            .dom_elements
            .iter()
            .filter(|element| element.visible)
            .filter(|element| bridge_dom_class_contains(element, "addition-block"))
            .filter(|element| bridge_dom_selector_starts_with(element, "#visual-1"))
            .count();
        let addend_b = bridge_state
            .info
            .dom_elements
            .iter()
            .filter(|element| element.visible)
            .filter(|element| bridge_dom_class_contains(element, "addition-block"))
            .filter(|element| bridge_dom_selector_starts_with(element, "#visual-2"))
            .count();
        let answer = (addend_a + addend_b).to_string();
        if bridge_value_by_selector(&bridge_state.info.interactive_elements, "#math-answer")
            != answer
        {
            inference_tool_call(
                "browser__type",
                json!({ "selector": "#math-answer", "text": answer }),
            )
        } else {
            inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
        }
    }

    fn identify_shape_action(&self, bridge_state: &BridgeState) -> Vec<u8> {
        let summaries =
            bridge_dom_summaries_with_selector_prefix(&bridge_state.info.dom_elements, "#area_svg");
        let Some(target) = summaries
            .iter()
            .filter(|summary| summary.visible)
            .find_map(svg_shape_kind)
        else {
            return inference_fail("ERROR_CLASS=ObservationGap identify-shape figure missing");
        };
        inference_tool_call(
            "browser__click",
            json!({ "selector": format!("#area-buttons button[data-type='{target}']") }),
        )
    }

    fn count_shape_action(
        &self,
        bridge_state: &BridgeState,
        elements: &[BridgeInteractiveElement],
        query: &str,
    ) -> Vec<u8> {
        let Some(descriptor) = parse_count_shape_descriptor(query) else {
            return inference_fail("ERROR_CLASS=PlannerGap count-shape descriptor missing");
        };
        let summaries =
            bridge_dom_summaries_with_selector_prefix(&bridge_state.info.dom_elements, "#area_svg");
        let count = count_shape_matches(&summaries, &descriptor);
        bridge_selector_for_label(elements, &count.to_string())
            .map(|selector| inference_tool_call("browser__click", json!({ "selector": selector })))
            .unwrap_or_else(|| {
                inference_fail("ERROR_CLASS=ObservationGap count-shape answer button missing")
            })
    }

    fn count_sides_action(&self, elements: &[BridgeInteractiveElement]) -> Vec<u8> {
        if let Some(estimated_sides) = self.take_count_sides_estimate() {
            let label = estimated_sides.to_string();
            return bridge_selector_for_label(elements, &label)
                .map(|selector| {
                    inference_tool_call("browser__click", json!({ "selector": selector }))
                })
                .unwrap_or_else(|| {
                    inference_fail("ERROR_CLASS=ObservationGap count-sides answer button missing")
                });
        }

        inference_tool_call("browser__canvas_summary", json!({ "selector": "#c" }))
    }

    fn find_midpoint_action(&self, bridge_state: &BridgeState) -> Vec<u8> {
        let blue_circle_present =
            bridge_state.info.dom_elements.iter().any(|element| {
                element.visible && element.selector.as_deref() == Some("#blue-circle")
            });
        if blue_circle_present {
            return inference_tool_call("browser__click", json!({ "selector": "#subbtn" }));
        }

        let circles = bridge_state
            .info
            .dom_elements
            .iter()
            .filter(|element| element.visible)
            .filter(|element| element.tag == "circle")
            .filter(|element| bridge_dom_class_contains(element, "black-circle"))
            .collect::<Vec<_>>();
        if circles.len() != 2 {
            return inference_fail("ERROR_CLASS=ObservationGap find-midpoint circles missing");
        }
        let midpoint = if let (Some(point_a_x), Some(point_a_y), Some(point_b_x), Some(point_b_y)) = (
            bridge_dom_numeric_attribute(circles[0], "cx"),
            bridge_dom_numeric_attribute(circles[0], "cy"),
            bridge_dom_numeric_attribute(circles[1], "cx"),
            bridge_dom_numeric_attribute(circles[1], "cy"),
        ) {
            let query_offset_y = bridge_state
                .info
                .dom_elements
                .iter()
                .find(|element| element.selector.as_deref() == Some("#query"))
                .map(|element| element.height)
                .unwrap_or(50.0);
            (
                (point_a_x + point_b_x) / 2.0,
                ((point_a_y + point_b_y) / 2.0) + query_offset_y,
            )
        } else {
            (
                (circles[0].center_x + circles[1].center_x) / 2.0,
                (circles[0].center_y + circles[1].center_y) / 2.0,
            )
        };
        self.note_pending_followup("find_midpoint_wait");
        inference_tool_call(
            "browser__synthetic_click",
            json!({ "x": midpoint.0, "y": midpoint.1 }),
        )
    }

    fn social_media_action(&self, bridge_state: &BridgeState, query: &str) -> Vec<u8> {
        let visible = bridge_visible_content_after_query(bridge_state, query);
        if let Some(pending) = self.take_pending_social_media_menu_action() {
            return inference_tool_call(
                "browser__click",
                json!({
                    "selector": format!(
                        "#area .media:nth-of-type({}) ul:not(.hide) .{}",
                        pending.row_index, pending.action_class
                    )
                }),
            );
        }

        let target_user = parse_social_media_user(query).unwrap_or_default();
        let button_label = parse_social_media_button(query).unwrap_or_default();
        let Some((action_class, requires_menu)) = social_media_action_class(&button_label) else {
            return inference_fail("ERROR_CLASS=PlannerGap social-media action unsupported");
        };
        let Some(row_index) = social_media_matching_rows(visible, &target_user)
            .into_iter()
            .next()
        else {
            return inference_fail("ERROR_CLASS=ObservationGap social-media user missing");
        };

        if requires_menu {
            self.note_pending_social_media_menu_action(row_index, action_class);
            inference_tool_call(
                "browser__click",
                json!({ "selector": format!("#area .media:nth-of-type({row_index}) .more") }),
            )
        } else {
            inference_tool_call(
                "browser__click",
                json!({ "selector": format!("#area .media:nth-of-type({row_index}) .{action_class}") }),
            )
        }
    }

    fn social_media_multi_action(
        &self,
        visible: &str,
        query: &str,
        stage: usize,
        required_count: Option<usize>,
    ) -> Vec<u8> {
        let target_user = parse_social_media_user(query).unwrap_or_default();
        let button_label = parse_social_media_button(query).unwrap_or_default();
        let Some((action_class, requires_menu)) = social_media_action_class(&button_label) else {
            return inference_fail("ERROR_CLASS=PlannerGap social-media action unsupported");
        };
        if requires_menu {
            return inference_fail("ERROR_CLASS=PlannerGap social-media menu action unsupported");
        }
        let rows = social_media_matching_rows(visible, &target_user);
        let expected_count = required_count.unwrap_or(rows.len());
        if rows.len() < expected_count {
            return inference_fail("ERROR_CLASS=ObservationGap social-media rows missing");
        }
        if stage < expected_count {
            let row_index = rows[stage];
            inference_tool_call(
                "browser__click",
                json!({ "selector": format!("#area .media:nth-of-type({row_index}) .{action_class}") }),
            )
        } else {
            inference_tool_call("browser__click", json!({ "selector": "#submitRow button" }))
        }
    }

    fn stock_market_action(&self, bridge_state: &BridgeState, query: &str) -> Vec<u8> {
        let threshold = parse_stock_market_threshold(query).unwrap_or(f64::MAX);
        let current_price =
            parse_stock_market_visible_price(bridge_visible_text_excerpt(bridge_state));
        if bridge_state.info.focused_id.as_deref() != Some("buy") {
            return inference_tool_call("browser__key", json!({ "key": "Tab" }));
        }
        if current_price.is_some_and(|price| price <= threshold) {
            inference_tool_call("browser__key", json!({ "key": "Enter" }))
        } else {
            inference_tool_call("browser__wait", json!({ "ms": 100 }))
        }
    }

    fn email_inbox_action(
        &self,
        bridge_state: &BridgeState,
        elements: &[BridgeInteractiveElement],
        query: &str,
    ) -> Vec<u8> {
        let sender = email_inbox_sender_value(bridge_state, query).unwrap_or_default();
        let Some(action) = email_inbox_action_value(bridge_state, query) else {
            return inference_fail("ERROR_CLASS=PlannerGap email-inbox action missing");
        };
        let forward_input_selector = "#forward .forward-sender";
        let forward_input = elements.iter().find(|element| {
            element.visible
                && element
                    .class_list
                    .iter()
                    .any(|class_name| class_name == "forward-sender")
        });

        if bridge_element_by_selector(elements, "#reply-text")
            .is_some_and(|element| element.visible)
        {
            let reply_text = email_inbox_reply_value(bridge_state, query).unwrap_or_default();
            if let Some(action) =
                self.fill_text_field_if_needed(bridge_state, elements, "#reply-text", &reply_text)
            {
                return action;
            }
            return inference_tool_call("browser__click", json!({ "selector": "#send-reply" }));
        }

        if let Some(element) = forward_input {
            let recipient = email_inbox_forward_value(bridge_state, query).unwrap_or_default();
            if element.value.as_deref().unwrap_or_default() != recipient {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": forward_input_selector, "text": recipient }),
                );
            }
            return inference_tool_call("browser__click", json!({ "selector": "#send-forward" }));
        }

        let search_open = bridge_element_by_selector(elements, "#search-input")
            .map(|element| element.visible)
            .unwrap_or(false);
        if search_open {
            if let Some(action) =
                self.fill_text_field_if_needed(bridge_state, elements, "#search-input", &sender)
            {
                return action;
            }
            return match action {
                "delete" | "important" | "reply" | "forward" => {
                    self.note_pending_followup("email_open");
                    inference_tool_call(
                        "browser__click",
                        json!({ "selector": "#search .email-thread" }),
                    )
                }
                _ => inference_fail("ERROR_CLASS=PlannerGap email-inbox action unsupported"),
            };
        }

        let visible = normalize_label(bridge_visible_content_after_query(bridge_state, query));
        if visible.contains("to me") {
            return match action {
                "delete" => {
                    inference_tool_call("browser__click", json!({ "selector": "#email .trash" }))
                }
                "important" => {
                    inference_tool_call("browser__click", json!({ "selector": "#email .star" }))
                }
                "reply" | "forward" => {
                    self.note_pending_followup("email_compose");
                    let selector = if action == "reply" {
                        "#email .email-reply"
                    } else {
                        "#email .email-forward"
                    };
                    inference_tool_call("browser__click", json!({ "selector": selector }))
                }
                _ => inference_fail("ERROR_CLASS=PlannerGap email-inbox action unsupported"),
            };
        }

        inference_tool_call("browser__click", json!({ "selector": "#open-search" }))
    }

    fn workflow_ticket_routing_action(
        &self,
        bridge_state: &BridgeState,
        elements: &[BridgeInteractiveElement],
    ) -> Vec<u8> {
        let Some(username) = workflow_target_username(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow username missing");
        };
        let Some(password) = workflow_target_password(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow password missing");
        };
        let Some(ticket_id) = workflow_target_ticket_id(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow ticket id missing");
        };
        let Some(assignee) = workflow_target_assignee(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow assignee missing");
        };
        let Some(note) = workflow_target_note(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow note missing");
        };
        let page_url = bridge_state.info.page_url.as_deref().unwrap_or_default();

        if page_url.contains("/login") {
            if bridge_value_by_selector(elements, "#username") != username {
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#username", "text": username }),
                );
            }
            if bridge_value_by_selector(elements, "#password") != password {
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#password", "text": password }),
                );
            }
            return inference_tool_call("browser__click", json!({ "selector": "#sign-in" }));
        }

        if page_url.contains("/queue") {
            let selector = workflow_ticket_link_selector(&ticket_id);
            if bridge_element_by_selector(elements, &selector).is_none() {
                return inference_wait(120);
            }
            return inference_tool_call("browser__click", json!({ "selector": selector }));
        }

        if page_url.contains("/tickets/") {
            if !bridge_selected_contains(elements, "#assignee", &assignee) {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__select_dropdown",
                    json!({ "selector": "#assignee", "label": assignee }),
                );
            }
            if bridge_value_by_selector(elements, "#note") != note {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#note", "text": note }),
                );
            }
            return inference_tool_call("browser__click", json!({ "selector": "#submit-update" }));
        }

        if page_url.contains("/confirmation") {
            return inference_wait(100);
        }

        inference_wait(120)
    }

    fn workflow_queue_verification_action(
        &self,
        bridge_state: &BridgeState,
        elements: &[BridgeInteractiveElement],
    ) -> Vec<u8> {
        let Some(username) = workflow_target_username(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow username missing");
        };
        let Some(password) = workflow_target_password(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow password missing");
        };
        let Some(ticket_id) = workflow_target_ticket_id(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow ticket id missing");
        };
        let Some(assignee) = workflow_target_assignee(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow assignee missing");
        };
        let Some(status) = workflow_target_status(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow status missing");
        };
        let Some(note) = workflow_target_note(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow note missing");
        };
        let Some(queue_search) = workflow_target_queue_search(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow queue search missing");
        };
        let Some(queue_filter) = workflow_target_queue_status_filter(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow queue filter missing");
        };
        let page_url = bridge_state.info.page_url.as_deref().unwrap_or_default();

        if page_url.contains("/login") {
            if bridge_value_by_selector(elements, "#username") != username {
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#username", "text": username }),
                );
            }
            if bridge_value_by_selector(elements, "#password") != password {
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#password", "text": password }),
                );
            }
            return inference_tool_call("browser__click", json!({ "selector": "#sign-in" }));
        }

        if page_url.contains("/queue") {
            if workflow_field_is_true(bridge_state, "confirmation_seen") {
                if workflow_field_is_true(bridge_state, "queue_verified") {
                    return inference_wait(120);
                }
                if !bridge_selected_contains(elements, "#queue-status-filter", &status) {
                    self.note_pending_followup("form_type");
                    return inference_tool_call(
                        "browser__select_dropdown",
                        json!({ "selector": "#queue-status-filter", "label": status }),
                    );
                }
                let selector = workflow_ticket_link_selector(&ticket_id);
                if bridge_element_by_selector(elements, &selector).is_none() {
                    return inference_tool_call(
                        "browser__click",
                        json!({ "selector": "#apply-filters" }),
                    );
                }
                return inference_wait(120);
            }
            if bridge_value_by_selector(elements, "#queue-search") != queue_search {
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#queue-search", "text": queue_search }),
                );
            }
            if !bridge_selected_contains(elements, "#queue-status-filter", &queue_filter) {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__select_dropdown",
                    json!({ "selector": "#queue-status-filter", "label": queue_filter }),
                );
            }
            let selector = workflow_ticket_link_selector(&ticket_id);
            if bridge_element_by_selector(elements, &selector).is_none() {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#apply-filters" }),
                );
            }
            return inference_tool_call("browser__click", json!({ "selector": selector }));
        }

        if page_url.contains("/tickets/") {
            if workflow_active_ticket_id(bridge_state).as_deref() != Some(ticket_id.as_str()) {
                return inference_tool_call("browser__click", json!({ "selector": "#queue-link" }));
            }
            if !bridge_selected_contains(elements, "#assignee", &assignee) {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__select_dropdown",
                    json!({ "selector": "#assignee", "label": assignee }),
                );
            }
            if !bridge_selected_contains(elements, "#status", &status) {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__select_dropdown",
                    json!({ "selector": "#status", "label": status }),
                );
            }
            if bridge_value_by_selector(elements, "#note") != note {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#note", "text": note }),
                );
            }
            return inference_tool_call("browser__click", json!({ "selector": "#review-update" }));
        }

        if page_url.contains("/review") {
            if workflow_active_ticket_id(bridge_state).as_deref() != Some(ticket_id.as_str()) {
                return inference_tool_call("browser__click", json!({ "selector": "#queue-link" }));
            }
            if workflow_field_value(bridge_state, "current_assignee").as_deref()
                != Some(assignee.as_str())
            {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#edit-update" }),
                );
            }
            if workflow_field_value(bridge_state, "current_status").as_deref()
                != Some(status.as_str())
            {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#edit-update" }),
                );
            }
            if workflow_field_value(bridge_state, "current_note").as_deref() != Some(note.as_str())
            {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#edit-update" }),
                );
            }
            return inference_tool_call("browser__click", json!({ "selector": "#confirm-update" }));
        }

        if page_url.contains("/confirmation") {
            if workflow_field_is_true(bridge_state, "queue_verified") {
                return inference_wait(100);
            }
            return inference_tool_call("browser__click", json!({ "selector": "#queue-link" }));
        }

        inference_wait(120)
    }

    fn workflow_audit_history_action(
        &self,
        bridge_state: &BridgeState,
        elements: &[BridgeInteractiveElement],
    ) -> Vec<u8> {
        let Some(username) = workflow_target_username(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow username missing");
        };
        let Some(password) = workflow_target_password(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow password missing");
        };
        let Some(ticket_id) = workflow_target_ticket_id(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow ticket id missing");
        };
        let Some(assignee) = workflow_target_assignee(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow assignee missing");
        };
        let Some(status) = workflow_target_status(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow status missing");
        };
        let Some(note) = workflow_target_note(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow note missing");
        };
        let Some(queue_search) = workflow_target_queue_search(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow queue search missing");
        };
        let Some(queue_filter) = workflow_target_queue_status_filter(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow queue filter missing");
        };
        let page_url = bridge_state.info.page_url.as_deref().unwrap_or_default();

        if page_url.contains("/login") {
            if bridge_value_by_selector(elements, "#username") != username {
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#username", "text": username }),
                );
            }
            if bridge_value_by_selector(elements, "#password") != password {
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#password", "text": password }),
                );
            }
            return inference_tool_call("browser__click", json!({ "selector": "#sign-in" }));
        }

        if page_url.contains("/queue") {
            if bridge_value_by_selector(elements, "#queue-search") != queue_search {
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#queue-search", "text": queue_search }),
                );
            }
            if !bridge_selected_contains(elements, "#queue-status-filter", &queue_filter) {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__select_dropdown",
                    json!({ "selector": "#queue-status-filter", "label": queue_filter }),
                );
            }
            let selector = workflow_ticket_link_selector(&ticket_id);
            if bridge_element_by_selector(elements, &selector).is_none() {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#apply-filters" }),
                );
            }
            return inference_tool_call("browser__click", json!({ "selector": selector }));
        }

        if page_url.contains("/history") {
            if workflow_field_is_true(bridge_state, "history_verified") {
                return inference_wait(100);
            }
            if workflow_active_ticket_id(bridge_state).as_deref() != Some(ticket_id.as_str()) {
                return inference_tool_call("browser__click", json!({ "selector": "#queue-link" }));
            }
            if workflow_history_event_matches(
                bridge_state,
                &ticket_id,
                &username,
                &assignee,
                &status,
                &note,
            ) {
                return inference_wait(120);
            }
            return inference_tool_call("browser__click", json!({ "selector": "#reopen-ticket" }));
        }

        if page_url.contains("/tickets/") {
            if workflow_active_ticket_id(bridge_state).as_deref() != Some(ticket_id.as_str()) {
                return inference_tool_call("browser__click", json!({ "selector": "#queue-link" }));
            }
            if !bridge_selected_contains(elements, "#assignee", &assignee) {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__select_dropdown",
                    json!({ "selector": "#assignee", "label": assignee }),
                );
            }
            if !bridge_selected_contains(elements, "#status", &status) {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__select_dropdown",
                    json!({ "selector": "#status", "label": status }),
                );
            }
            if bridge_value_by_selector(elements, "#note") != note {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#note", "text": note }),
                );
            }
            return inference_tool_call("browser__click", json!({ "selector": "#review-update" }));
        }

        if page_url.contains("/review") {
            if workflow_active_ticket_id(bridge_state).as_deref() != Some(ticket_id.as_str()) {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#cancel-update" }),
                );
            }
            if workflow_field_value(bridge_state, "current_assignee").as_deref()
                != Some(assignee.as_str())
            {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#cancel-update" }),
                );
            }
            if workflow_field_value(bridge_state, "current_status").as_deref()
                != Some(status.as_str())
            {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#cancel-update" }),
                );
            }
            if workflow_field_value(bridge_state, "current_note").as_deref() != Some(note.as_str())
            {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#cancel-update" }),
                );
            }
            return inference_tool_call("browser__click", json!({ "selector": "#confirm-update" }));
        }

        if page_url.contains("/confirmation") {
            if workflow_field_is_true(bridge_state, "history_verified") {
                return inference_wait(100);
            }
            if workflow_field_value(bridge_state, "saved_assignee").as_deref()
                != Some(assignee.as_str())
                || workflow_field_value(bridge_state, "saved_status").as_deref()
                    != Some(status.as_str())
                || workflow_field_value(bridge_state, "saved_note").as_deref()
                    != Some(note.as_str())
            {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#reopen-ticket" }),
                );
            }
            return inference_tool_call("browser__click", json!({ "selector": "#history-link" }));
        }

        inference_wait(120)
    }

    fn workflow_mutation_isolation_action(
        &self,
        bridge_state: &BridgeState,
        elements: &[BridgeInteractiveElement],
    ) -> Vec<u8> {
        let Some(username) = workflow_target_username(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow username missing");
        };
        let Some(password) = workflow_target_password(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow password missing");
        };
        let Some(ticket_id) = workflow_target_ticket_id(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow ticket id missing");
        };
        let Some(assignee) = workflow_target_assignee(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow assignee missing");
        };
        let Some(status) = workflow_target_status(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow status missing");
        };
        let Some(note) = workflow_target_note(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow note missing");
        };
        let Some(queue_search) = workflow_target_queue_search(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow queue search missing");
        };
        let Some(queue_filter) = workflow_target_queue_status_filter(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow queue filter missing");
        };
        let Some(distractor_ticket_id) = workflow_target_distractor_ticket_id(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow distractor ticket missing");
        };
        let page_url = bridge_state.info.page_url.as_deref().unwrap_or_default();

        if page_url.contains("/login") {
            if bridge_value_by_selector(elements, "#username") != username {
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#username", "text": username }),
                );
            }
            if bridge_value_by_selector(elements, "#password") != password {
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#password", "text": password }),
                );
            }
            return inference_tool_call("browser__click", json!({ "selector": "#sign-in" }));
        }

        if page_url.contains("/queue") {
            if bridge_value_by_selector(elements, "#queue-search") != queue_search {
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#queue-search", "text": queue_search }),
                );
            }
            if !bridge_selected_contains(elements, "#queue-status-filter", &queue_filter) {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__select_dropdown",
                    json!({ "selector": "#queue-status-filter", "label": queue_filter }),
                );
            }

            let target_selector = workflow_ticket_link_selector(&ticket_id);
            let target_history_selector = workflow_ticket_history_link_selector(&ticket_id);
            let distractor_history_selector =
                workflow_ticket_history_link_selector(&distractor_ticket_id);

            if !workflow_field_is_true(bridge_state, "confirmation_seen") {
                if bridge_element_by_selector(elements, &target_selector).is_none() {
                    return inference_tool_call(
                        "browser__click",
                        json!({ "selector": "#apply-filters" }),
                    );
                }
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": target_selector }),
                );
            }

            if !workflow_field_is_true(bridge_state, "queue_verified") {
                if bridge_element_by_selector(elements, &target_selector).is_none()
                    || bridge_element_by_selector(elements, &distractor_history_selector).is_none()
                {
                    return inference_tool_call(
                        "browser__click",
                        json!({ "selector": "#apply-filters" }),
                    );
                }
                if workflow_field_is_true(bridge_state, "saved_target_matches")
                    && workflow_field_is_true(bridge_state, "saved_distractor_matches")
                {
                    return inference_wait(120);
                }
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#apply-filters" }),
                );
            }

            if !workflow_field_is_true(bridge_state, "history_verified") {
                if bridge_element_by_selector(elements, &target_history_selector).is_none() {
                    return inference_tool_call(
                        "browser__click",
                        json!({ "selector": "#apply-filters" }),
                    );
                }
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": target_history_selector }),
                );
            }

            if !workflow_field_is_true(bridge_state, "distractor_history_verified") {
                if bridge_element_by_selector(elements, &distractor_history_selector).is_none() {
                    return inference_tool_call(
                        "browser__click",
                        json!({ "selector": "#apply-filters" }),
                    );
                }
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": distractor_history_selector }),
                );
            }

            return inference_wait(100);
        }

        if page_url.contains("/history") {
            let active_ticket = workflow_active_ticket_id(bridge_state).unwrap_or_default();
            if active_ticket == ticket_id {
                if workflow_field_is_true(bridge_state, "history_verified") {
                    if workflow_field_is_true(bridge_state, "distractor_history_verified") {
                        return inference_wait(100);
                    }
                    return inference_tool_call(
                        "browser__click",
                        json!({ "selector": "#queue-link" }),
                    );
                }
                if workflow_history_event_matches(
                    bridge_state,
                    &ticket_id,
                    &username,
                    &assignee,
                    &status,
                    &note,
                ) {
                    return inference_wait(120);
                }
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#reopen-ticket" }),
                );
            }

            if active_ticket == distractor_ticket_id {
                if workflow_field_is_true(bridge_state, "distractor_history_verified") {
                    return inference_wait(100);
                }
                if workflow_field_is_true(bridge_state, "distractor_saved_update_exists") {
                    return inference_tool_call(
                        "browser__click",
                        json!({ "selector": "#queue-link" }),
                    );
                }
                return inference_wait(120);
            }

            return inference_tool_call("browser__click", json!({ "selector": "#queue-link" }));
        }

        if page_url.contains("/tickets/") {
            if workflow_active_ticket_id(bridge_state).as_deref() != Some(ticket_id.as_str()) {
                return inference_tool_call("browser__click", json!({ "selector": "#queue-link" }));
            }
            if !bridge_selected_contains(elements, "#assignee", &assignee) {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__select_dropdown",
                    json!({ "selector": "#assignee", "label": assignee }),
                );
            }
            if !bridge_selected_contains(elements, "#status", &status) {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__select_dropdown",
                    json!({ "selector": "#status", "label": status }),
                );
            }
            if bridge_value_by_selector(elements, "#note") != note {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#note", "text": note }),
                );
            }
            return inference_tool_call("browser__click", json!({ "selector": "#review-update" }));
        }

        if page_url.contains("/review") {
            if workflow_active_ticket_id(bridge_state).as_deref() != Some(ticket_id.as_str()) {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#cancel-update" }),
                );
            }
            if workflow_field_value(bridge_state, "current_assignee").as_deref()
                != Some(assignee.as_str())
            {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#cancel-update" }),
                );
            }
            if workflow_field_value(bridge_state, "current_status").as_deref()
                != Some(status.as_str())
            {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#cancel-update" }),
                );
            }
            if workflow_field_value(bridge_state, "current_note").as_deref() != Some(note.as_str())
            {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#cancel-update" }),
                );
            }
            return inference_tool_call("browser__click", json!({ "selector": "#confirm-update" }));
        }

        if page_url.contains("/confirmation") {
            if workflow_active_ticket_id(bridge_state).as_deref() != Some(ticket_id.as_str()) {
                return inference_tool_call("browser__click", json!({ "selector": "#queue-link" }));
            }
            if !workflow_field_is_true(bridge_state, "saved_target_matches") {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#reopen-ticket" }),
                );
            }
            if !workflow_field_is_true(bridge_state, "saved_distractor_matches") {
                return inference_tool_call("browser__click", json!({ "selector": "#queue-link" }));
            }
            if !workflow_field_is_true(bridge_state, "queue_verified") {
                return inference_tool_call("browser__click", json!({ "selector": "#queue-link" }));
            }
            if !workflow_field_is_true(bridge_state, "history_verified") {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#history-link" }),
                );
            }
            if !workflow_field_is_true(bridge_state, "distractor_history_verified") {
                return inference_tool_call("browser__click", json!({ "selector": "#queue-link" }));
            }
            return inference_wait(100);
        }

        inference_wait(120)
    }

    fn workflow_stale_queue_reorder_action(
        &self,
        bridge_state: &BridgeState,
        elements: &[BridgeInteractiveElement],
    ) -> Vec<u8> {
        let Some(username) = workflow_target_username(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow username missing");
        };
        let Some(password) = workflow_target_password(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow password missing");
        };
        let Some(ticket_id) = workflow_target_ticket_id(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow ticket id missing");
        };
        let Some(assignee) = workflow_target_assignee(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow assignee missing");
        };
        let Some(status) = workflow_target_status(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow status missing");
        };
        let Some(note) = workflow_target_note(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow note missing");
        };
        let Some(queue_search) = workflow_target_queue_search(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow queue search missing");
        };
        let Some(queue_filter) = workflow_target_queue_status_filter(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow queue filter missing");
        };
        let Some(initial_queue_sort) = workflow_target_queue_sort(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow queue sort missing");
        };
        let Some(post_confirm_queue_sort) = workflow_target_post_confirm_queue_sort(bridge_state)
        else {
            return inference_fail(
                "ERROR_CLASS=ObservationGap workflow post-confirm queue sort missing",
            );
        };
        let Some(distractor_ticket_id) = workflow_target_distractor_ticket_id(bridge_state) else {
            return inference_fail("ERROR_CLASS=ObservationGap workflow distractor ticket missing");
        };
        let page_url = bridge_state.info.page_url.as_deref().unwrap_or_default();

        if page_url.contains("/login") {
            if bridge_value_by_selector(elements, "#username") != username {
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#username", "text": username }),
                );
            }
            if bridge_value_by_selector(elements, "#password") != password {
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#password", "text": password }),
                );
            }
            return inference_tool_call("browser__click", json!({ "selector": "#sign-in" }));
        }

        if page_url.contains("/queue") {
            if bridge_value_by_selector(elements, "#queue-search") != queue_search {
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#queue-search", "text": queue_search }),
                );
            }
            if !bridge_selected_contains(elements, "#queue-status-filter", &queue_filter) {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__select_dropdown",
                    json!({ "selector": "#queue-status-filter", "label": queue_filter }),
                );
            }

            let target_selector = workflow_ticket_link_selector(&ticket_id);
            let distractor_history_selector =
                workflow_ticket_history_link_selector(&distractor_ticket_id);
            let expected_sort = if workflow_field_is_true(bridge_state, "confirmation_seen") {
                post_confirm_queue_sort.as_str()
            } else {
                initial_queue_sort.as_str()
            };

            if !bridge_selected_contains(elements, "#queue-sort", expected_sort) {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__select_dropdown",
                    json!({ "selector": "#queue-sort", "label": expected_sort }),
                );
            }

            if !workflow_field_is_true(bridge_state, "confirmation_seen") {
                if bridge_element_by_selector(elements, &target_selector).is_none() {
                    return inference_tool_call(
                        "browser__click",
                        json!({ "selector": "#apply-filters" }),
                    );
                }
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": target_selector }),
                );
            }

            if !workflow_field_is_true(bridge_state, "queue_view_fresh") {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#apply-filters" }),
                );
            }

            if !workflow_field_is_true(bridge_state, "queue_verified") {
                if bridge_element_by_selector(elements, &target_selector).is_none()
                    || bridge_element_by_selector(elements, &distractor_history_selector).is_none()
                {
                    return inference_tool_call(
                        "browser__click",
                        json!({ "selector": "#apply-filters" }),
                    );
                }
                if workflow_field_is_true(bridge_state, "saved_target_matches")
                    && workflow_field_is_true(bridge_state, "saved_distractor_matches")
                    && workflow_field_is_true(bridge_state, "queue_target_precedes_distractor")
                {
                    return inference_wait(120);
                }
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#apply-filters" }),
                );
            }

            if !workflow_field_is_true(bridge_state, "distractor_history_verified") {
                if bridge_element_by_selector(elements, &distractor_history_selector).is_none() {
                    return inference_tool_call(
                        "browser__click",
                        json!({ "selector": "#apply-filters" }),
                    );
                }
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": distractor_history_selector }),
                );
            }

            return inference_wait(100);
        }

        if page_url.contains("/history") {
            let active_ticket = workflow_active_ticket_id(bridge_state).unwrap_or_default();
            if active_ticket == distractor_ticket_id {
                if workflow_field_is_true(bridge_state, "distractor_history_verified") {
                    return inference_wait(100);
                }
                if workflow_field_is_true(bridge_state, "distractor_saved_update_exists") {
                    return inference_tool_call(
                        "browser__click",
                        json!({ "selector": "#queue-link" }),
                    );
                }
                return inference_wait(120);
            }
            return inference_tool_call("browser__click", json!({ "selector": "#queue-link" }));
        }

        if page_url.contains("/tickets/") {
            if workflow_active_ticket_id(bridge_state).as_deref() != Some(ticket_id.as_str()) {
                return inference_tool_call("browser__click", json!({ "selector": "#queue-link" }));
            }
            if !bridge_selected_contains(elements, "#assignee", &assignee) {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__select_dropdown",
                    json!({ "selector": "#assignee", "label": assignee }),
                );
            }
            if !bridge_selected_contains(elements, "#status", &status) {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__select_dropdown",
                    json!({ "selector": "#status", "label": status }),
                );
            }
            if bridge_value_by_selector(elements, "#note") != note {
                self.note_pending_followup("form_type");
                return inference_tool_call(
                    "browser__type",
                    json!({ "selector": "#note", "text": note }),
                );
            }
            return inference_tool_call("browser__click", json!({ "selector": "#review-update" }));
        }

        if page_url.contains("/review") {
            if workflow_active_ticket_id(bridge_state).as_deref() != Some(ticket_id.as_str()) {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#cancel-update" }),
                );
            }
            if workflow_field_value(bridge_state, "current_assignee").as_deref()
                != Some(assignee.as_str())
            {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#cancel-update" }),
                );
            }
            if workflow_field_value(bridge_state, "current_status").as_deref()
                != Some(status.as_str())
            {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#cancel-update" }),
                );
            }
            if workflow_field_value(bridge_state, "current_note").as_deref() != Some(note.as_str())
            {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#cancel-update" }),
                );
            }
            return inference_tool_call("browser__click", json!({ "selector": "#confirm-update" }));
        }

        if page_url.contains("/confirmation") {
            if workflow_active_ticket_id(bridge_state).as_deref() != Some(ticket_id.as_str()) {
                return inference_tool_call("browser__click", json!({ "selector": "#queue-link" }));
            }
            if !workflow_field_is_true(bridge_state, "saved_target_matches") {
                return inference_tool_call(
                    "browser__click",
                    json!({ "selector": "#reopen-ticket" }),
                );
            }
            if !workflow_field_is_true(bridge_state, "saved_distractor_matches") {
                return inference_tool_call("browser__click", json!({ "selector": "#queue-link" }));
            }
            if !workflow_field_is_true(bridge_state, "queue_verified") {
                return inference_tool_call("browser__click", json!({ "selector": "#queue-link" }));
            }
            if !workflow_field_is_true(bridge_state, "distractor_history_verified") {
                return inference_tool_call("browser__click", json!({ "selector": "#queue-link" }));
            }
            return inference_wait(100);
        }

        inference_wait(120)
    }

    pub(super) fn hover_shape_recovery_action(&self, system_prompt: &str) -> Vec<u8> {
        let phase = self.hover_shape_phase();
        let candidates = match phase.as_deref() {
            Some("await_post_wait_1") => vec![
                ("browser__hover", json!({ "selector": "#highlight" })),
                ("browser__wait", json!({ "ms": 1450 })),
            ],
            Some("await_post_wait_2") => vec![
                ("browser__hover", json!({ "selector": "#highlight" })),
                ("browser__wait", json!({ "ms": 1450 })),
            ],
            Some("await_post_hover_2") | Some("retry_hover_2_after_wait") => vec![
                ("browser__wait", json!({ "ms": 1300 })),
                ("browser__wait", json!({ "ms": 1450 })),
                ("browser__hover", json!({ "selector": "#highlight" })),
            ],
            Some("await_post_hover_3") | Some("retry_hover_3_after_wait") => vec![
                ("browser__wait", json!({ "ms": 1300 })),
                ("browser__wait", json!({ "ms": 1450 })),
                ("browser__hover", json!({ "selector": "#highlight" })),
            ],
            Some("complete") => return inference_tool_call("agent__complete", json!({})),
            _ => vec![
                ("browser__wait", json!({ "ms": 1300 })),
                ("browser__wait", json!({ "ms": 1450 })),
                ("browser__hover", json!({ "selector": "#highlight" })),
            ],
        };
        if let Some((name, arguments)) =
            pick_incident_recovery_candidate(system_prompt, &candidates)
        {
            match (phase.as_deref(), name.as_str()) {
                (Some("await_post_wait_1"), "browser__hover") => {
                    self.note_hover_shape_phase("await_post_hover_2");
                }
                (Some("await_post_wait_2"), "browser__hover") => {
                    self.note_hover_shape_phase("await_post_hover_3");
                }
                (
                    Some("await_post_hover_2") | Some("retry_hover_2_after_wait"),
                    "browser__wait",
                ) => {
                    self.note_hover_shape_phase("retry_hover_2_after_wait");
                }
                (
                    Some("await_post_hover_2") | Some("retry_hover_2_after_wait"),
                    "browser__hover",
                ) => {
                    self.note_hover_shape_phase("await_post_hover_2");
                }
                (
                    Some("await_post_hover_3") | Some("retry_hover_3_after_wait"),
                    "browser__wait",
                ) => {
                    self.note_hover_shape_phase("retry_hover_3_after_wait");
                }
                (
                    Some("await_post_hover_3") | Some("retry_hover_3_after_wait"),
                    "browser__hover",
                ) => {
                    self.note_hover_shape_phase("await_post_hover_3");
                }
                (_, "browser__wait") => {
                    self.note_hover_shape_phase("retry_hover_1_after_wait");
                }
                (_, "browser__hover") => {
                    self.note_hover_shape_phase("await_post_hover_1");
                }
                _ => {}
            }
            return inference_tool_call(&name, arguments);
        }

        self.recovery_tool_or_safe_fallback(system_prompt, &candidates)
    }

    fn recovery_tool_or_safe_fallback(
        &self,
        system_prompt: &str,
        candidates: &[(&str, Value)],
    ) -> Vec<u8> {
        if let Some(tool) = pick_incident_recovery_tool(system_prompt, candidates) {
            return tool;
        }

        let visited_len = incident_visited_fingerprints(system_prompt).len() as u64;
        let wait_base = 125 + (visited_len * 37);
        for ms in [wait_base, wait_base + 43, wait_base + 89] {
            let wait_candidate = [("browser__wait", json!({ "ms": ms }))];
            if let Some(tool) = pick_incident_recovery_tool(system_prompt, &wait_candidate) {
                return tool;
            }
        }

        let navigate_candidate = [("browser__navigate", json!({ "url": self.url }))];
        if let Some(tool) = pick_incident_recovery_tool(system_prompt, &navigate_candidate) {
            return tool;
        }

        inference_wait(wait_base)
    }

    pub(super) fn recovery_action(
        &self,
        bridge_state: &BridgeState,
        system_prompt: &str,
    ) -> Vec<u8> {
        match self.case.recipe {
            RecipeId::LoginUserPopup => {
                if bridge_element_by_selector(
                    &bridge_state.info.interactive_elements,
                    "#popup-cancel",
                )
                .is_some_and(|element| element.visible && !element.disabled)
                {
                    return self.recovery_tool_or_safe_fallback(
                        system_prompt,
                        &[
                            ("browser__click", json!({ "selector": "#popup-cancel" })),
                            ("browser__key", json!({ "key": "Escape" })),
                            ("browser__wait", json!({ "ms": 120 })),
                        ],
                    );
                }

                self.recovery_tool_or_safe_fallback(
                    system_prompt,
                    &[
                        ("browser__wait", json!({ "ms": 120 })),
                        ("browser__click", json!({ "selector": "#username" })),
                        ("browser__click", json!({ "selector": "#password" })),
                    ],
                )
            }
            RecipeId::ScrollText2 => {
                let root_tool = incident_root_tool(system_prompt).unwrap_or_default();
                let go_bottom = bridge_state
                    .info
                    .query_text
                    .as_deref()
                    .or(Some(bridge_state.utterance.as_str()))
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains("bottom");
                if let Some(target) =
                    scroll_target_by_id(&bridge_state.info.scroll_targets, "text-area")
                {
                    if scroll_target_reached(target, go_bottom) {
                        if let Some(tool) = pick_incident_recovery_tool(
                            system_prompt,
                            &[
                                ("browser__click", json!({ "selector": "#subbtn" })),
                                ("browser__snapshot", json!({})),
                            ],
                        ) {
                            return tool;
                        }
                    }

                    let page_key = scroll_page_key(go_bottom);
                    let (jump_key, jump_modifiers) = scroll_jump_key(go_bottom);
                    let focus_candidate = ("browser__click", json!({ "selector": "#text-area" }));
                    let type_candidate = (
                        "browser__type",
                        json!({ "selector": "#text-area", "text": "" }),
                    );
                    let page_key_candidate = ("browser__key", json!({ "key": page_key }));
                    let jump_key_candidate = (
                        "browser__key",
                        json!({ "key": jump_key, "modifiers": jump_modifiers }),
                    );
                    let candidates = match root_tool {
                        "browser__key" => vec![
                            jump_key_candidate.clone(),
                            page_key_candidate.clone(),
                            focus_candidate.clone(),
                            ("browser__snapshot", json!({})),
                            type_candidate.clone(),
                        ],
                        "browser__click" => vec![
                            jump_key_candidate.clone(),
                            page_key_candidate.clone(),
                            type_candidate.clone(),
                            ("browser__snapshot", json!({})),
                        ],
                        "browser__type" => vec![
                            jump_key_candidate.clone(),
                            page_key_candidate.clone(),
                            focus_candidate.clone(),
                            ("browser__snapshot", json!({})),
                        ],
                        "browser__scroll" => vec![
                            jump_key_candidate.clone(),
                            page_key_candidate.clone(),
                            focus_candidate.clone(),
                            ("browser__snapshot", json!({})),
                        ],
                        _ => vec![
                            jump_key_candidate,
                            page_key_candidate,
                            focus_candidate,
                            ("browser__snapshot", json!({})),
                            type_candidate,
                        ],
                    };
                    return self.recovery_tool_or_safe_fallback(system_prompt, &candidates);
                }

                self.recovery_tool_or_safe_fallback(
                    system_prompt,
                    &[
                        ("browser__click", json!({ "selector": "#text-area" })),
                        ("browser__snapshot", json!({})),
                    ],
                )
            }
            RecipeId::ChooseList => {
                let label = parse_submit_target(
                    bridge_state
                        .info
                        .query_text
                        .as_deref()
                        .or(Some(bridge_state.utterance.as_str()))
                        .unwrap_or_default(),
                )
                .unwrap_or_default();
                let candidates = if bridge_selected_contains(
                    &bridge_state.info.interactive_elements,
                    "#options",
                    &label,
                ) {
                    vec![
                        ("browser__click", json!({ "selector": "#options" })),
                        ("browser__click", json!({ "selector": "button" })),
                        ("browser__snapshot", json!({})),
                    ]
                } else {
                    vec![
                        ("browser__click", json!({ "selector": "#options" })),
                        ("browser__snapshot", json!({})),
                    ]
                };
                self.recovery_tool_or_safe_fallback(system_prompt, &candidates)
            }
            RecipeId::UseAutocomplete => {
                let target =
                    bridge_value_by_selector(&bridge_state.info.interactive_elements, "#tags");
                let candidates = if target.is_empty() {
                    vec![
                        ("browser__click", json!({ "selector": "#tags" })),
                        ("browser__wait", json!({ "ms": 120 })),
                        ("browser__snapshot", json!({})),
                    ]
                } else {
                    vec![
                        ("browser__click", json!({ "selector": "#subbtn" })),
                        ("browser__key", json!({ "key": "Escape" })),
                        ("browser__wait", json!({ "ms": 120 })),
                    ]
                };
                self.recovery_tool_or_safe_fallback(system_prompt, &candidates)
            }
            RecipeId::HoverShape => self.hover_shape_recovery_action(system_prompt),
            RecipeId::DragItems => self.recovery_tool_or_safe_fallback(
                system_prompt,
                &[("browser__wait", json!({ "ms": 180 }))],
            ),
            RecipeId::HighlightText => {
                let query = bridge_state
                    .info
                    .query_text
                    .as_deref()
                    .or(Some(bridge_state.utterance.as_str()))
                    .unwrap_or_default();
                let selector = highlight_target_selector(query);
                let candidates = match incident_root_tool(system_prompt).unwrap_or_default() {
                    "browser__select_text" => vec![
                        ("browser__wait", json!({ "ms": 150 })),
                        ("browser__click", json!({ "selector": "#subbtn" })),
                        (
                            "browser__select_text",
                            json!({ "selector": selector.clone() }),
                        ),
                        ("browser__click", json!({ "selector": selector })),
                    ],
                    "browser__click" => vec![
                        ("browser__wait", json!({ "ms": 150 })),
                        ("browser__click", json!({ "selector": "#subbtn" })),
                        (
                            "browser__select_text",
                            json!({ "selector": selector.clone() }),
                        ),
                        ("browser__click", json!({ "selector": selector })),
                    ],
                    _ => vec![
                        ("browser__wait", json!({ "ms": 150 })),
                        ("browser__click", json!({ "selector": "#subbtn" })),
                        (
                            "browser__select_text",
                            json!({ "selector": selector.clone() }),
                        ),
                        ("browser__click", json!({ "selector": selector })),
                    ],
                };
                self.recovery_tool_or_safe_fallback(system_prompt, &candidates)
            }
            RecipeId::CopyPaste => {
                let query = bridge_state
                    .info
                    .query_text
                    .as_deref()
                    .or(Some(bridge_state.utterance.as_str()))
                    .unwrap_or_default();
                let source_selector = copy_paste_source_selector(query);
                let source_value = bridge_value_by_selector(
                    &bridge_state.info.interactive_elements,
                    &source_selector,
                );
                let answer_value = bridge_value_by_selector(
                    &bridge_state.info.interactive_elements,
                    "#answer-input",
                );
                if !source_value.is_empty() && answer_value == source_value {
                    if let Some(tool) = pick_incident_recovery_tool(
                        system_prompt,
                        &[
                            ("browser__click", json!({ "selector": "#subbtn" })),
                            ("browser__click", json!({ "selector": "#answer-input" })),
                            (
                                "browser__paste_clipboard",
                                json!({ "selector": "#answer-input" }),
                            ),
                        ],
                    ) {
                        return tool;
                    }
                }

                let select_all_args =
                    json!({ "key": "a", "modifiers": [primary_browser_modifier()] });
                let reselect_source_args = json!({ "selector": source_selector.clone() });
                let candidates = match incident_root_tool(system_prompt).unwrap_or_default() {
                    "browser__click" => vec![
                        ("browser__key", select_all_args.clone()),
                        ("browser__select_text", reselect_source_args.clone()),
                        ("browser__copy_selection", json!({})),
                        (
                            "browser__click",
                            json!({ "selector": source_selector.clone() }),
                        ),
                    ],
                    "browser__key" => vec![
                        ("browser__select_text", reselect_source_args.clone()),
                        ("browser__copy_selection", json!({})),
                        (
                            "browser__click",
                            json!({ "selector": source_selector.clone() }),
                        ),
                    ],
                    "browser__copy_selection" => vec![
                        ("browser__select_text", reselect_source_args.clone()),
                        ("browser__key", select_all_args.clone()),
                        (
                            "browser__click",
                            json!({ "selector": source_selector.clone() }),
                        ),
                    ],
                    "browser__paste_clipboard" => vec![
                        ("browser__select_text", reselect_source_args.clone()),
                        ("browser__copy_selection", json!({})),
                        ("browser__key", select_all_args.clone()),
                        (
                            "browser__click",
                            json!({ "selector": source_selector.clone() }),
                        ),
                        (
                            "browser__paste_clipboard",
                            json!({ "selector": "#answer-input" }),
                        ),
                    ],
                    _ => vec![
                        (
                            "browser__click",
                            json!({ "selector": source_selector.clone() }),
                        ),
                        ("browser__key", select_all_args),
                        ("browser__select_text", reselect_source_args),
                        ("browser__copy_selection", json!({})),
                        (
                            "browser__paste_clipboard",
                            json!({ "selector": "#answer-input" }),
                        ),
                    ],
                };
                self.recovery_tool_or_safe_fallback(system_prompt, &candidates)
            }
            RecipeId::EmailInbox
            | RecipeId::VisualAddition
            | RecipeId::IdentifyShape
            | RecipeId::CountShape
            | RecipeId::CountSides
            | RecipeId::FindMidpoint
            | RecipeId::WorkflowTicketRouting
            | RecipeId::WorkflowQueueVerification
            | RecipeId::WorkflowAuditHistory
            | RecipeId::WorkflowMutationIsolation
            | RecipeId::WorkflowStaleQueueReorder
            | RecipeId::SurveyOnly => self.recovery_tool_or_safe_fallback(
                system_prompt,
                &[("browser__wait", json!({ "ms": 180 }))],
            ),
            _ => self.recovery_tool_or_safe_fallback(
                system_prompt,
                &[
                    ("browser__snapshot", json!({})),
                    ("browser__click", json!({ "selector": "button" })),
                    ("browser__click", json!({ "selector": "#subbtn" })),
                ],
            ),
        }
    }

    pub(super) fn next_action(&self, bridge_state: &BridgeState) -> Vec<u8> {
        if !self.startup_navigation_issued() {
            self.mark_startup_navigation_issued();
            return inference_tool_call("browser__navigate", json!({ "url": self.url }));
        }

        if !bridge_state.info.task_ready.unwrap_or(false) || bridge_state.utterance.is_empty() {
            if bridge_state.info.page_url.as_deref() == Some(self.url.as_str()) {
                return inference_wait(100);
            }
            return inference_tool_call("browser__navigate", json!({ "url": self.url }));
        }
        if bridge_state.terminated
            || should_break_agent_loop_for_reward(bridge_state, self.case.expected_reward_floor)
        {
            return inference_wait(50);
        }

        let query = bridge_state
            .info
            .query_text
            .clone()
            .unwrap_or_else(|| bridge_state.utterance.clone());
        let elements = &bridge_state.info.interactive_elements;
        let stage = bridge_state.episode_step as usize;

        if let Some(phase) = self.take_pending_followup() {
            return match phase.as_str() {
                "find_greatest_submit" => {
                    inference_tool_call("browser__click", json!({ "selector": "#submit" }))
                }
                "find_midpoint_wait" => {
                    self.note_pending_followup("find_midpoint_submit");
                    inference_wait(80)
                }
                "find_midpoint_submit" => {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
                other => {
                    let wait_ms = match other {
                        "form_type" => 120,
                        "search_click" => 150,
                        "text_editor_apply" => 80,
                        "email_open" | "email_compose" => 80,
                        _ => 50,
                    };
                    inference_wait(wait_ms)
                }
            };
        }

        let click_label = |label: &str| {
            bridge_selector_for_label(elements, label).map(|selector| {
                inference_tool_call("browser__click", json!({ "selector": selector }))
            })
        };

        match self.case.recipe {
            RecipeId::ClickButton | RecipeId::ClickLink => {
                let target = quoted_values(&query).into_iter().next().unwrap_or_default();
                click_label(&target).unwrap_or_else(|| {
                    inference_fail("ERROR_CLASS=TargetNotFound missing selector for target")
                })
            }
            RecipeId::EnterText => {
                let text = quoted_values(&query).into_iter().next().unwrap_or_default();
                if bridge_value_by_selector(elements, "#tt") != text {
                    inference_tool_call("browser__type", json!({ "selector": "#tt", "text": text }))
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::FocusText => {
                if bridge_focus_matches(bridge_state, "#tt") {
                    inference_wait(50)
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#tt" }))
                }
            }
            RecipeId::ChooseList => {
                let label = parse_submit_target(&query).unwrap_or_default();
                if !bridge_selected_contains(elements, "#options", &label) {
                    inference_tool_call(
                        "browser__select_dropdown",
                        json!({ "selector": "#options", "label": label }),
                    )
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "button" }))
                }
            }
            RecipeId::ClickTab => {
                if let Some(target) = quoted_values(&query)
                    .into_iter()
                    .find(|target| !target.trim().is_empty())
                {
                    if let Some(selector) = bridge_selector_for_label(elements, &target) {
                        inference_tool_call("browser__click", json!({ "selector": selector }))
                    } else if let Some(selector) =
                        bridge_hidden_tab_selector_for_label(elements, &target)
                    {
                        inference_tool_call("browser__click", json!({ "selector": selector }))
                    } else {
                        inference_fail("ERROR_CLASS=TargetNotFound click-tab target missing")
                    }
                } else {
                    let number = parse_tab_number(&query).unwrap_or(1);
                    let selector = format!("#ui-id-{}", number);
                    if bridge_element_by_selector(elements, &selector).is_some() {
                        inference_tool_call("browser__click", json!({ "selector": selector }))
                    } else {
                        inference_tool_call(
                            "browser__click",
                            json!({ "selector": format!("a[href='#tabs-{}']", number) }),
                        )
                    }
                }
            }
            RecipeId::UseAutocomplete => {
                let target = infer_autocomplete_target(&query).unwrap_or_default();
                let value = bridge_value_by_selector(elements, "#tags");
                if value != target {
                    inference_tool_call(
                        "browser__type",
                        json!({ "selector": "#tags", "text": target }),
                    )
                } else if bridge_state.episode_step == 0 {
                    inference_tool_call("browser__key", json!({ "key": "Escape" }))
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::ScrollText2 => {
                let go_bottom = query.to_ascii_lowercase().contains("bottom");
                let selector =
                    scroll_target_selector(&bridge_state.info.scroll_targets, "text-area")
                        .unwrap_or_else(|| "#text-area".to_string());
                let page_key = scroll_page_key(go_bottom);
                let (jump_key, jump_modifiers) = scroll_jump_key(go_bottom);
                if let Some(target) =
                    scroll_target_by_id(&bridge_state.info.scroll_targets, "text-area")
                {
                    if scroll_target_reached(target, go_bottom) {
                        self.note_scroll_action("submit");
                        inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                    } else if !bridge_focus_matches(bridge_state, &selector) {
                        self.note_scroll_action("focus");
                        inference_tool_call("browser__click", json!({ "selector": selector }))
                    } else if self.last_scroll_action().as_deref() == Some("jump_key") {
                        self.note_scroll_action("page_key");
                        inference_tool_call("browser__key", json!({ "key": page_key }))
                    } else {
                        self.note_scroll_action("jump_key");
                        inference_tool_call(
                            "browser__key",
                            json!({ "key": jump_key, "modifiers": jump_modifiers }),
                        )
                    }
                } else {
                    inference_tool_call("browser__click", json!({ "selector": selector }))
                }
            }
            RecipeId::ClickOption => match stage {
                0 => {
                    let label = parse_submit_target(&query).unwrap_or_default();
                    click_label(&label).unwrap_or_else(|| {
                        inference_fail("ERROR_CLASS=TargetNotFound click-option target missing")
                    })
                }
                _ => inference_tool_call("browser__click", json!({ "selector": "button" })),
            },
            RecipeId::ClickCheckboxes | RecipeId::ClickCheckboxesTransfer => {
                let targets = parse_checkbox_targets(&query);
                if let Some(label) = targets
                    .iter()
                    .find(|label| !self.checkbox_target_satisfied(elements, label))
                {
                    click_label(label)
                        .map(|action| {
                            self.note_checkbox_click(label);
                            action
                        })
                        .unwrap_or_else(|| {
                            inference_fail("ERROR_CLASS=TargetNotFound checkbox target missing")
                        })
                } else if !targets.is_empty()
                    && !targets.iter().all(|label| {
                        bridge_checkbox_checked_for_label(elements, label).unwrap_or(false)
                    })
                {
                    inference_wait(120)
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "button" }))
                }
            }
            RecipeId::EnterPassword => {
                let password = quoted_values(&query).into_iter().next().unwrap_or_default();
                let password_value = bridge_value_by_selector(elements, "#password");
                let verify_value = bridge_value_by_selector(elements, "#verify");
                if password_value != password {
                    if bridge_focus_matches(bridge_state, "#password") {
                        self.note_pending_followup("form_type");
                        inference_tool_call(
                            "browser__type",
                            json!({ "selector": "#password", "text": password }),
                        )
                    } else {
                        inference_tool_call("browser__click", json!({ "selector": "#password" }))
                    }
                } else if verify_value != password {
                    if bridge_focus_matches(bridge_state, "#verify") {
                        self.note_pending_followup("form_type");
                        inference_tool_call(
                            "browser__type",
                            json!({ "selector": "#verify", "text": password }),
                        )
                    } else {
                        inference_tool_call("browser__click", json!({ "selector": "#verify" }))
                    }
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::LoginUser => {
                let quoted = quoted_values(&query);
                let username = quoted.first().cloned().unwrap_or_default();
                let password = quoted.get(1).cloned().unwrap_or_default();
                let username_value = bridge_value_by_selector(elements, "#username");
                let password_value = bridge_value_by_selector(elements, "#password");
                if username_value != username {
                    if bridge_focus_matches(bridge_state, "#username") {
                        self.note_pending_followup("form_type");
                        inference_tool_call(
                            "browser__type",
                            json!({ "selector": "#username", "text": username }),
                        )
                    } else {
                        inference_tool_call("browser__click", json!({ "selector": "#username" }))
                    }
                } else if password_value != password {
                    if bridge_focus_matches(bridge_state, "#password") {
                        self.note_pending_followup("form_type");
                        inference_tool_call(
                            "browser__type",
                            json!({ "selector": "#password", "text": password }),
                        )
                    } else {
                        inference_tool_call("browser__click", json!({ "selector": "#password" }))
                    }
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::FocusText2 => {
                let index = parse_focus_index(&query).unwrap_or(1);
                let selector = format!("#tt{}", index);
                if bridge_focus_matches(bridge_state, &selector) {
                    inference_wait(50)
                } else {
                    inference_tool_call("browser__click", json!({ "selector": selector }))
                }
            }
            RecipeId::EnterText2 => match stage {
                0 => {
                    let raw_text = quoted_values(&query).into_iter().next().unwrap_or_default();
                    let text = parse_uppercase_transform(&query, &raw_text);
                    inference_tool_call("browser__type", json!({ "selector": "#tt", "text": text }))
                }
                _ => inference_tool_call("browser__click", json!({ "selector": "#subbtn" })),
            },
            RecipeId::ClickButtonSequence => {
                if stage == 0 {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn2" }))
                }
            }
            RecipeId::ClickCollapsible => {
                if stage == 0 {
                    inference_tool_call("browser__click", json!({ "selector": "#area h3" }))
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::ClickCollapsible2 => {
                let target = quoted_values(&query).into_iter().next().unwrap_or_default();
                if let Some(action) = click_label(&target) {
                    action
                } else if let Some(selector) =
                    bridge_hidden_collapsible_selector_for_label(elements, &target)
                {
                    inference_tool_call("browser__click", json!({ "selector": selector }))
                } else {
                    inference_fail("ERROR_CLASS=TargetNotFound click-collapsible-2 target missing")
                }
            }
            RecipeId::SearchEngine => {
                let position = parse_search_result_position(&query).unwrap_or(1);
                let page = ((position - 1) / 3) + 1;
                let local_index = ((position - 1) % 3) + 1;
                let search_term = quoted_values(&query).into_iter().next().unwrap_or_default();
                let search_value = bridge_value_by_selector(elements, "#search-text");
                if search_value != search_term {
                    if bridge_focus_matches(bridge_state, "#search-text") {
                        self.note_pending_followup("form_type");
                        inference_tool_call(
                            "browser__type",
                            json!({ "selector": "#search-text", "text": search_term }),
                        )
                    } else {
                        inference_tool_call("browser__click", json!({ "selector": "#search-text" }))
                    }
                } else if search_result_selector(elements, 1).is_none() {
                    self.note_pending_followup("search_click");
                    inference_tool_call("browser__click", json!({ "selector": "#search" }))
                } else if page > 1 && !search_results_page_matches(elements, page) {
                    self.note_pending_followup("search_click");
                    click_label(&page.to_string()).unwrap_or_else(|| {
                        inference_fail("ERROR_CLASS=TargetNotFound pagination target missing")
                    })
                } else {
                    if let Some(selector) = search_result_selector(elements, local_index as usize) {
                        inference_tool_call("browser__click", json!({ "selector": selector }))
                    } else {
                        inference_fail(
                            "ERROR_CLASS=TargetNotFound search-engine result selector missing",
                        )
                    }
                }
            }
            RecipeId::SimpleArithmetic => {
                let problem = trim_submit_button_suffix(bridge_visible_content_after_query(
                    bridge_state,
                    &query,
                ));
                let Some(answer) = solve_simple_arithmetic_problem(problem) else {
                    return inference_fail(
                        "ERROR_CLASS=ObservationGap simple-arithmetic prompt missing",
                    );
                };
                let answer = answer.to_string();
                if let Some(action) =
                    self.fill_text_field_if_needed(bridge_state, elements, "#math-answer", &answer)
                {
                    action
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::SimpleAlgebra => {
                let visible_problem = trim_submit_button_suffix(
                    bridge_visible_content_after_query(bridge_state, &query),
                );
                let problem = visible_problem
                    .split_once(" x =")
                    .map(|(value, _)| value.trim())
                    .unwrap_or(visible_problem);
                let Some(answer) = solve_simple_algebra_problem(problem) else {
                    return inference_fail(
                        "ERROR_CLASS=ObservationGap simple-algebra prompt missing",
                    );
                };
                let answer = answer.to_string();
                if let Some(action) =
                    self.fill_text_field_if_needed(bridge_state, elements, "#math-answer", &answer)
                {
                    action
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::OddOrEven => {
                let visible_numbers = odd_or_even_visible_numbers(
                    bridge_visible_content_after_query(bridge_state, &query),
                );
                if visible_numbers.is_empty() {
                    inference_fail("ERROR_CLASS=ObservationGap odd-or-even numbers missing")
                } else if stage < visible_numbers.len() {
                    let parity_selector = if visible_numbers[stage].rem_euclid(2) == 0 {
                        ".even"
                    } else {
                        ".odd"
                    };
                    inference_tool_call(
                        "browser__click",
                        json!({
                            "selector": format!(
                                "#numbers .row:nth-of-type({}) {}",
                                stage + 1,
                                parity_selector
                            )
                        }),
                    )
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#submit" }))
                }
            }
            RecipeId::FindWord => {
                let word_index = parse_find_word_index(&query).unwrap_or(1);
                let paragraph = trim_submit_button_suffix(bridge_visible_content_after_query(
                    bridge_state,
                    &query,
                ));
                let words = paragraph
                    .split_whitespace()
                    .map(|word| {
                        word.chars()
                            .filter(|ch| ch.is_ascii_alphanumeric())
                            .collect::<String>()
                    })
                    .filter(|word| !word.is_empty())
                    .collect::<Vec<_>>();
                let Some(answer) = words.get(word_index.saturating_sub(1)) else {
                    return inference_fail("ERROR_CLASS=ObservationGap find-word target missing");
                };
                if let Some(action) =
                    self.fill_text_field_if_needed(bridge_state, elements, "#answer-input", answer)
                {
                    action
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::ReadTable => {
                let target = parse_read_table_target(&query).unwrap_or_default();
                let values = visible_table_value_map(bridge_visible_content_after_query(
                    bridge_state,
                    &query,
                ));
                let Some(answer) = values.get(&target) else {
                    return inference_fail("ERROR_CLASS=ObservationGap read-table value missing");
                };
                if let Some(action) =
                    self.fill_text_field_if_needed(bridge_state, elements, "#tt", answer)
                {
                    action
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::ReadTable2 => {
                let values = visible_table_value_map(bridge_visible_content_after_query(
                    bridge_state,
                    &query,
                ));
                let label_1 = bridge_element_by_selector(elements, "#ll1")
                    .map(bridge_element_display_text)
                    .map(|text| text.trim().trim_end_matches(':').to_string())
                    .unwrap_or_default();
                let label_2 = bridge_element_by_selector(elements, "#ll2")
                    .map(bridge_element_display_text)
                    .map(|text| text.trim().trim_end_matches(':').to_string())
                    .unwrap_or_default();
                let Some(answer_1) = values.get(&label_1) else {
                    return inference_fail(
                        "ERROR_CLASS=ObservationGap read-table-2 first value missing",
                    );
                };
                let Some(answer_2) = values.get(&label_2) else {
                    return inference_fail(
                        "ERROR_CLASS=ObservationGap read-table-2 second value missing",
                    );
                };
                if let Some(action) =
                    self.fill_text_field_if_needed(bridge_state, elements, "#tt1", answer_1)
                {
                    action
                } else if let Some(action) =
                    self.fill_text_field_if_needed(bridge_state, elements, "#tt2", answer_2)
                {
                    action
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::PhoneBook => {
                let target_name = parse_phone_book_name(&query).unwrap_or_default();
                let target_kind = parse_phone_book_target(&query).unwrap_or_default();
                let property_selector = match normalize_label(&target_kind).as_str() {
                    "phone number" | "phone" => "#contact .phone",
                    "email" => "#contact .email",
                    "address" => "#contact .address",
                    _ => {
                        return inference_fail(
                            "ERROR_CLASS=TargetNotFound phone-book target kind missing",
                        )
                    }
                };
                let current_name = phone_book_visible_name(bridge_visible_content_after_query(
                    bridge_state,
                    &query,
                ))
                .unwrap_or_default();
                if normalize_label(&current_name) == normalize_label(&target_name) {
                    inference_tool_call("browser__click", json!({ "selector": property_selector }))
                } else if let Some(next_selector) = bridge_selector_for_label(elements, ">") {
                    inference_tool_call("browser__click", json!({ "selector": next_selector }))
                } else {
                    inference_fail("ERROR_CLASS=TargetNotFound phone-book next page missing")
                }
            }
            RecipeId::FormSequence => self.form_sequence_action(bridge_state, elements, &query),
            RecipeId::FormSequence2 => self.form_sequence_2_action(bridge_state, elements, &query),
            RecipeId::FormSequence3 => self.form_sequence_3_action(elements, &query),
            RecipeId::LoginUserPopup => {
                self.login_user_popup_action(bridge_state, elements, &query)
            }
            RecipeId::TextEditor => self.text_editor_action(bridge_state, &query),
            RecipeId::GuessNumber => self.guess_number_action(bridge_state, elements, &query),
            RecipeId::FindGreatest => self.find_greatest_action(bridge_state, &query),
            RecipeId::SocialMedia => self.social_media_action(bridge_state, &query),
            RecipeId::SocialMediaAll => self.social_media_multi_action(
                bridge_visible_content_after_query(bridge_state, &query),
                &query,
                stage,
                None,
            ),
            RecipeId::SocialMediaSome => {
                let amount = parse_social_media_amount(&query).unwrap_or(1);
                self.social_media_multi_action(
                    bridge_visible_content_after_query(bridge_state, &query),
                    &query,
                    stage,
                    Some(amount),
                )
            }
            RecipeId::StockMarket => self.stock_market_action(bridge_state, &query),
            RecipeId::EmailInbox => self.email_inbox_action(bridge_state, elements, &query),
            RecipeId::VisualAddition => self.visual_addition_action(bridge_state),
            RecipeId::IdentifyShape => self.identify_shape_action(bridge_state),
            RecipeId::CountShape => self.count_shape_action(bridge_state, elements, &query),
            RecipeId::CountSides => self.count_sides_action(elements),
            RecipeId::FindMidpoint => self.find_midpoint_action(bridge_state),
            RecipeId::WorkflowTicketRouting => {
                self.workflow_ticket_routing_action(bridge_state, elements)
            }
            RecipeId::WorkflowQueueVerification => {
                self.workflow_queue_verification_action(bridge_state, elements)
            }
            RecipeId::WorkflowAuditHistory => {
                self.workflow_audit_history_action(bridge_state, elements)
            }
            RecipeId::WorkflowMutationIsolation => {
                self.workflow_mutation_isolation_action(bridge_state, elements)
            }
            RecipeId::WorkflowStaleQueueReorder => {
                self.workflow_stale_queue_reorder_action(bridge_state, elements)
            }
            RecipeId::HoverShape => match self.hover_shape_phase().as_deref() {
                None => {
                    self.note_hover_shape_phase("await_post_hover_1");
                    inference_tool_call("browser__hover", json!({ "selector": "#highlight" }))
                }
                Some("retry_hover_1_after_wait") => {
                    self.note_hover_shape_phase("await_post_hover_1");
                    inference_tool_call("browser__hover", json!({ "selector": "#highlight" }))
                }
                Some("await_post_hover_1") => {
                    self.note_hover_shape_phase("await_post_wait_1");
                    inference_tool_call("browser__wait", json!({ "ms": 1300 }))
                }
                Some("await_post_wait_1") => {
                    self.note_hover_shape_phase("await_post_hover_2");
                    inference_tool_call("browser__hover", json!({ "selector": "#highlight" }))
                }
                Some("retry_hover_2_after_wait") => {
                    self.note_hover_shape_phase("await_post_hover_2");
                    inference_tool_call("browser__hover", json!({ "selector": "#highlight" }))
                }
                Some("await_post_hover_2") => {
                    self.note_hover_shape_phase("await_post_wait_2");
                    inference_tool_call("browser__wait", json!({ "ms": 1300 }))
                }
                Some("await_post_wait_2") => {
                    self.note_hover_shape_phase("await_post_hover_3");
                    inference_tool_call("browser__hover", json!({ "selector": "#highlight" }))
                }
                Some("retry_hover_3_after_wait") => {
                    self.note_hover_shape_phase("await_post_hover_3");
                    inference_tool_call("browser__hover", json!({ "selector": "#highlight" }))
                }
                Some("await_post_hover_3") => {
                    self.note_hover_shape_phase("complete");
                    inference_tool_call("agent__complete", json!({}))
                }
                _ => inference_tool_call("agent__complete", json!({})),
            },
            RecipeId::DragItems => inference_fail(
                "ERROR_CLASS=PlannerGap drag-items agent recipe needs structured order readback",
            ),
            RecipeId::HighlightText => {
                let selector = highlight_target_selector(&query);
                match stage {
                    0 => {
                        inference_tool_call("browser__select_text", json!({ "selector": selector }))
                    }
                    1 => inference_wait(150),
                    _ => inference_tool_call("browser__click", json!({ "selector": "#subbtn" })),
                }
            }
            RecipeId::CopyPaste => {
                let source_selector = copy_paste_source_selector(&query);
                let source_value = bridge_value_by_selector(elements, &source_selector);
                let answer_value = bridge_value_by_selector(elements, "#answer-input");
                let phase = self.last_copy_paste_action();
                if !source_value.is_empty() && answer_value == source_value {
                    match phase.as_deref() {
                        Some("paste") => {
                            self.note_copy_paste_action("submit_wait");
                            inference_wait(150)
                        }
                        Some("submit_wait") | Some("paste_retry") => {
                            self.note_copy_paste_action("submit");
                            inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                        }
                        Some("submit") => inference_wait(50),
                        _ => {
                            self.note_copy_paste_action("submit");
                            inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                        }
                    }
                } else {
                    match phase.as_deref() {
                        None => {
                            self.note_copy_paste_action("click_source");
                            inference_tool_call(
                                "browser__click",
                                json!({ "selector": source_selector }),
                            )
                        }
                        Some("click_source") => {
                            self.note_copy_paste_action("focus_wait");
                            inference_wait(100)
                        }
                        Some("focus_wait") => {
                            self.note_copy_paste_action("key_chord");
                            inference_tool_call(
                                "browser__key",
                                json!({ "key": "a", "modifiers": [primary_browser_modifier()] }),
                            )
                        }
                        Some("key_chord") => {
                            self.note_copy_paste_action("selection_wait");
                            inference_wait(100)
                        }
                        Some("selection_wait") => {
                            self.note_copy_paste_action("copy");
                            inference_tool_call("browser__copy_selection", json!({}))
                        }
                        Some("copy") => {
                            self.note_copy_paste_action("paste");
                            inference_tool_call(
                                "browser__paste_clipboard",
                                json!({ "selector": "#answer-input" }),
                            )
                        }
                        Some("paste") => {
                            self.note_copy_paste_action("paste_wait");
                            inference_wait(100)
                        }
                        Some("paste_wait") => {
                            self.note_copy_paste_action("paste_retry");
                            inference_tool_call(
                                "browser__paste_clipboard",
                                json!({ "selector": "#answer-input" }),
                            )
                        }
                        _ => {
                            self.note_copy_paste_action("copy");
                            inference_tool_call("browser__copy_selection", json!({}))
                        }
                    }
                }
            }
            RecipeId::SurveyOnly => inference_fail("ERROR_CLASS=CatalogSurvey survey-only case"),
        }
    }
}

#[async_trait]
impl InferenceRuntime for MiniwobAgentRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        if std::env::var_os("COMPUTER_USE_SUITE_DEBUG_PROMPTS").is_some() {
            let debug_path = std::env::temp_dir()
                .join(format!("computer_use_suite_{}_prompt.json", self.case.id));
            let _ = fs::write(&debug_path, input_context);
        }
        let system_prompt = extract_system_prompt(input_context);
        let bridge_state = self
            .client
            .state(&self.session_id)
            .await
            .map_err(|err| VmError::HostError(format!("bridge state: {}", err)))?;
        if is_incident_recovery_prompt(&system_prompt) {
            if matches!(self.case.recipe, RecipeId::HoverShape) {
                return Ok(self.hover_shape_recovery_action(&system_prompt));
            }
            return Ok(self.recovery_action(&bridge_state, &system_prompt));
        }
        Ok(self.next_action(&bridge_state))
    }

    async fn load_model(
        &self,
        _model_hash: [u8; 32],
        _model_path: &std::path::Path,
    ) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}
