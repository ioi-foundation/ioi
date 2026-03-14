#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BrowserAutocompleteState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controls_dom_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_descendant_dom_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assistive_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BrowserTypeOutcome {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dom_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub focused: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scroll_top: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scroll_height: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_height: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub can_scroll_up: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub can_scroll_down: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub already_satisfied: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autocomplete: Option<BrowserAutocompleteState>,
}

const SCROLL_EDGE_SETTLE_TOLERANCE: i32 = 4;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct BrowserScrollProbe {
    page: BrowserScrollPosition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<BrowserScrollTargetState>,
}

impl BrowserDriver {
    fn normalize_typed_text_value(value: &str) -> String {
        value.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn typed_text_request_already_satisfied(outcome: &BrowserTypeOutcome, text: &str) -> bool {
        if !outcome.focused {
            return false;
        }

        let requested = Self::normalize_typed_text_value(text);
        if requested.is_empty() {
            return false;
        }

        outcome
            .value
            .as_deref()
            .map(Self::normalize_typed_text_value)
            .is_some_and(|value| value == requested)
    }

    fn active_mouse_button(buttons: i64) -> Option<MouseButton> {
        if buttons & Self::mouse_button_mask(&MouseButton::Left) != 0 {
            Some(MouseButton::Left)
        } else if buttons & Self::mouse_button_mask(&MouseButton::Right) != 0 {
            Some(MouseButton::Right)
        } else if buttons & Self::mouse_button_mask(&MouseButton::Middle) != 0 {
            Some(MouseButton::Middle)
        } else if buttons & Self::mouse_button_mask(&MouseButton::Back) != 0 {
            Some(MouseButton::Back)
        } else if buttons & Self::mouse_button_mask(&MouseButton::Forward) != 0 {
            Some(MouseButton::Forward)
        } else {
            None
        }
    }

    fn parse_mouse_button(button: &str) -> std::result::Result<MouseButton, BrowserError> {
        match button.trim().to_ascii_lowercase().as_str() {
            "" | "left" => Ok(MouseButton::Left),
            "right" => Ok(MouseButton::Right),
            "middle" => Ok(MouseButton::Middle),
            "back" => Ok(MouseButton::Back),
            "forward" => Ok(MouseButton::Forward),
            other => Err(BrowserError::Internal(format!(
                "Unsupported mouse button '{}'",
                other
            ))),
        }
    }

    fn mouse_button_mask(button: &MouseButton) -> i64 {
        match button {
            MouseButton::Left => 1,
            MouseButton::Right => 2,
            MouseButton::Middle => 4,
            MouseButton::Back => 8,
            MouseButton::Forward => 16,
            MouseButton::None => 0,
        }
    }

    fn parse_keyboard_modifier(
        modifier: &str,
    ) -> std::result::Result<(&'static str, i64), BrowserError> {
        match modifier.trim().to_ascii_lowercase().as_str() {
            "alt" | "option" => Ok(("Alt", 1)),
            "control" | "ctrl" => Ok(("Control", 2)),
            "meta" | "command" | "cmd" | "super" => Ok(("Meta", 4)),
            "shift" => Ok(("Shift", 8)),
            other => Err(BrowserError::Internal(format!(
                "Unsupported keyboard modifier '{}'",
                other
            ))),
        }
    }

    fn modifiers_include(modifiers: &[String], expected: &str) -> bool {
        modifiers.iter().any(|modifier| {
            Self::parse_keyboard_modifier(modifier)
                .map(|(canonical, _)| canonical.eq_ignore_ascii_case(expected))
                .unwrap_or(false)
        })
    }

    fn is_top_edge_jump_chord(key: &str, modifiers: &[String]) -> bool {
        (key.eq_ignore_ascii_case("Home") && Self::modifiers_include(modifiers, "Control"))
            || (key.eq_ignore_ascii_case("ArrowUp") && Self::modifiers_include(modifiers, "Meta"))
    }

    fn is_bottom_edge_jump_chord(key: &str, modifiers: &[String]) -> bool {
        (key.eq_ignore_ascii_case("End") && Self::modifiers_include(modifiers, "Control"))
            || (key.eq_ignore_ascii_case("ArrowDown")
                && Self::modifiers_include(modifiers, "Meta"))
    }

    fn edge_jump_settle_key(
        key: &str,
        modifiers: &[String],
        outcome: &BrowserTypeOutcome,
    ) -> Option<&'static str> {
        if !outcome.focused {
            return None;
        }

        if Self::is_top_edge_jump_chord(key, modifiers)
            && outcome.can_scroll_up == Some(true)
            && outcome
                .scroll_top
                .is_some_and(|scroll_top| (0..=SCROLL_EDGE_SETTLE_TOLERANCE).contains(&scroll_top))
        {
            return Some("PageUp");
        }

        if Self::is_bottom_edge_jump_chord(key, modifiers)
            && outcome.can_scroll_down == Some(true)
        {
            let remaining_distance = outcome
                .scroll_height
                .zip(outcome.client_height)
                .zip(outcome.scroll_top)
                .map(|((scroll_height, client_height), scroll_top)| {
                    scroll_height.saturating_sub(client_height).saturating_sub(scroll_top)
                });
            if remaining_distance
                .is_some_and(|distance| (0..=SCROLL_EDGE_SETTLE_TOLERANCE).contains(&distance))
            {
                return Some("PageDown");
            }
        }

        None
    }

    async fn dispatch_key_and_wait(
        &self,
        key: &str,
        modifiers: &[String],
    ) -> std::result::Result<BrowserTypeOutcome, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;
        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        let resolve_key_definition = |name: &str| {
            keys::get_key_definition(name)
                .or_else(|| {
                    keys::USKEYBOARD_LAYOUT
                        .iter()
                        .find(|definition| definition.key.eq_ignore_ascii_case(name))
                })
                .ok_or_else(|| BrowserError::Internal(format!("Unsupported key '{}'", name)))
        };

        let mut pressed_modifiers = Vec::new();
        let mut modifier_mask = 0i64;
        for modifier in modifiers {
            let (modifier_key, mask) = Self::parse_keyboard_modifier(modifier)?;
            if modifier_mask & mask != 0 {
                continue;
            }

            let key_definition = resolve_key_definition(modifier_key)?;
            let modifier_down = DispatchKeyEventParams::builder()
                .r#type(DispatchKeyEventType::RawKeyDown)
                .modifiers(modifier_mask | mask)
                .key(key_definition.key)
                .code(key_definition.code)
                .windows_virtual_key_code(key_definition.key_code)
                .native_virtual_key_code(key_definition.key_code)
                .build()
                .map_err(BrowserError::Internal)?;
            page.execute(modifier_down).await.map_err(|e| {
                BrowserError::Internal(format!(
                    "Modifier key down failed for '{}': {}",
                    modifier_key, e
                ))
            })?;
            modifier_mask |= mask;
            pressed_modifiers.push((modifier_key, mask));
        }

        let key_definition = resolve_key_definition(key)?;
        let mut cmd = DispatchKeyEventParams::builder()
            .r#type(DispatchKeyEventType::KeyDown)
            .key(key_definition.key)
            .code(key_definition.code)
            .windows_virtual_key_code(key_definition.key_code)
            .native_virtual_key_code(key_definition.key_code);
        if modifier_mask != 0 {
            cmd = cmd.modifiers(modifier_mask);
        }

        let key_down_event_type = if modifier_mask == 0 {
            if let Some(text) = key_definition.text {
                cmd = cmd.text(text);
                DispatchKeyEventType::KeyDown
            } else if key_definition.key.len() == 1 {
                cmd = cmd.text(key_definition.key);
                DispatchKeyEventType::KeyDown
            } else {
                DispatchKeyEventType::RawKeyDown
            }
        } else {
            DispatchKeyEventType::RawKeyDown
        };

        let key_down = cmd
            .clone()
            .r#type(key_down_event_type)
            .build()
            .map_err(BrowserError::Internal)?;
        page.execute(key_down)
            .await
            .map_err(|e| BrowserError::Internal(format!("Key down failed: {}", e)))?;

        let key_up = cmd
            .clone()
            .r#type(DispatchKeyEventType::KeyUp)
            .build()
            .map_err(BrowserError::Internal)?;
        page.execute(key_up)
            .await
            .map_err(|e| BrowserError::Internal(format!("Key up failed: {}", e)))?;

        for (modifier_key, mask) in pressed_modifiers.into_iter().rev() {
            let key_definition = resolve_key_definition(modifier_key)?;
            let modifier_up = DispatchKeyEventParams::builder()
                .r#type(DispatchKeyEventType::KeyUp)
                .modifiers(modifier_mask)
                .key(key_definition.key)
                .code(key_definition.code)
                .windows_virtual_key_code(key_definition.key_code)
                .native_virtual_key_code(key_definition.key_code)
                .build()
                .map_err(BrowserError::Internal)?;
            page.execute(modifier_up).await.map_err(|e| {
                BrowserError::Internal(format!(
                    "Modifier key up failed for '{}': {}",
                    modifier_key, e
                ))
            })?;
            modifier_mask &= !mask;
        }

        tokio::time::sleep(Duration::from_millis(40)).await;
        self.wait_for_typed_text_state(None).await
    }

    async fn dispatch_text_keyup(
        &self,
        selector: Option<&str>,
        text: &str,
    ) -> std::result::Result<(), BrowserError> {
        let selector_json = serde_json::to_string(&selector)
            .map_err(|e| BrowserError::Internal(format!("Selector encode failed: {}", e)))?;
        let key = text
            .chars()
            .last()
            .map(|ch| ch.to_string())
            .unwrap_or_else(|| "Unidentified".to_string());
        let key_json = serde_json::to_string(&key)
            .map_err(|e| BrowserError::Internal(format!("Key encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();
        let script = format!(
            r#"(() => {{
                const selector = {selector_json};
                const key = {key_json};
                {helpers}
                const el = selector ? deepQuerySelector(selector) : deepActiveElement();
                if (!el) {{
                    return false;
                }}
                try {{
                    const upper = key.length === 1 ? key.toUpperCase() : key;
                    const keyCode =
                        upper.length === 1 ? upper.charCodeAt(0) : 0;
                    const event = new KeyboardEvent("keyup", {{
                        key,
                        code: key.length === 1 ? `Key${{upper}}` : key,
                        keyCode,
                        which: keyCode,
                        bubbles: true,
                        cancelable: true,
                        composed: true,
                    }});
                    el.dispatchEvent(event);
                    return true;
                }} catch (_e) {{
                    return false;
                }}
            }})()"#,
            selector_json = selector_json,
            key_json = key_json,
            helpers = helpers
        );
        let _: bool = self.evaluate_js(&script).await?;
        Ok(())
    }

    async fn probe_typed_text_state(
        &self,
        selector: Option<&str>,
    ) -> std::result::Result<BrowserTypeOutcome, BrowserError> {
        let selector_json = serde_json::to_string(&selector)
            .map_err(|e| BrowserError::Internal(format!("Selector encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();
        let script = format!(
            r#"(() => {{
                const selector = {selector_json};
                {helpers}
                const normalize = (value) =>
                    String(value || "")
                        .replace(/\s+/g, " ")
                        .trim();
                const selectorForDomId = (domId) => {{
                    const normalized = normalize(domId);
                    if (!normalized) {{
                        return null;
                    }}
                    return `[id="${{normalized.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}}"]`;
                }};
                const firstIdToken = (value) => {{
                    const tokens = normalize(value).split(/\s+/).filter(Boolean);
                    return tokens.length > 0 ? tokens[0] : null;
                }};
                const relatedIds = (el) => {{
                    if (!el || typeof el.getAttribute !== "function") {{
                        return [];
                    }}
                    const ids = [];
                    const seen = new Set();
                    for (const attr of [
                        "aria-controls",
                        "aria-owns",
                        "aria-describedby",
                        "aria-activedescendant",
                    ]) {{
                        const raw = normalize(el.getAttribute(attr));
                        if (!raw) continue;
                        for (const token of raw.split(/\s+/).filter(Boolean)) {{
                            if (seen.has(token)) continue;
                            seen.add(token);
                            ids.push(token);
                        }}
                    }}
                    return ids;
                }};
                const bestAssistiveHint = (el) => {{
                    const hints = [];
                    const pushHint = (value) => {{
                        const text = normalize(value);
                        if (text) {{
                            hints.push(text);
                        }}
                    }};

                    for (const id of relatedIds(el)) {{
                        const related = document.getElementById(id);
                        if (related) {{
                            pushHint(related.innerText || related.textContent || "");
                        }}
                    }}

                    const assistiveRegions = document.querySelectorAll(
                        "[role='status'], [role='alert'], [role='log'], [aria-live], .ui-helper-hidden-accessible"
                    );
                    for (const region of assistiveRegions) {{
                        pushHint(region.innerText || region.textContent || "");
                    }}

                    hints.sort((left, right) => right.length - left.length);
                    return hints.length > 0 ? hints[0].slice(0, 160) : null;
                }};

                    const el = selector ? deepQuerySelector(selector) : deepActiveElement();
                    if (!el) {{
                        return {{
                            selector,
                            dom_id: null,
                            tag_name: null,
                            value: null,
                            focused: false,
                            scroll_top: null,
                            scroll_height: null,
                            client_height: null,
                            can_scroll_up: null,
                            can_scroll_down: null,
                            autocomplete: null,
                        }};
                    }}

                    const domId = normalize(el.id);
                    const tagName = normalize(el.tagName).toLowerCase();
                    const autocompleteMode = (() => {{
                        const ariaAutocomplete = normalize(el.getAttribute("aria-autocomplete")).toLowerCase();
                        if (ariaAutocomplete) {{
                            return ariaAutocomplete;
                        }}
                        const className = normalize(String(el.className || "")).toLowerCase();
                        return className.includes("autocomplete") ? "list" : null;
                    }})();
                    const controlsDomId = firstIdToken(el.getAttribute("aria-controls"));
                    const activeDescendantDomId = firstIdToken(
                        el.getAttribute("aria-activedescendant")
                    );
                    const autocomplete =
                        autocompleteMode || controlsDomId || activeDescendantDomId
                            ? {{
                                  mode: autocompleteMode,
                                  controls_dom_id: controlsDomId,
                                  active_descendant_dom_id: activeDescendantDomId,
                                  assistive_hint: bestAssistiveHint(el),
                              }}
                            : null;
                    const value =
                        "value" in el ? normalize(el.value || "") : normalize(el.innerText || el.textContent || "");
                    const scrollHeight = Number(el.scrollHeight || 0);
                    const clientHeight = Number(el.clientHeight || 0);
                    const scrollTop = Number(el.scrollTop || 0);
                    const scrollable = scrollHeight > clientHeight + 1;

                    return {{
                        selector: selector || selectorForDomId(domId),
                        dom_id: domId || null,
                        tag_name: tagName || null,
                        value: value || null,
                        focused: deepActiveElement() === el,
                        scroll_top: scrollable ? Math.round(scrollTop) : null,
                        scroll_height: scrollable ? Math.round(scrollHeight) : null,
                        client_height: scrollable ? Math.round(clientHeight) : null,
                        can_scroll_up: scrollable ? scrollTop > 1 : null,
                        can_scroll_down:
                            scrollable ? scrollTop + clientHeight + 1 < scrollHeight : null,
                        autocomplete,
                    }};
            }})()"#,
            selector_json = selector_json,
            helpers = helpers
        );

        self.evaluate_js(&script).await
    }

    async fn wait_for_typed_text_state(
        &self,
        selector: Option<&str>,
    ) -> std::result::Result<BrowserTypeOutcome, BrowserError> {
        let mut last = self.probe_typed_text_state(selector).await?;
        let mut autocomplete_pending = last.autocomplete.is_some();

        for _ in 0..5 {
            let autocomplete_ready = last.autocomplete.as_ref().is_some_and(|autocomplete| {
                autocomplete
                    .assistive_hint
                    .as_ref()
                    .is_some_and(|hint| !hint.trim().is_empty())
                    || autocomplete
                        .active_descendant_dom_id
                        .as_ref()
                        .is_some_and(|id| !id.trim().is_empty())
                    || autocomplete
                        .controls_dom_id
                        .as_ref()
                        .is_some_and(|id| !id.trim().is_empty())
            });
            if autocomplete_ready {
                break;
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
            last = self.probe_typed_text_state(selector).await?;
            autocomplete_pending |= last.autocomplete.is_some();
        }

        if !autocomplete_pending {
            tokio::time::sleep(Duration::from_millis(50)).await;
            last = self.probe_typed_text_state(selector).await?;
        }

        Ok(last)
    }

    fn scroll_target_changed(
        before: Option<&BrowserScrollTargetState>,
        after: Option<&BrowserScrollTargetState>,
    ) -> bool {
        match (before, after) {
            (Some(before), Some(after)) => {
                before.dom_id != after.dom_id
                    || (before.scroll_top - after.scroll_top).abs() > 0.5
                    || before.can_scroll_up != after.can_scroll_up
                    || before.can_scroll_down != after.can_scroll_down
            }
            (None, None) => false,
            _ => true,
        }
    }

    async fn probe_scroll_state(
        &self,
        anchor_x: f64,
        anchor_y: f64,
    ) -> std::result::Result<BrowserScrollProbe, BrowserError> {
        let anchor_x_json = serde_json::to_string(&anchor_x)
            .map_err(|e| BrowserError::Internal(format!("Anchor x encode failed: {}", e)))?;
        let anchor_y_json = serde_json::to_string(&anchor_y)
            .map_err(|e| BrowserError::Internal(format!("Anchor y encode failed: {}", e)))?;
        let helpers = Self::deep_dom_helper_js();
        let script = format!(
            r#"(() => {{
                const anchorX = {anchor_x_json};
                const anchorY = {anchor_y_json};
                {helpers}
                const normalize = (value) =>
                    String(value || "")
                        .replace(/\s+/g, " ")
                        .trim();
                const selectorForDomId = (domId) => {{
                    const normalized = normalize(domId);
                    if (!normalized) {{
                        return null;
                    }}
                    return `[id="${{normalized.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}}"]`;
                }};
                const pageScrollState = () => {{
                    const scrollingEl =
                        document.scrollingElement || document.documentElement || document.body;
                    const x =
                        scrollingEl && Number.isFinite(scrollingEl.scrollLeft)
                            ? scrollingEl.scrollLeft
                            : (Number.isFinite(window.scrollX) ? window.scrollX : 0);
                    const y =
                        scrollingEl && Number.isFinite(scrollingEl.scrollTop)
                            ? scrollingEl.scrollTop
                            : (Number.isFinite(window.scrollY) ? window.scrollY : 0);
                    return {{ x, y }};
                }};
                const scrollableState = (el) => {{
                    if (!el) {{
                        return null;
                    }}

                    const scrollHeight = Number(el.scrollHeight || 0);
                    const clientHeight = Number(el.clientHeight || 0);
                    const scrollTop = Number(el.scrollTop || 0);
                    const scrollWidth = Number(el.scrollWidth || 0);
                    const clientWidth = Number(el.clientWidth || 0);
                    const scrollLeft = Number(el.scrollLeft || 0);
                    const verticalScrollable = scrollHeight > clientHeight + 1;
                    const horizontalScrollable = scrollWidth > clientWidth + 1;
                    if (!verticalScrollable && !horizontalScrollable) {{
                        return null;
                    }}

                    let rect = null;
                    try {{
                        rect = typeof el.getBoundingClientRect === "function"
                            ? el.getBoundingClientRect()
                            : null;
                    }} catch (_e) {{}}

                    const domId = normalize(el.id);
                    const tagName = normalize(el.tagName).toLowerCase();
                    const value =
                        "value" in el ? normalize(el.value || "") : normalize(el.innerText || el.textContent || "");
                    const centerX =
                        rect && Number.isFinite(rect.left) && Number.isFinite(rect.width)
                            ? rect.left + rect.width / 2
                            : null;
                    const centerY =
                        rect && Number.isFinite(rect.top) && Number.isFinite(rect.height)
                            ? rect.top + rect.height / 2
                            : null;

                    return {{
                        selector: selectorForDomId(domId),
                        dom_id: domId || null,
                        tag_name: tagName || null,
                        value: value || null,
                        focused: deepActiveElement() === el,
                        scroll_top: scrollTop,
                        scroll_height: scrollHeight,
                        client_height: clientHeight,
                        can_scroll_up: scrollTop > 1,
                        can_scroll_down: scrollTop + clientHeight + 1 < scrollHeight,
                        center_x: centerX,
                        center_y: centerY,
                    }};
                }};
                const nearestScrollableAncestor = (node) => {{
                    let current = node;
                    const visited = new Set();
                    while (current && !visited.has(current)) {{
                        visited.add(current);
                        const state = scrollableState(current);
                        if (state) {{
                            return state;
                        }}
                        const root = current.getRootNode ? current.getRootNode() : null;
                        if (root && root.host) {{
                            current = root.host;
                            continue;
                        }}
                        const ownerDoc = current.ownerDocument || null;
                        const frameEl =
                            ownerDoc &&
                            ownerDoc.defaultView &&
                            ownerDoc.defaultView.frameElement
                                ? ownerDoc.defaultView.frameElement
                                : null;
                        if (frameEl) {{
                            current = frameEl;
                            continue;
                        }}
                        current = current.parentElement;
                    }}
                    return null;
                }};

                const focusedTarget = nearestScrollableAncestor(deepActiveElement());
                const pointedTarget = nearestScrollableAncestor(
                    deepElementFromPoint(anchorX, anchorY)
                );

                return {{
                    page: pageScrollState(),
                    target: focusedTarget || pointedTarget,
                }};
            }})()"#,
            anchor_x_json = anchor_x_json,
            anchor_y_json = anchor_y_json,
            helpers = helpers
        );

        self.evaluate_js(&script).await
    }

    async fn wait_for_scroll_state(
        &self,
        anchor_x: f64,
        anchor_y: f64,
        before: &BrowserScrollProbe,
    ) -> std::result::Result<BrowserScrollProbe, BrowserError> {
        let mut last = self.probe_scroll_state(anchor_x, anchor_y).await?;
        for _ in 0..3 {
            let page_changed = (last.page.x - before.page.x).abs() > 0.5
                || (last.page.y - before.page.y).abs() > 0.5;
            let target_changed =
                Self::scroll_target_changed(before.target.as_ref(), last.target.as_ref());
            if page_changed || target_changed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
            last = self.probe_scroll_state(anchor_x, anchor_y).await?;
        }
        Ok(last)
    }

    pub async fn reset_pointer_state(&self) {
        *self.pointer_state.lock().await = BrowserPointerState::default();
    }

    pub async fn pointer_state(&self) -> BrowserPointerState {
        *self.pointer_state.lock().await
    }

    pub async fn move_mouse(&self, x: f64, y: f64) -> std::result::Result<(), BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;
        let buttons = self.pointer_state().await.buttons;
        let mut cmd_move = DispatchMouseEventParams::builder()
            .r#type(DispatchMouseEventType::MouseMoved)
            .x(x)
            .y(y)
            .buttons(buttons);
        if let Some(button) = Self::active_mouse_button(buttons) {
            cmd_move = cmd_move.button(button);
        }
        let cmd_move = cmd_move.build().map_err(BrowserError::Internal)?;
        page.execute(cmd_move).await.map_err(|e| {
            BrowserError::Internal(format!(
                "Mouse move dispatch failed at ({:.2}, {:.2}): {}",
                x, y, e
            ))
        })?;

        let mut state = self.pointer_state.lock().await;
        state.x = x;
        state.y = y;
        Ok(())
    }

    pub async fn mouse_down(
        &self,
        x: f64,
        y: f64,
        button: &str,
    ) -> std::result::Result<(), BrowserError> {
        let button = Self::parse_mouse_button(button)?;
        self.move_mouse(x, y).await?;

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;
        let next_buttons = {
            let state = self.pointer_state.lock().await;
            state.buttons | Self::mouse_button_mask(&button)
        };

        let cmd_down = DispatchMouseEventParams::builder()
            .r#type(DispatchMouseEventType::MousePressed)
            .button(button.clone())
            .x(x)
            .y(y)
            .buttons(next_buttons)
            .click_count(1)
            .build()
            .map_err(BrowserError::Internal)?;
        page.execute(cmd_down).await.map_err(|e| {
            BrowserError::Internal(format!(
                "Mouse press dispatch failed at ({:.2}, {:.2}): {}",
                x, y, e
            ))
        })?;

        let mut state = self.pointer_state.lock().await;
        state.x = x;
        state.y = y;
        state.buttons = next_buttons;
        Ok(())
    }

    pub async fn mouse_up(
        &self,
        x: f64,
        y: f64,
        button: &str,
    ) -> std::result::Result<(), BrowserError> {
        let button = Self::parse_mouse_button(button)?;
        self.move_mouse(x, y).await?;

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;
        let next_buttons = {
            let state = self.pointer_state.lock().await;
            state.buttons & !Self::mouse_button_mask(&button)
        };

        let cmd_up = DispatchMouseEventParams::builder()
            .r#type(DispatchMouseEventType::MouseReleased)
            .button(button.clone())
            .x(x)
            .y(y)
            .buttons(next_buttons)
            .click_count(1)
            .build()
            .map_err(BrowserError::Internal)?;
        page.execute(cmd_up).await.map_err(|e| {
            BrowserError::Internal(format!(
                "Mouse release dispatch failed at ({:.2}, {:.2}): {}",
                x, y, e
            ))
        })?;

        let mut state = self.pointer_state.lock().await;
        state.x = x;
        state.y = y;
        state.buttons = next_buttons;
        Ok(())
    }

    pub async fn synthetic_click_with_button(
        &self,
        x: f64,
        y: f64,
        button: MouseButton,
    ) -> std::result::Result<(), BrowserError> {
        self.mouse_down(x, y, button.as_ref()).await?;
        self.mouse_up(x, y, button.as_ref()).await?;
        Ok(())
    }

    pub async fn synthetic_click(&self, x: f64, y: f64) -> std::result::Result<(), BrowserError> {
        self.synthetic_click_with_button(x, y, MouseButton::Left)
            .await
    }

    pub async fn scroll(
        &self,
        delta_x: i32,
        delta_y: i32,
    ) -> std::result::Result<BrowserScrollOutcome, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;
        let metrics = page
            .execute(GetLayoutMetricsParams::default())
            .await
            .map_err(|e| {
                BrowserError::Internal(format!("Failed to get layout for scroll: {}", e))
            })?;

        let viewport = &metrics.css_layout_viewport;
        let pointer = self.pointer_state().await;
        let pointer_in_viewport = pointer.x.is_finite()
            && pointer.y.is_finite()
            && pointer.x >= 0.0
            && pointer.y >= 0.0
            && pointer.x <= viewport.client_width as f64
            && pointer.y <= viewport.client_height as f64;
        let viewport_center = (
            viewport.client_width as f64 / 2.0,
            viewport.client_height as f64 / 2.0,
        );
        let initial_probe = self
            .probe_scroll_state(viewport_center.0, viewport_center.1)
            .await?;
        let (cx, cy, anchor) = if pointer_in_viewport {
            (pointer.x, pointer.y, "pointer")
        } else if let Some(target) = initial_probe
            .target
            .as_ref()
            .filter(|target| target.focused)
        {
            match (target.center_x, target.center_y) {
                (Some(center_x), Some(center_y)) => (center_x, center_y, "focused_target"),
                _ => (viewport_center.0, viewport_center.1, "viewport_center"),
            }
        } else {
            (viewport_center.0, viewport_center.1, "viewport_center")
        };
        let before = if anchor == "viewport_center" {
            initial_probe
        } else {
            self.probe_scroll_state(cx, cy).await?
        };

        let cmd = DispatchMouseEventParams::builder()
            .r#type(DispatchMouseEventType::MouseWheel)
            .x(cx)
            .y(cy)
            .delta_x(delta_x as f64)
            .delta_y(delta_y as f64)
            .build()
            .map_err(BrowserError::Internal)?;

        page.execute(cmd)
            .await
            .map_err(|e| BrowserError::Internal(format!("Scroll failed: {}", e)))?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let after = self.wait_for_scroll_state(cx, cy, &before).await?;
        let page_moved =
            (after.page.x - before.page.x).abs() > 0.5 || (after.page.y - before.page.y).abs() > 0.5;
        let target_moved = Self::scroll_target_changed(before.target.as_ref(), after.target.as_ref());

        Ok(BrowserScrollOutcome {
            delta_x,
            delta_y,
            anchor: anchor.to_string(),
            anchor_x: cx,
            anchor_y: cy,
            page_before: before.page,
            page_after: after.page,
            page_moved,
            target_before: before.target,
            target_after: after.target,
            target_moved,
        })
    }

    pub async fn type_text(
        &self,
        text: &str,
        selector: Option<&str>,
    ) -> std::result::Result<BrowserTypeOutcome, BrowserError> {
        if let Some(sel) = selector {
            match self.focus_selector(sel).await {
                Ok(true) => {}
                Ok(false) => {
                    return Err(BrowserError::Internal(format!(
                        "Failed to focus selector '{}'",
                        sel
                    )))
                }
                Err(e) => {
                    return Err(BrowserError::Internal(format!(
                        "Selector focus failed for '{}': {}",
                        sel, e
                    )))
                }
            }
        }

        self.require_runtime()?;
        self.ensure_page().await?;
        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        let current = self.probe_typed_text_state(selector).await?;
        if Self::typed_text_request_already_satisfied(&current, text) {
            let mut satisfied = current;
            satisfied.already_satisfied = Some(true);
            return Ok(satisfied);
        }

        page.execute(InsertTextParams::new(text))
            .await
            .map_err(|e| BrowserError::Internal(format!("Type failed: {}", e)))?;

        if !text.is_empty() {
            self.dispatch_text_keyup(selector, text).await?;
        }

        self.wait_for_typed_text_state(selector).await
    }

    pub async fn press_key(
        &self,
        key: &str,
        modifiers: &[String],
    ) -> std::result::Result<BrowserTypeOutcome, BrowserError> {
        let key = key.trim();
        if key.is_empty() {
            return Err(BrowserError::Internal("Key cannot be empty".to_string()));
        }

        let outcome = self.dispatch_key_and_wait(key, modifiers).await?;
        let Some(recovery_key) = Self::edge_jump_settle_key(key, modifiers, &outcome) else {
            return Ok(outcome);
        };

        let empty_modifiers: Vec<String> = Vec::new();
        self.dispatch_key_and_wait(recovery_key, &empty_modifiers)
            .await
    }

    pub async fn click_selector(&self, selector: &str) -> std::result::Result<(), BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() };

        if let Some(p) = page {
            let primary_click_result = match p.find_element(selector).await {
                Ok(element) => match element.click().await {
                    Ok(_) => Ok(()),
                    Err(e) => Err(format!("Click failed: {}", e)),
                },
                Err(e) => Err(format!("Element not found: {}", e)),
            };
            if let Err(primary_error) = primary_click_result {
                if let Err(deep_error) = self.click_selector_deep(selector).await {
                    // Tier-2 fallback: resolve element geometry across open shadow roots/iframes,
                    // then issue a real pointer-style click via CDP coordinates.
                    match self.get_selector_rect_window_logical(selector).await {
                        Ok(rect) => {
                            let center = rect.center();
                            if let Err(geometry_error) =
                                self.synthetic_click(center.x, center.y).await
                            {
                                return Err(BrowserError::Internal(format!(
                                    "Primary click failed ({primary_error}); deep selector fallback failed: {deep_error}; geometry click fallback failed: {geometry_error}"
                                )));
                            }
                        }
                        Err(geometry_error) => {
                            return Err(BrowserError::Internal(format!(
                                "Primary click failed ({primary_error}); deep selector fallback failed: {deep_error}; geometry resolution failed: {geometry_error}"
                            )));
                        }
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(())
        } else {
            Err(BrowserError::NoActivePage)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_mouse_button_prefers_primary_pressed_button() {
        assert_eq!(BrowserDriver::active_mouse_button(0), None);
        assert_eq!(
            BrowserDriver::active_mouse_button(1),
            Some(MouseButton::Left)
        );
        assert_eq!(
            BrowserDriver::active_mouse_button(2),
            Some(MouseButton::Right)
        );
        assert_eq!(
            BrowserDriver::active_mouse_button(4),
            Some(MouseButton::Middle)
        );
        assert_eq!(
            BrowserDriver::active_mouse_button(8),
            Some(MouseButton::Back)
        );
        assert_eq!(
            BrowserDriver::active_mouse_button(16),
            Some(MouseButton::Forward)
        );
        assert_eq!(
            BrowserDriver::active_mouse_button(1 | 2 | 4),
            Some(MouseButton::Left)
        );
    }

    #[test]
    fn parse_keyboard_modifier_supports_aliases() {
        assert_eq!(
            BrowserDriver::parse_keyboard_modifier("ctrl").expect("ctrl alias"),
            ("Control", 2)
        );
        assert_eq!(
            BrowserDriver::parse_keyboard_modifier("cmd").expect("cmd alias"),
            ("Meta", 4)
        );
        assert_eq!(
            BrowserDriver::parse_keyboard_modifier("option").expect("option alias"),
            ("Alt", 1)
        );
        assert_eq!(
            BrowserDriver::parse_keyboard_modifier("shift").expect("shift alias"),
            ("Shift", 8)
        );
    }

    fn scrollable_outcome(
        scroll_top: i32,
        scroll_height: i32,
        client_height: i32,
        can_scroll_up: bool,
        can_scroll_down: bool,
    ) -> BrowserTypeOutcome {
        BrowserTypeOutcome {
            selector: Some("#text-area".to_string()),
            dom_id: Some("text-area".to_string()),
            tag_name: Some("textarea".to_string()),
            value: Some("Lorem ipsum".to_string()),
            focused: true,
            scroll_top: Some(scroll_top),
            scroll_height: Some(scroll_height),
            client_height: Some(client_height),
            can_scroll_up: Some(can_scroll_up),
            can_scroll_down: Some(can_scroll_down),
            already_satisfied: None,
            autocomplete: None,
        }
    }

    #[test]
    fn typed_text_request_already_satisfied_for_exact_match() {
        let outcome = BrowserTypeOutcome {
            selector: Some("#queue-search".to_string()),
            dom_id: Some("queue-search".to_string()),
            tag_name: Some("input".to_string()),
            value: Some("fiber".to_string()),
            focused: true,
            scroll_top: None,
            scroll_height: None,
            client_height: None,
            can_scroll_up: None,
            can_scroll_down: None,
            already_satisfied: None,
            autocomplete: None,
        };

        assert!(BrowserDriver::typed_text_request_already_satisfied(
            &outcome,
            "fiber"
        ));
    }

    #[test]
    fn typed_text_request_already_satisfied_rejects_different_or_unfocused_values() {
        let different = BrowserTypeOutcome {
            selector: Some("#queue-search".to_string()),
            dom_id: Some("queue-search".to_string()),
            tag_name: Some("input".to_string()),
            value: Some("fiber".to_string()),
            focused: true,
            scroll_top: None,
            scroll_height: None,
            client_height: None,
            can_scroll_up: None,
            can_scroll_down: None,
            already_satisfied: None,
            autocomplete: None,
        };
        let unfocused = BrowserTypeOutcome {
            focused: false,
            ..different.clone()
        };

        assert!(!BrowserDriver::typed_text_request_already_satisfied(
            &different,
            "fiber outage"
        ));
        assert!(!BrowserDriver::typed_text_request_already_satisfied(
            &unfocused,
            "fiber"
        ));
    }

    #[test]
    fn edge_jump_settle_key_requests_page_up_for_near_top_control_home() {
        let modifiers = vec!["Control".to_string()];
        let outcome = scrollable_outcome(2, 565, 104, true, true);

        assert_eq!(
            BrowserDriver::edge_jump_settle_key("Home", &modifiers, &outcome),
            Some("PageUp")
        );
    }

    #[test]
    fn edge_jump_settle_key_skips_page_up_when_not_near_top() {
        let modifiers = vec!["Control".to_string()];
        let outcome = scrollable_outcome(24, 565, 104, true, true);

        assert_eq!(
            BrowserDriver::edge_jump_settle_key("Home", &modifiers, &outcome),
            None
        );
    }

    #[test]
    fn edge_jump_settle_key_requests_page_down_for_near_bottom_control_end() {
        let modifiers = vec!["Control".to_string()];
        let outcome = scrollable_outcome(459, 565, 104, true, true);

        assert_eq!(
            BrowserDriver::edge_jump_settle_key("End", &modifiers, &outcome),
            Some("PageDown")
        );
    }
}
