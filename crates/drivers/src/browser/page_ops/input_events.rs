impl BrowserDriver {
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
    ) -> std::result::Result<(), BrowserError> {
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
        let (cx, cy) = if pointer_in_viewport {
            (pointer.x, pointer.y)
        } else {
            (
                viewport.client_width as f64 / 2.0,
                viewport.client_height as f64 / 2.0,
            )
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
        Ok(())
    }

    pub async fn type_text(
        &self,
        text: &str,
        selector: Option<&str>,
    ) -> std::result::Result<(), BrowserError> {
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

        page.execute(InsertTextParams::new(text))
            .await
            .map_err(|e| BrowserError::Internal(format!("Type failed: {}", e)))?;

        if !text.is_empty() {
            self.dispatch_text_keyup(selector, text).await?;
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(())
    }

    pub async fn press_key(
        &self,
        key: &str,
        modifiers: &[String],
    ) -> std::result::Result<(), BrowserError> {
        let key = key.trim();
        if key.is_empty() {
            return Err(BrowserError::Internal("Key cannot be empty".to_string()));
        }

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
        Ok(())
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
}
