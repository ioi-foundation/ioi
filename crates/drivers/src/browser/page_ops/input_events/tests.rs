    use super::*;
    use std::fs;
    use tempfile::tempdir;

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
            &outcome, "fiber"
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
            &unfocused, "fiber"
        ));
    }

    #[test]
    fn selector_probe_prefers_dom_click_for_container_controls() {
        let probe = SelectorProbe {
            found: true,
            visible: true,
            tag: "div".to_string(),
            ..SelectorProbe::default()
        };

        assert!(BrowserDriver::selector_probe_prefers_dom_click(&probe));
    }

    #[test]
    fn selector_probe_keeps_pointer_click_for_native_controls() {
        let probe = SelectorProbe {
            found: true,
            visible: true,
            tag: "button".to_string(),
            ..SelectorProbe::default()
        };

        assert!(!BrowserDriver::selector_probe_prefers_dom_click(&probe));
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
    fn edge_jump_settle_key_requests_page_up_within_one_visible_page_of_top() {
        let modifiers = vec!["Control".to_string()];
        let outcome = scrollable_outcome(75, 565, 104, true, true);

        assert_eq!(
            BrowserDriver::edge_jump_settle_key("Home", &modifiers, &outcome),
            Some("PageUp")
        );
    }

    #[test]
    fn edge_jump_settle_key_skips_page_up_when_more_than_one_page_from_top() {
        let modifiers = vec!["Control".to_string()];
        let outcome = scrollable_outcome(140, 565, 104, true, true);

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

    #[test]
    fn fractional_pointer_bridge_only_activates_for_subpixel_coords() {
        assert!(!BrowserDriver::needs_fractional_pointer_bridge(85.0, 107.0));
        assert!(BrowserDriver::needs_fractional_pointer_bridge(
            85.006, 107.0
        ));
        assert!(BrowserDriver::needs_fractional_pointer_bridge(
            85.0, 105.412
        ));
    }

    #[test]
    fn fractional_synthetic_click_script_dispatches_float_mouse_events() {
        let script = BrowserDriver::fractional_synthetic_click_script(
            85.006,
            105.412,
            &MouseButton::Left,
            0,
        )
        .expect("script should serialize fractional click");
        assert!(script.contains("const target = deepElementFromPoint(topX, topY);"));
        assert!(script.contains("clientX: localX"));
        assert!(script.contains("clientY: localY"));
        assert!(script.contains("Object.defineProperty(event, key"));
        assert!(script.contains("pageX,"));
        assert!(script.contains("pageY,"));
        assert!(script.contains("new ctor(type, init)"));
        assert!(script.contains("const finalEventType = \"click\";"));
        assert!(script.contains("currentDoc.defaultView && currentDoc.defaultView.frameElement"));
    }

    #[test]
    fn fractional_synthetic_click_script_uses_button_specific_terminal_events() {
        let middle_script =
            BrowserDriver::fractional_synthetic_click_script(40.25, 80.75, &MouseButton::Middle, 0)
                .expect("middle-button script should serialize");
        assert!(middle_script.contains("const finalEventType = \"auxclick\";"));

        let right_script =
            BrowserDriver::fractional_synthetic_click_script(12.5, 24.5, &MouseButton::Right, 0)
                .expect("right-button script should serialize");
        assert!(right_script.contains("const finalEventType = \"contextmenu\";"));
    }

    #[derive(Debug, serde::Deserialize)]
    struct RecordedSyntheticClick {
        target_id: Option<String>,
        current_target_id: Option<String>,
        client_x: f64,
        client_y: f64,
        page_x: f64,
        page_y: f64,
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "launches Chromium to probe fractional synthetic click coordinate fidelity"]
    async fn fractional_synthetic_click_preserves_browser_event_coordinates() {
        let fixture_dir = tempdir().expect("temp fixture dir");
        let fixture_path = fixture_dir.path().join("fractional-click-probe.html");
        fs::write(
            &fixture_path,
            r#"<!doctype html>
<html>
  <body style="margin:0">
    <div id="target" style="width:400px;height:300px;background:#dde7ff"></div>
    <script>
      window.__clicks = [];
      const target = document.getElementById("target");
      target.addEventListener("click", (event) => {
        window.__clicks.push({
          target_id: event.target && event.target.id ? event.target.id : null,
          current_target_id:
            event.currentTarget && event.currentTarget.id ? event.currentTarget.id : null,
          client_x: event.clientX,
          client_y: event.clientY,
          page_x: event.pageX,
          page_y: event.pageY,
        });
      });
    </script>
  </body>
</html>
"#,
        )
        .expect("fixture should write");
        let fixture_url = format!("file://{}", fixture_path.display());

        let driver = BrowserDriver::new();
        driver.set_lease(true);
        driver
            .navigate(&fixture_url)
            .await
            .expect("fixture should load");
        driver
            .synthetic_click(85.006, 105.412)
            .await
            .expect("fractional synthetic click should succeed");

        let recorded: Vec<RecordedSyntheticClick> = driver
            .evaluate_js("(() => window.__clicks || [])()")
            .await
            .expect("click record should decode");
        driver.force_reset().await;

        let click = recorded.first().expect("fixture should record a click");
        assert_eq!(click.target_id.as_deref(), Some("target"));
        assert_eq!(click.current_target_id.as_deref(), Some("target"));
        assert!((click.client_x - 85.006).abs() < 0.01, "{click:?}");
        assert!((click.client_y - 105.412).abs() < 0.01, "{click:?}");
        assert!((click.page_x - 85.006).abs() < 0.01, "{click:?}");
        assert!((click.page_y - 105.412).abs() < 0.01, "{click:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "launches Chromium to probe legacy window.event click handlers"]
    async fn fractional_synthetic_click_supports_legacy_window_event_handlers() {
        let fixture_dir = tempdir().expect("temp fixture dir");
        let fixture_path = fixture_dir
            .path()
            .join("fractional-click-window-event.html");
        fs::write(
            &fixture_path,
            r#"<!doctype html>
<html>
  <body style="margin:0">
    <div id="target" style="width:400px;height:300px;background:#ffe8d6"></div>
    <script>
      window.__clicks = [];
      function recordClicked(observedEvent) {
        window.__clicks.push({
          page_x: observedEvent.pageX,
          page_y: observedEvent.pageY,
          client_x: observedEvent.clientX,
          client_y: observedEvent.clientY,
        });
      }
      const target = document.getElementById("target");
      target.addEventListener("click", function() {
        recordClicked(event);
      });
    </script>
  </body>
</html>
"#,
        )
        .expect("fixture should write");
        let fixture_url = format!("file://{}", fixture_path.display());

        let driver = BrowserDriver::new();
        driver.set_lease(true);
        driver
            .navigate(&fixture_url)
            .await
            .expect("fixture should load");
        driver
            .synthetic_click(85.006, 105.412)
            .await
            .expect("fractional synthetic click should succeed");

        let recorded: Vec<RecordedSyntheticClick> = driver
            .evaluate_js("(() => window.__clicks || [])()")
            .await
            .expect("click record should decode");
        driver.force_reset().await;

        let click = recorded
            .first()
            .expect("legacy window.event fixture should record a click");
        assert!((click.client_x - 85.006).abs() < 0.01, "{click:?}");
        assert!((click.client_y - 105.412).abs() < 0.01, "{click:?}");
        assert!((click.page_x - 85.006).abs() < 0.01, "{click:?}");
        assert!((click.page_y - 105.412).abs() < 0.01, "{click:?}");
    }
