use super::render_browser_use_state_text;
use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
use std::collections::HashMap;

fn node(
    role: &str,
    name: Option<&str>,
    attrs: &[(&str, &str)],
    som_id: Option<u32>,
    children: Vec<AccessibilityNode>,
) -> AccessibilityNode {
    AccessibilityNode {
        id: format!("node-{role}"),
        role: role.to_string(),
        name: name.map(str::to_string),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 10,
            height: 10,
        },
        children,
        is_visible: true,
        attributes: attrs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<HashMap<_, _>>(),
        som_id,
    }
}

#[test]
fn render_browser_use_state_text_includes_interactive_and_iframe_hints() {
    let tree = node(
        "root",
        None,
        &[],
        None,
        vec![node(
            "iframe",
            Some("Embedded"),
            &[
                ("tag_name", "iframe"),
                ("hidden_below_count", "2"),
                ("hidden_below", "textbox:Search@1.1p|button:Submit@1.5p"),
            ],
            None,
            vec![
                node(
                    "button",
                    Some("Submit"),
                    &[("tag_name", "button")],
                    Some(3),
                    vec![],
                ),
                node("StaticText", Some("Helpful text"), &[], None, vec![]),
            ],
        )],
    );

    let text = render_browser_use_state_text(&tree).expect("state text");

    assert!(text.contains("|IFRAME|<iframe name=Embedded hidden_below_count=2"));
    assert!(text.contains("[3]<button name=Submit"));
    assert!(text.contains("Helpful text"));
    assert!(text.contains("... (2 more elements below - scroll to reveal):"));
    assert!(text.contains("<textbox> \"Search\" ~1.1 pages down"));
}
