use super::{
    inline_value, BrowserUseCompoundChild, BrowserUseDomTreeNode, BROWSER_USE_INCLUDE_ATTRS,
};
use crate::browser::dom_ops::browser_use::BrowserUseDomRect;
use std::collections::HashSet;

const DISABLED_ELEMENTS: &[&str] = &["style", "script", "head", "meta", "link", "title"];
const SVG_ELEMENTS: &[&str] = &[
    "path", "rect", "g", "circle", "ellipse", "line", "polyline", "polygon", "use", "defs",
    "clipPath", "mask", "pattern", "image", "text", "tspan",
];
const CONTAINMENT_THRESHOLD: f64 = 0.99;

#[derive(Debug, Clone)]
struct PropagatingBounds {
    bounds: BrowserUseDomRect,
}

#[derive(Debug, Clone, Copy)]
struct PaintRect {
    x1: f64,
    y1: f64,
    x2: f64,
    y2: f64,
}

impl PaintRect {
    fn contains(self, other: PaintRect) -> bool {
        self.x1 <= other.x1 && self.y1 <= other.y1 && self.x2 >= other.x2 && self.y2 >= other.y2
    }

    fn intersects(self, other: PaintRect) -> bool {
        !(self.x2 <= other.x1 || other.x2 <= self.x1 || self.y2 <= other.y1 || other.y2 <= self.y1)
    }
}

#[derive(Default)]
struct RectUnion {
    rects: Vec<PaintRect>,
}

impl RectUnion {
    fn split_diff(a: PaintRect, b: PaintRect) -> Vec<PaintRect> {
        let mut parts = Vec::new();

        if a.y1 < b.y1 {
            parts.push(PaintRect {
                x1: a.x1,
                y1: a.y1,
                x2: a.x2,
                y2: b.y1,
            });
        }
        if b.y2 < a.y2 {
            parts.push(PaintRect {
                x1: a.x1,
                y1: b.y2,
                x2: a.x2,
                y2: a.y2,
            });
        }

        let y_lo = a.y1.max(b.y1);
        let y_hi = a.y2.min(b.y2);

        if a.x1 < b.x1 {
            parts.push(PaintRect {
                x1: a.x1,
                y1: y_lo,
                x2: b.x1,
                y2: y_hi,
            });
        }
        if b.x2 < a.x2 {
            parts.push(PaintRect {
                x1: b.x2,
                y1: y_lo,
                x2: a.x2,
                y2: y_hi,
            });
        }

        parts
    }

    fn contains(&self, rect: PaintRect) -> bool {
        if self.rects.is_empty() {
            return false;
        }

        let mut stack = vec![rect];
        for existing in &self.rects {
            let mut next = Vec::new();
            for piece in stack {
                if existing.contains(piece) {
                    continue;
                }
                if piece.intersects(*existing) {
                    next.extend(Self::split_diff(piece, *existing));
                } else {
                    next.push(piece);
                }
            }
            if next.is_empty() {
                return true;
            }
            stack = next;
        }

        false
    }

    fn add(&mut self, rect: PaintRect) {
        if self.contains(rect) {
            return;
        }

        let mut pending = vec![rect];
        for existing in &self.rects {
            let mut next = Vec::new();
            for piece in pending {
                if piece.intersects(*existing) {
                    next.extend(Self::split_diff(piece, *existing));
                } else {
                    next.push(piece);
                }
            }
            pending = next;
        }

        self.rects.extend(pending);
    }
}

fn cap_text_length(value: &str, max_chars: usize) -> String {
    let compact = inline_value(value);
    let mut chars = compact.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

fn push_attr(attrs: &mut Vec<(String, String)>, key: impl Into<String>, value: impl Into<String>) {
    let key = key.into();
    if attrs.iter().any(|(existing_key, _)| existing_key == &key) {
        return;
    }

    let value = value.into();
    if value.trim().is_empty() {
        return;
    }

    attrs.push((key, value));
}

fn upsert_attr(
    attrs: &mut Vec<(String, String)>,
    key: impl Into<String>,
    value: impl Into<String>,
) {
    let key = key.into();
    let value = value.into();
    if value.trim().is_empty() {
        return;
    }

    if let Some((_, existing_value)) = attrs
        .iter_mut()
        .find(|(existing_key, _)| existing_key == &key)
    {
        *existing_value = value;
    } else {
        attrs.push((key, value));
    }
}

fn remove_attr(attrs: &mut Vec<(String, String)>, key: &str) {
    attrs.retain(|(existing_key, _)| existing_key != key);
}

fn input_format_hint(input_type: &str) -> Option<&'static str> {
    match input_type {
        "date" => Some("YYYY-MM-DD"),
        "time" => Some("HH:MM"),
        "datetime-local" => Some("YYYY-MM-DDTHH:MM"),
        "month" => Some("YYYY-MM"),
        "week" => Some("YYYY-W##"),
        _ => None,
    }
}

fn current_field_value(node: &BrowserUseDomTreeNode) -> Option<String> {
    if matches!(
        node.tag_name().as_deref(),
        Some("input" | "textarea" | "select")
    ) {
        if let Some(value) = node.ax_data.properties.get("valuetext").map(String::as_str) {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
        if let Some(value) = node.ax_data.properties.get("value").map(String::as_str) {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }

    node.attributes
        .get("value")
        .map(String::as_str)
        .or_else(|| node.text_value())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn append_input_hints(node: &BrowserUseDomTreeNode, attrs: &mut Vec<(String, String)>) {
    if !matches!(node.tag_name().as_deref(), Some("input")) {
        return;
    }

    let input_type = node
        .attributes
        .get("type")
        .map(String::as_str)
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();

    if let Some(format_hint) = input_format_hint(&input_type) {
        push_attr(attrs, "format", format_hint);
        if !attrs.iter().any(|(key, _)| key == "placeholder") {
            push_attr(attrs, "placeholder", format_hint);
        }
        return;
    }

    if input_type == "tel" && !attrs.iter().any(|(key, _)| key == "pattern") {
        push_attr(attrs, "placeholder", "123-456-7890");
    }

    if !matches!(input_type.as_str(), "" | "text") {
        return;
    }

    if let Some(date_format) = node
        .attributes
        .get("uib-datepicker-popup")
        .map(String::as_str)
    {
        let date_format = date_format.trim();
        if !date_format.is_empty() {
            push_attr(attrs, "expected_format", date_format);
            push_attr(attrs, "format", date_format);
            return;
        }
    }

    let class_attr = node
        .attributes
        .get("class")
        .map(String::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let has_datepicker_class = ["datepicker", "datetimepicker", "daterangepicker"]
        .iter()
        .any(|indicator| class_attr.contains(indicator));
    let has_data_datepicker = node.attributes.contains_key("data-datepicker");

    if !(has_datepicker_class || has_data_datepicker) {
        return;
    }

    let date_format = node
        .attributes
        .get("data-date-format")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("mm/dd/yyyy");
    push_attr(attrs, "placeholder", date_format);
    push_attr(attrs, "format", date_format);
}

fn render_compound_children(node: &BrowserUseDomTreeNode) -> Option<String> {
    if node.compound_children.is_empty() {
        return None;
    }

    let entries = node
        .compound_children
        .iter()
        .filter_map(|child| {
            let mut parts = Vec::new();
            if let Some(name) = child
                .name
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                parts.push(format!("name={}", inline_value(name)));
            }
            if let Some(role) = child
                .role
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                parts.push(format!("role={}", inline_value(role)));
            }
            if let Some(min) = child
                .valuemin
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                parts.push(format!("min={}", inline_value(min)));
            }
            if let Some(max) = child
                .valuemax
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                parts.push(format!("max={}", inline_value(max)));
            }
            if let Some(current) = child
                .valuenow
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                parts.push(format!("current={}", inline_value(current)));
            }
            if let Some(count) = child.options_count {
                parts.push(format!("count={count}"));
            }
            if !child.first_options.is_empty() {
                parts.push(format!(
                    "options={}",
                    child
                        .first_options
                        .iter()
                        .map(|option| inline_value(option))
                        .collect::<Vec<_>>()
                        .join("|")
                ));
            }
            if let Some(format_hint) = child
                .format_hint
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                parts.push(format!("format={}", inline_value(format_hint)));
            }
            (!parts.is_empty()).then(|| format!("({})", parts.join(",")))
        })
        .collect::<Vec<_>>();

    (!entries.is_empty()).then(|| entries.join(","))
}

pub(super) fn build_attributes_string(node: &BrowserUseDomTreeNode) -> String {
    let mut attrs = Vec::new();
    let is_password_field = node.is_password_input();

    if let Some(name) = node.name_for_render() {
        push_attr(&mut attrs, "name", inline_value(&name));
    }

    if !is_password_field {
        if let Some(value) = current_field_value(node) {
            push_attr(&mut attrs, "value", inline_value(&value));
        }
    }

    for key in BROWSER_USE_INCLUDE_ATTRS {
        let Some(value) = node.attributes.get(*key).map(String::as_str) else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if is_password_field && matches!(*key, "value" | "valuetext") {
            continue;
        }
        push_attr(&mut attrs, *key, inline_value(value));
    }

    append_input_hints(node, &mut attrs);

    for key in [
        "checked",
        "selected",
        "expanded",
        "pressed",
        "disabled",
        "invalid",
        "valuemin",
        "valuemax",
        "valuenow",
        "keyshortcuts",
        "haspopup",
        "multiselectable",
        "required",
        "valuetext",
        "level",
        "busy",
        "live",
    ] {
        let Some(value) = node.ax_data.properties.get(key).map(String::as_str) else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if is_password_field && matches!(key, "value" | "valuetext") {
            continue;
        }
        push_attr(&mut attrs, key, inline_value(value));
    }

    if matches!(
        node.tag_name().as_deref(),
        Some("input" | "textarea" | "select")
    ) && !is_password_field
    {
        if let Some(value) = current_field_value(node) {
            upsert_attr(&mut attrs, "value", inline_value(&value));
        }
    }

    if let Some(compound_components) = render_compound_children(node) {
        push_attr(&mut attrs, "compound_components", compound_components);
    }

    let mut seen_values = HashSet::new();
    let protected_attrs = [
        "format",
        "expected_format",
        "placeholder",
        "value",
        "aria-label",
        "title",
    ];
    attrs.retain(|(key, value)| {
        if protected_attrs.contains(&key.as_str()) || value.chars().count() <= 5 {
            return true;
        }
        seen_values.insert((key.clone(), value.clone()))
            || !seen_values.iter().any(|(_, seen)| seen == value)
    });

    if let Some(tag_name) = node.tag_name() {
        if attrs
            .iter()
            .find(|(key, value)| key == "role" && value.eq_ignore_ascii_case(&tag_name))
            .is_some()
        {
            remove_attr(&mut attrs, "role");
        }
        if attrs
            .iter()
            .find(|(key, value)| key == "type" && value.eq_ignore_ascii_case(&tag_name))
            .is_some()
        {
            remove_attr(&mut attrs, "type");
        }
    }

    if attrs
        .iter()
        .find(|(key, value)| key == "invalid" && value.eq_ignore_ascii_case("false"))
        .is_some()
    {
        remove_attr(&mut attrs, "invalid");
    }
    if attrs.iter().any(|(key, value)| {
        key == "required" && matches!(value.to_ascii_lowercase().as_str(), "false" | "0" | "no")
    }) {
        remove_attr(&mut attrs, "required");
    }
    if attrs.iter().any(|(key, _)| key == "expanded") {
        remove_attr(&mut attrs, "aria-expanded");
    }

    attrs
        .into_iter()
        .filter_map(|(key, value)| {
            let value = cap_text_length(&value, 100);
            if value.is_empty() {
                Some(format!("{key}=''"))
            } else {
                Some(format!("{key}={value}"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Clone)]
struct SelectOptionsInfo {
    count: usize,
    first_options: Vec<String>,
    format_hint: Option<String>,
}

fn direct_text_value(node: &BrowserUseDomTreeNode) -> String {
    let mut text = String::new();
    for child in &node.children {
        if child.node_type == 3 {
            if let Some(value) = child.text_value() {
                if !value.is_empty() {
                    if !text.is_empty() {
                        text.push(' ');
                    }
                    text.push_str(value);
                }
            }
        }
    }
    inline_value(&text)
}

fn extract_select_options(node: &BrowserUseDomTreeNode) -> Option<SelectOptionsInfo> {
    let mut options = Vec::new();
    let mut option_values = Vec::new();

    fn recurse(
        node: &BrowserUseDomTreeNode,
        options: &mut Vec<(String, String)>,
        option_values: &mut Vec<String>,
    ) {
        let tag_name = node.tag_name().unwrap_or_default();
        if tag_name == "option" {
            let option_text = direct_text_value(node);
            let option_value = node
                .attributes
                .get("value")
                .map(String::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| option_text.clone());
            if !option_text.is_empty() || !option_value.is_empty() {
                options.push((option_text.clone(), option_value.clone()));
                option_values.push(option_value);
            }
            return;
        }

        for child in &node.children {
            recurse(child, options, option_values);
        }
    }

    for child in &node.children {
        recurse(child, &mut options, &mut option_values);
    }

    if options.is_empty() {
        return None;
    }

    let mut first_options = options
        .iter()
        .take(4)
        .filter_map(|(text, value)| {
            let display = if !text.trim().is_empty() { text } else { value };
            (!display.trim().is_empty()).then(|| cap_text_length(display, 30))
        })
        .collect::<Vec<_>>();
    if options.len() > 4 {
        first_options.push(format!("... {} more options...", options.len() - 4));
    }

    let format_hint = if option_values.len() >= 2 {
        let sample = option_values
            .iter()
            .take(5)
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if !sample.is_empty()
            && sample
                .iter()
                .all(|value| value.chars().all(|ch| ch.is_ascii_digit()))
        {
            Some("numeric".to_string())
        } else if !sample.is_empty()
            && sample
                .iter()
                .all(|value| value.len() == 2 && value.chars().all(|ch| ch.is_ascii_uppercase()))
        {
            Some("country/state codes".to_string())
        } else if sample.iter().any(|value| value.contains('@')) {
            Some("email addresses".to_string())
        } else if sample
            .iter()
            .all(|value| value.contains('/') || value.contains('-'))
        {
            Some("date/path format".to_string())
        } else {
            None
        }
    } else {
        None
    };

    Some(SelectOptionsInfo {
        count: options.len(),
        first_options,
        format_hint,
    })
}

fn populate_compound_children(node: &mut BrowserUseDomTreeNode) {
    node.compound_children.clear();

    for shadow_root in &mut node.shadow_roots {
        populate_compound_children(shadow_root);
    }
    for child in &mut node.children {
        populate_compound_children(child);
    }
    if let Some(content_document) = node.content_document.as_deref_mut() {
        populate_compound_children(content_document);
    }

    let Some(tag_name) = node.tag_name() else {
        return;
    };
    if !matches!(
        tag_name.as_str(),
        "input" | "select" | "details" | "audio" | "video"
    ) {
        return;
    }

    if tag_name == "input" {
        let input_type = node
            .attributes
            .get("type")
            .map(String::as_str)
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        match input_type.as_str() {
            "date" | "time" | "datetime-local" | "month" | "week" => {}
            "range" => {
                node.compound_children.push(BrowserUseCompoundChild {
                    role: Some("slider".to_string()),
                    name: Some("Value".to_string()),
                    valuemin: node
                        .attributes
                        .get("min")
                        .cloned()
                        .or_else(|| Some("0".to_string())),
                    valuemax: node
                        .attributes
                        .get("max")
                        .cloned()
                        .or_else(|| Some("100".to_string())),
                    valuenow: None,
                    ..BrowserUseCompoundChild::default()
                });
            }
            "number" => {
                node.compound_children.push(BrowserUseCompoundChild {
                    role: Some("button".to_string()),
                    name: Some("Increment".to_string()),
                    ..BrowserUseCompoundChild::default()
                });
                node.compound_children.push(BrowserUseCompoundChild {
                    role: Some("button".to_string()),
                    name: Some("Decrement".to_string()),
                    ..BrowserUseCompoundChild::default()
                });
                node.compound_children.push(BrowserUseCompoundChild {
                    role: Some("textbox".to_string()),
                    name: Some("Value".to_string()),
                    valuemin: node.attributes.get("min").cloned(),
                    valuemax: node.attributes.get("max").cloned(),
                    ..BrowserUseCompoundChild::default()
                });
            }
            "color" => {
                node.compound_children.push(BrowserUseCompoundChild {
                    role: Some("textbox".to_string()),
                    name: Some("Hex Value".to_string()),
                    ..BrowserUseCompoundChild::default()
                });
                node.compound_children.push(BrowserUseCompoundChild {
                    role: Some("button".to_string()),
                    name: Some("Color Picker".to_string()),
                    ..BrowserUseCompoundChild::default()
                });
            }
            "file" => {
                let multiple = node.attributes.contains_key("multiple");
                let current_value = node
                    .ax_data
                    .properties
                    .get("valuetext")
                    .cloned()
                    .or_else(|| {
                        node.ax_data.properties.get("value").map(|value| {
                            value
                                .rsplit(['\\', '/'])
                                .next()
                                .unwrap_or(value.as_str())
                                .to_string()
                        })
                    })
                    .filter(|value| {
                        let normalized = value.trim().to_ascii_lowercase();
                        !normalized.is_empty()
                            && !matches!(normalized.as_str(), "no file chosen" | "no file selected")
                    })
                    .unwrap_or_else(|| "None".to_string());
                node.compound_children.push(BrowserUseCompoundChild {
                    role: Some("button".to_string()),
                    name: Some("Browse Files".to_string()),
                    ..BrowserUseCompoundChild::default()
                });
                node.compound_children.push(BrowserUseCompoundChild {
                    role: Some("textbox".to_string()),
                    name: Some(if multiple {
                        "Files Selected".to_string()
                    } else {
                        "File Selected".to_string()
                    }),
                    valuenow: Some(current_value),
                    ..BrowserUseCompoundChild::default()
                });
            }
            _ => {}
        }
        return;
    }

    if tag_name == "select" {
        node.compound_children.push(BrowserUseCompoundChild {
            role: Some("button".to_string()),
            name: Some("Dropdown Toggle".to_string()),
            ..BrowserUseCompoundChild::default()
        });
        let options_info = extract_select_options(node);
        node.compound_children.push(BrowserUseCompoundChild {
            role: Some("listbox".to_string()),
            name: Some("Options".to_string()),
            options_count: options_info.as_ref().map(|info| info.count),
            first_options: options_info
                .as_ref()
                .map(|info| info.first_options.clone())
                .unwrap_or_default(),
            format_hint: options_info.and_then(|info| info.format_hint),
            ..BrowserUseCompoundChild::default()
        });
        return;
    }

    if tag_name == "details" {
        node.compound_children.push(BrowserUseCompoundChild {
            role: Some("button".to_string()),
            name: Some("Toggle Disclosure".to_string()),
            ..BrowserUseCompoundChild::default()
        });
        node.compound_children.push(BrowserUseCompoundChild {
            role: Some("region".to_string()),
            name: Some("Content Area".to_string()),
            ..BrowserUseCompoundChild::default()
        });
        return;
    }

    if tag_name == "audio" {
        node.compound_children.extend([
            BrowserUseCompoundChild {
                role: Some("button".to_string()),
                name: Some("Play/Pause".to_string()),
                ..BrowserUseCompoundChild::default()
            },
            BrowserUseCompoundChild {
                role: Some("slider".to_string()),
                name: Some("Progress".to_string()),
                valuemin: Some("0".to_string()),
                valuemax: Some("100".to_string()),
                ..BrowserUseCompoundChild::default()
            },
            BrowserUseCompoundChild {
                role: Some("button".to_string()),
                name: Some("Mute".to_string()),
                ..BrowserUseCompoundChild::default()
            },
            BrowserUseCompoundChild {
                role: Some("slider".to_string()),
                name: Some("Volume".to_string()),
                valuemin: Some("0".to_string()),
                valuemax: Some("100".to_string()),
                ..BrowserUseCompoundChild::default()
            },
        ]);
        return;
    }

    if tag_name == "video" {
        node.compound_children.extend([
            BrowserUseCompoundChild {
                role: Some("button".to_string()),
                name: Some("Play/Pause".to_string()),
                ..BrowserUseCompoundChild::default()
            },
            BrowserUseCompoundChild {
                role: Some("slider".to_string()),
                name: Some("Progress".to_string()),
                valuemin: Some("0".to_string()),
                valuemax: Some("100".to_string()),
                ..BrowserUseCompoundChild::default()
            },
            BrowserUseCompoundChild {
                role: Some("button".to_string()),
                name: Some("Mute".to_string()),
                ..BrowserUseCompoundChild::default()
            },
            BrowserUseCompoundChild {
                role: Some("slider".to_string()),
                name: Some("Volume".to_string()),
                valuemin: Some("0".to_string()),
                valuemax: Some("100".to_string()),
                ..BrowserUseCompoundChild::default()
            },
            BrowserUseCompoundChild {
                role: Some("button".to_string()),
                name: Some("Fullscreen".to_string()),
                ..BrowserUseCompoundChild::default()
            },
        ]);
    }
}

fn reset_render_state(node: &mut BrowserUseDomTreeNode) {
    node.should_display = true;
    node.assigned_interactive = false;
    node.is_new = false;
    node.ignored_by_paint_order = false;
    node.excluded_by_parent = false;
    node.is_shadow_host = !node.shadow_roots.is_empty();

    for shadow_root in &mut node.shadow_roots {
        reset_render_state(shadow_root);
    }
    for child in &mut node.children {
        reset_render_state(child);
    }
    if let Some(content_document) = node.content_document.as_deref_mut() {
        reset_render_state(content_document);
    }
}

fn compute_displayability(node: &mut BrowserUseDomTreeNode) -> bool {
    let mut has_displayable_descendants = false;
    for shadow_root in &mut node.shadow_roots {
        has_displayable_descendants |= compute_displayability(shadow_root);
    }
    for child in &mut node.children {
        has_displayable_descendants |= compute_displayability(child);
    }
    if let Some(content_document) = node.content_document.as_deref_mut() {
        has_displayable_descendants |= compute_displayability(content_document);
    }

    let should_display = match node.node_type {
        9 => has_displayable_descendants,
        11 => has_displayable_descendants,
        3 => node
            .text_value()
            .is_some_and(|value| node.is_visible && value.len() > 1),
        1 => {
            let tag_name = node.tag_name().unwrap_or_default();
            if DISABLED_ELEMENTS.contains(&tag_name.as_str()) {
                false
            } else if SVG_ELEMENTS.contains(&tag_name.as_str()) {
                false
            } else if node
                .attributes
                .get("data-browser-use-exclude")
                .is_some_and(|value| value.eq_ignore_ascii_case("true"))
            {
                false
            } else {
                let has_validation_attrs = !node.is_visible
                    && node
                        .attributes
                        .keys()
                        .any(|attr| attr.starts_with("aria-") || attr.starts_with("pseudo"));
                node.is_visible
                    || node.is_scrollable()
                    || has_displayable_descendants
                    || has_validation_attrs
                    || node.is_file_input()
            }
        }
        _ => has_displayable_descendants,
    };

    node.should_display = should_display;
    should_display
}

#[derive(Debug, Clone)]
struct PaintOrderEntry {
    path: String,
    paint_order: i64,
    rect: PaintRect,
    transparent: bool,
    low_opacity: bool,
}

fn collect_paint_order_entries(
    node: &BrowserUseDomTreeNode,
    path: String,
    out: &mut Vec<PaintOrderEntry>,
) {
    if node.should_display {
        if let Some(snapshot) = node.snapshot.as_ref() {
            if let (Some(paint_order), Some(bounds)) =
                (snapshot.paint_order, snapshot.bounds.as_ref())
            {
                out.push(PaintOrderEntry {
                    path: path.clone(),
                    paint_order,
                    rect: PaintRect {
                        x1: bounds.x,
                        y1: bounds.y,
                        x2: bounds.x + bounds.width,
                        y2: bounds.y + bounds.height,
                    },
                    transparent: snapshot
                        .computed_styles
                        .get("background-color")
                        .map(String::as_str)
                        .unwrap_or("rgba(0, 0, 0, 0)")
                        == "rgba(0, 0, 0, 0)",
                    low_opacity: snapshot
                        .computed_styles
                        .get("opacity")
                        .and_then(|value| value.parse::<f64>().ok())
                        .is_some_and(|opacity| opacity < 0.8),
                });
            }
        }
    }

    for (idx, shadow_root) in node.shadow_roots.iter().enumerate() {
        collect_paint_order_entries(shadow_root, format!("{path}/s{idx}"), out);
    }
    for (idx, child) in node.children.iter().enumerate() {
        collect_paint_order_entries(child, format!("{path}/c{idx}"), out);
    }
    if let Some(content_document) = node.content_document.as_deref() {
        collect_paint_order_entries(content_document, format!("{path}/d"), out);
    }
}

fn mark_ignored_by_paint_order(
    node: &mut BrowserUseDomTreeNode,
    path: String,
    ignored: &HashSet<String>,
) {
    node.ignored_by_paint_order = ignored.contains(&path);

    for (idx, shadow_root) in node.shadow_roots.iter_mut().enumerate() {
        mark_ignored_by_paint_order(shadow_root, format!("{path}/s{idx}"), ignored);
    }
    for (idx, child) in node.children.iter_mut().enumerate() {
        mark_ignored_by_paint_order(child, format!("{path}/c{idx}"), ignored);
    }
    if let Some(content_document) = node.content_document.as_deref_mut() {
        mark_ignored_by_paint_order(content_document, format!("{path}/d"), ignored);
    }
}

fn apply_paint_order_filtering(root: &mut BrowserUseDomTreeNode) {
    let mut entries = Vec::new();
    collect_paint_order_entries(root, "root".to_string(), &mut entries);
    entries.sort_by(|left, right| right.paint_order.cmp(&left.paint_order));

    let mut ignored_paths = HashSet::new();
    let mut rect_union = RectUnion::default();
    let mut current_paint_order = None;
    let mut batch = Vec::new();

    let flush_batch = |batch: &mut Vec<PaintOrderEntry>,
                       rect_union: &mut RectUnion,
                       ignored_paths: &mut HashSet<String>| {
        if batch.is_empty() {
            return;
        }

        for entry in batch.iter() {
            if rect_union.contains(entry.rect) {
                ignored_paths.insert(entry.path.clone());
            }
        }
        for entry in batch.iter() {
            if !(entry.transparent || entry.low_opacity) {
                rect_union.add(entry.rect);
            }
        }
        batch.clear();
    };

    for entry in entries {
        if current_paint_order != Some(entry.paint_order) {
            flush_batch(&mut batch, &mut rect_union, &mut ignored_paths);
            current_paint_order = Some(entry.paint_order);
        }
        batch.push(entry);
    }
    flush_batch(&mut batch, &mut rect_union, &mut ignored_paths);

    mark_ignored_by_paint_order(root, "root".to_string(), &ignored_paths);
}

fn is_propagating_element(node: &BrowserUseDomTreeNode) -> bool {
    let tag = node.tag_name().unwrap_or_default();
    let role = node
        .attributes
        .get("role")
        .map(String::as_str)
        .map(str::trim)
        .map(str::to_ascii_lowercase);
    matches!(
        (tag.as_str(), role.as_deref()),
        ("a", _)
            | ("button", _)
            | ("div", Some("button"))
            | ("div", Some("combobox"))
            | ("span", Some("button"))
            | ("span", Some("combobox"))
            | ("input", Some("combobox"))
    )
}

fn containment_ratio(child: &BrowserUseDomRect, parent: &BrowserUseDomRect) -> f64 {
    let x_overlap =
        0.0_f64.max((child.x + child.width).min(parent.x + parent.width) - child.x.max(parent.x));
    let y_overlap =
        0.0_f64.max((child.y + child.height).min(parent.y + parent.height) - child.y.max(parent.y));
    let intersection_area = x_overlap * y_overlap;
    let child_area = child.width * child.height;
    if child_area <= 0.0 {
        0.0
    } else {
        intersection_area / child_area
    }
}

fn should_exclude_child(node: &BrowserUseDomTreeNode, active_bounds: PropagatingBounds) -> bool {
    if node.node_type == 3 {
        return false;
    }

    let Some(child_bounds) = node
        .snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.bounds.as_ref())
    else {
        return false;
    };
    if containment_ratio(child_bounds, &active_bounds.bounds) < CONTAINMENT_THRESHOLD {
        return false;
    }

    let tag_name = node.tag_name().unwrap_or_default();
    if matches!(tag_name.as_str(), "input" | "select" | "textarea" | "label") {
        return false;
    }
    if is_propagating_element(node) {
        return false;
    }
    if node.attributes.contains_key("onclick") {
        return false;
    }
    if node
        .attributes
        .get("aria-label")
        .map(String::as_str)
        .is_some_and(|value| !value.trim().is_empty())
    {
        return false;
    }
    if node
        .attributes
        .get("role")
        .map(String::as_str)
        .is_some_and(|role| {
            matches!(
                role.trim().to_ascii_lowercase().as_str(),
                "button" | "link" | "checkbox" | "radio" | "tab" | "menuitem" | "option"
            )
        })
    {
        return false;
    }

    true
}

fn apply_bounding_box_filtering_recursive(
    node: &mut BrowserUseDomTreeNode,
    active_bounds: Option<PropagatingBounds>,
) {
    if let Some(active_bounds) = active_bounds.as_ref() {
        if should_exclude_child(node, active_bounds.clone()) {
            node.excluded_by_parent = true;
        }
    }

    let next_bounds = if is_propagating_element(node) {
        node.snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.bounds.as_ref())
            .cloned()
            .map(|bounds| PropagatingBounds { bounds })
            .or(active_bounds)
    } else {
        active_bounds
    };

    for shadow_root in &mut node.shadow_roots {
        apply_bounding_box_filtering_recursive(shadow_root, next_bounds.clone());
    }
    for child in &mut node.children {
        apply_bounding_box_filtering_recursive(child, next_bounds.clone());
    }
    if let Some(content_document) = node.content_document.as_deref_mut() {
        apply_bounding_box_filtering_recursive(content_document, next_bounds);
    }
}

fn has_candidate_interactive_descendants(node: &BrowserUseDomTreeNode) -> bool {
    node.shadow_roots
        .iter()
        .any(|child| child.is_interactive() || has_candidate_interactive_descendants(child))
        || node
            .children
            .iter()
            .any(|child| child.is_interactive() || has_candidate_interactive_descendants(child))
        || node.content_document.as_deref().is_some_and(|child| {
            child.is_interactive() || has_candidate_interactive_descendants(child)
        })
}

fn should_make_scrollable_interactive(node: &BrowserUseDomTreeNode) -> bool {
    let role = node
        .attributes
        .get("role")
        .map(String::as_str)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let tag_name = node.tag_name().unwrap_or_default();
    let class_attr = node
        .attributes
        .get("class")
        .map(String::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let class_list = class_attr.split_whitespace().collect::<Vec<_>>();

    let is_dropdown_container = matches!(
        role.as_str(),
        "listbox" | "menu" | "combobox" | "menubar" | "tree" | "grid"
    ) || tag_name == "select"
        || class_list.contains(&"dropdown")
        || class_list.contains(&"dropdown-menu")
        || class_list.contains(&"select-menu")
        || (class_list.contains(&"ui") && class_attr.contains("dropdown"));

    is_dropdown_container || !has_candidate_interactive_descendants(node)
}

fn assign_interactive_flags(node: &mut BrowserUseDomTreeNode) {
    node.assigned_interactive = false;
    if !node.excluded_by_parent && !node.ignored_by_paint_order {
        let is_interactive = node.is_interactive();
        let should_make_interactive = if node.is_scrollable() {
            should_make_scrollable_interactive(node)
        } else {
            is_interactive && (node.is_visible || node.is_file_input())
        };
        node.assigned_interactive = should_make_interactive;
    }

    for shadow_root in &mut node.shadow_roots {
        assign_interactive_flags(shadow_root);
    }
    for child in &mut node.children {
        assign_interactive_flags(child);
    }
    if let Some(content_document) = node.content_document.as_deref_mut() {
        assign_interactive_flags(content_document);
    }
}

fn mark_new_interactive_flags(
    node: &mut BrowserUseDomTreeNode,
    previous_interactive_backend_keys: Option<&HashSet<(String, i64)>>,
) {
    node.is_new = false;
    if node.should_display
        && !node.excluded_by_parent
        && !node.ignored_by_paint_order
        && node.assigned_interactive
    {
        if let Some(backend_node_id) = node.backend_node_id {
            node.is_new = previous_interactive_backend_keys.is_none_or(|previous| {
                !previous.contains(&(node.target_id.clone(), backend_node_id))
            });
        }
    }

    for shadow_root in &mut node.shadow_roots {
        mark_new_interactive_flags(shadow_root, previous_interactive_backend_keys);
    }
    for child in &mut node.children {
        mark_new_interactive_flags(child, previous_interactive_backend_keys);
    }
    if let Some(content_document) = node.content_document.as_deref_mut() {
        mark_new_interactive_flags(content_document, previous_interactive_backend_keys);
    }
}

pub(super) fn prepare_tree_for_browser_use_render(
    root: &mut BrowserUseDomTreeNode,
    previous_interactive_backend_keys: Option<&HashSet<(String, i64)>>,
) {
    reset_render_state(root);
    populate_compound_children(root);
    compute_displayability(root);
    apply_paint_order_filtering(root);
    apply_bounding_box_filtering_recursive(root, None);
    assign_interactive_flags(root);
    mark_new_interactive_flags(root, previous_interactive_backend_keys);
}

pub(super) fn collect_interactive_backend_keys(
    root: &BrowserUseDomTreeNode,
) -> HashSet<(String, i64)> {
    fn collect(node: &BrowserUseDomTreeNode, out: &mut HashSet<(String, i64)>) {
        if node.should_display
            && !node.excluded_by_parent
            && !node.ignored_by_paint_order
            && node.assigned_interactive
        {
            if let Some(backend_node_id) = node.backend_node_id {
                out.insert((node.target_id.clone(), backend_node_id));
            }
        }

        for shadow_root in &node.shadow_roots {
            collect(shadow_root, out);
        }
        for child in &node.children {
            collect(child, out);
        }
        if let Some(content_document) = node.content_document.as_deref() {
            collect(content_document, out);
        }
    }

    let mut keys = HashSet::new();
    collect(root, &mut keys);
    keys
}

pub(super) fn render_selector_map_from_dom(root: &BrowserUseDomTreeNode) -> Option<String> {
    fn collect(node: &BrowserUseDomTreeNode, out: &mut Vec<String>) {
        if node.should_display
            && !node.excluded_by_parent
            && !node.ignored_by_paint_order
            && node.assigned_interactive
        {
            if let (Some(display_id), Some(tag_name)) = (node.backend_node_id, node.tag_name()) {
                let mut line = format!("[{display_id}] <{tag_name}");
                let attrs = build_attributes_string(node);
                if !attrs.is_empty() {
                    line.push(' ');
                    line.push_str(&attrs);
                }
                if let Some(frame_id) = node
                    .frame_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    line.push_str(&format!(" frame_id={}", inline_value(frame_id)));
                }
                if !node.target_id.trim().is_empty() {
                    line.push_str(&format!(" target_id={}", inline_value(&node.target_id)));
                }
                line.push_str(" />");
                out.push(line);
            }
        }

        for child in &node.children {
            collect(child, out);
        }
        for shadow_root in &node.shadow_roots {
            collect(shadow_root, out);
        }
        if let Some(content_document) = node.content_document.as_deref() {
            collect(content_document, out);
        }
    }

    let mut lines = Vec::new();
    collect(root, &mut lines);
    (!lines.is_empty()).then(|| lines.join("\n"))
}

#[cfg(test)]
#[path = "serializer/tests.rs"]
mod tests;
