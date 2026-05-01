// Path: crates/drivers/src/gui/platform.rs

use super::accessibility::{AccessibilityNode, Rect, SovereignSubstrateProvider};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_crypto::algorithms::hash::sha256;
use ioi_memory::MemoryRuntime;
use ioi_types::app::{ActionRequest, ContextSlice};
use serde_json::json;
use std::sync::Arc;

// Windows Dependencies
#[cfg(target_os = "windows")]
use accesskit_windows::UiaTree;

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use std::collections::HashMap;
    use windows::core::{IUnknown, Interface, BSTR};
    use windows::Win32::System::Com::*;
    use windows::Win32::UI::Accessibility::*;

    pub fn fetch_tree() -> Result<AccessibilityNode> {
        unsafe {
            CoInitialize(None).ok(); // Init COM
            let automation: IUIAutomation =
                CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER)?;
            let root_element = automation.GetRootElement()?;

            // Recursive crawler (simplified depth-limited)
            crawl_element(&root_element, 0)
        }
    }

    unsafe fn crawl_element(
        element: &IUIAutomationElement,
        depth: usize,
    ) -> Result<AccessibilityNode> {
        if depth > 50 {
            return Err(anyhow!("Max depth"));
        }

        let name = element.CurrentName().unwrap_or_default().to_string();
        let rect_struct = element.CurrentBoundingRectangle()?;
        let rect = Rect {
            x: rect_struct.left,
            y: rect_struct.top,
            width: rect_struct.right - rect_struct.left,
            height: rect_struct.bottom - rect_struct.top,
        };
        let control_type = element.CurrentControlType()?;
        let role = map_control_type(control_type);

        // [NEW] Capture attributes (AutomationId, ClassName, etc.)
        let mut attributes = HashMap::new();

        if let Ok(auto_id) = element.CurrentAutomationId() {
            let s = auto_id.to_string();
            if !s.is_empty() {
                attributes.insert("automation_id".to_string(), s);
            }
        }

        if let Ok(class_name) = element.CurrentClassName() {
            let s = class_name.to_string();
            if !s.is_empty() {
                attributes.insert("class".to_string(), s);
            }
        }

        // Try to capture Value pattern if available
        let mut value = None;
        // (Simplified check - full impl would query ValuePattern)

        // Walk children
        let walker = {
            let automation: IUIAutomation =
                CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER)?;
            automation.ControlViewWalker()?
        };

        let mut children = Vec::new();
        let mut child = walker.GetFirstChildElement(element);

        while let Ok(c) = &child {
            if c.is_none() {
                break;
            }
            if let Ok(node) = crawl_element(c.as_ref().unwrap(), depth + 1) {
                children.push(node);
            }
            child = walker.GetNextSiblingElement(c.as_ref().unwrap());
        }

        Ok(AccessibilityNode {
            id: format!("{:p}", element.as_raw()), // Pointer as ID
            role,
            name: if name.is_empty() { None } else { Some(name) },
            value,
            rect,
            children,
            is_visible: true,
            attributes,
            som_id: None, // [FIX] Added missing field
        })
    }

    fn map_control_type(id: i32) -> String {
        match id {
            50000 => "button".into(),
            50004 => "window".into(),
            50033 => "pane".into(),
            _ => "unknown".into(),
        }
    }
}

// [NEW] Native Linux Implementation using AT-SPI
// This replaces the previous stub with a real accessibility tree crawler.
#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use atspi::connection::AccessibilityConnection;
    use atspi::proxy::accessible::AccessibleProxy;
    use atspi::proxy::component::ComponentProxy;
    use atspi::{Accessible, CoordType, State}; // [NEW] Import State enum
    use std::collections::{HashMap, HashSet, VecDeque};

    const MAX_ATSPI_CRAWL_DEPTH: usize = 32;
    const MAX_ATSPI_CHILDREN_PER_NODE: usize = 32;
    const MAX_ATSPI_NODES_PER_CRAWL: usize = 2048;

    fn is_likely_atspi_bus_error(message: &str) -> bool {
        let lower = message.to_ascii_lowercase();
        lower.contains("org.a11y.atspi")
            || lower.contains("accessibility bus")
            || lower.contains("dbus")
            || lower.contains("bus name")
            || lower.contains("service unknown")
            || lower.contains("name has no owner")
    }

    fn wrap_atspi_error(context: &str, error: impl std::fmt::Display) -> anyhow::Error {
        let message = error.to_string();
        if is_likely_atspi_bus_error(&message) {
            anyhow!(
                "AT-SPI {} failed: {}. Ensure the Linux accessibility bus is running and the target app exposes AT-SPI.",
                context,
                message
            )
        } else {
            anyhow!("AT-SPI {} failed: {}", context, message)
        }
    }

    pub async fn fetch_tree() -> Result<AccessibilityNode> {
        // 1. Connect to the Accessibility Bus
        let conn = AccessibilityConnection::open()
            .await
            .map_err(|error| wrap_atspi_error("connection open", error))?;

        // 2. Get the desktop root
        let desktop_root = build_accessible_proxy(
            &conn,
            "org.a11y.atspi.Registry",
            "/org/a11y/atspi/accessible/root",
        )
        .await
        .map_err(|error| wrap_atspi_error("desktop root lookup", error))?;

        // Prefer the active/focused application subtree when AT-SPI exposes one.
        // This keeps the tree smaller and more relevant than crawling the whole registry root.
        let preferred_root = select_primary_application(&desktop_root, &conn).await;
        let root = if let Some(preferred_root) = preferred_root.as_ref() {
            build_accessible_proxy(
                &conn,
                preferred_root.name.as_str(),
                preferred_root.path.as_str(),
            )
            .await
            .map_err(|error| wrap_atspi_error("primary application lookup", error))?
        } else {
            desktop_root
        };

        // 3. Recursive crawl. AT-SPI can expose cross-links back to ancestor
        // objects, so track visited object paths across the crawl rather than
        // relying only on a direct self-reference check.
        crawl_atspi_tree(&root, &conn).await
    }

    async fn build_accessible_proxy<'a>(
        conn: &'a AccessibilityConnection,
        destination: &'a str,
        path: &'a str,
    ) -> Result<AccessibleProxy<'a>> {
        AccessibleProxy::builder(&conn.connection().clone())
            .destination(destination)?
            .path(path)?
            .build()
            .await
            .map_err(|error| anyhow!(error.to_string()))
    }

    async fn select_primary_application<'a>(
        desktop_root: &'a AccessibleProxy<'a>,
        conn: &'a AccessibilityConnection,
    ) -> Option<Accessible> {
        let child_refs = desktop_root.get_children().await.ok()?;
        let mut fallback_ref: Option<Accessible> = None;
        let desktop_path = desktop_root.path().to_string();

        for child_ref in child_refs.into_iter().take(32) {
            if child_ref.path.as_str().ends_with("/null") || child_ref.path.as_str() == desktop_path
            {
                continue;
            }

            if fallback_ref.is_none() {
                fallback_ref = Some(child_ref.clone());
            }

            let child_proxy = match build_accessible_proxy(
                conn,
                child_ref.name.as_str(),
                child_ref.path.as_str(),
            )
            .await
            {
                Ok(proxy) => proxy,
                Err(_) => continue,
            };

            if let Ok(state_set) = child_proxy.get_state().await {
                if state_set.contains(State::Active)
                    || state_set.contains(State::Focused)
                    || state_set.contains(State::Showing)
                {
                    return Some(child_ref);
                }
            }
        }

        fallback_ref
    }

    fn normalize_role(raw_role: &str) -> String {
        if raw_role.is_empty() {
            return "unknown".to_string();
        }

        let mut out = String::with_capacity(raw_role.len() + 4);
        let mut prev_was_alnum = false;
        let mut prev_was_lower = false;

        for ch in raw_role.chars() {
            if ch == '_' || ch == '-' {
                if !out.ends_with(' ') && !out.is_empty() {
                    out.push(' ');
                }
                prev_was_alnum = false;
                prev_was_lower = false;
                continue;
            }

            if ch.is_ascii_uppercase() {
                if prev_was_alnum && prev_was_lower && !out.ends_with(' ') {
                    out.push(' ');
                }
                out.push(ch.to_ascii_lowercase());
                prev_was_alnum = true;
                prev_was_lower = false;
                continue;
            }

            if ch.is_whitespace() {
                if !out.ends_with(' ') && !out.is_empty() {
                    out.push(' ');
                }
                prev_was_alnum = false;
                prev_was_lower = false;
                continue;
            }

            out.push(ch.to_ascii_lowercase());
            prev_was_alnum = ch.is_ascii_alphanumeric();
            prev_was_lower = ch.is_ascii_lowercase();
        }

        let normalized = out.split_whitespace().collect::<Vec<_>>().join(" ");
        let canonical = match normalized.as_str() {
            "pushbutton" | "push button" | "togglebutton" | "toggle button" => "button",
            "combobox" => "combobox",
            "checkbox" => "checkbox",
            "radiobutton" | "radio button" => "radio",
            "menuitem" | "menu item" => "menuitem",
            "listitem" | "list item" => "listitem",
            "textbox" => "textbox",
            "searchbox" => "searchbox",
            _ => normalized.as_str(),
        };

        canonical.replace(' ', "_")
    }

    fn normalize_attribute_key(key: &str) -> String {
        let mut normalized = key.trim().to_ascii_lowercase().replace('-', "_");
        if normalized == "placeholder_text" || normalized == "placeholdertext" {
            normalized = "placeholder".to_string();
        }
        normalized
    }

    fn stable_accessible_id(destination: &str, path: &str) -> String {
        let destination = destination
            .replace(':', "_")
            .replace('.', "_")
            .replace('-', "_");
        let object_path = path.trim_matches('/').replace('/', "_").replace('-', "_");
        let stable_destination = if destination.is_empty() {
            "unk".to_string()
        } else {
            destination
        };
        let stable_object_path = if object_path.is_empty() {
            "root".to_string()
        } else {
            object_path
        };
        format!("atspi_{}_{}", stable_destination, stable_object_path)
    }

    #[derive(Clone)]
    struct PendingAccessible {
        destination: String,
        path: String,
        depth: usize,
        parent: Option<usize>,
    }

    struct NodeSlot {
        parent: Option<usize>,
        node: AccessibilityNode,
    }

    async fn read_atspi_node(
        proxy: &AccessibleProxy<'_>,
        conn: &AccessibilityConnection,
    ) -> (AccessibilityNode, Vec<Accessible>) {
        let name = proxy.name().await.unwrap_or_default();
        let role = proxy
            .get_role()
            .await
            .map(|r| normalize_role(&format!("{:?}", r)))
            .unwrap_or_else(|_| "unknown".into());

        let ext = {
            let comp_builder = ComponentProxy::builder(&conn.connection().clone())
                .destination(proxy.destination().to_owned())
                .expect("Invalid destination");

            if let Ok(comp_builder) = comp_builder.path(proxy.path().to_owned()) {
                if let Ok(comp) = comp_builder.build().await {
                    comp.get_extents(CoordType::Screen)
                        .await
                        .unwrap_or((0, 0, 0, 0))
                } else {
                    (0, 0, 0, 0)
                }
            } else {
                (0, 0, 0, 0)
            }
        };

        let rect = Rect {
            x: ext.0,
            y: ext.1,
            width: ext.2,
            height: ext.3,
        };

        let mut attributes = HashMap::new();
        if let Ok(attrs) = proxy.get_attributes().await {
            for (k, v) in attrs {
                if !k.is_empty() {
                    attributes.insert(k.clone(), v.clone());
                }
                let normalized_key = normalize_attribute_key(&k);
                if !normalized_key.is_empty() {
                    attributes.insert(normalized_key, v);
                }
            }
        }

        let mut state_available = false;
        let mut state_indicates_visible = false;
        if let Ok(state_set) = proxy.get_state().await {
            state_available = true;
            if !state_set.contains(State::Enabled) {
                attributes.insert("disabled".to_string(), "true".to_string());
            }
            if state_set.contains(State::Checked) {
                attributes.insert("checked".to_string(), "true".to_string());
            }
            if state_set.contains(State::Selected) {
                attributes.insert("selected".to_string(), "true".to_string());
            }
            if state_set.contains(State::Focused) {
                attributes.insert("focused".to_string(), "true".to_string());
            }
            if state_set.contains(State::Active) {
                attributes.insert("active".to_string(), "true".to_string());
            }
            if state_set.contains(State::Expanded) {
                attributes.insert("expanded".to_string(), "true".to_string());
            }
            if state_set.contains(State::Showing) {
                attributes.insert("showing".to_string(), "true".to_string());
            }
            if state_set.contains(State::Visible)
                || state_set.contains(State::Showing)
                || state_set.contains(State::Focused)
            {
                state_indicates_visible = true;
            }
        }

        if let Ok(desc) = proxy.description().await {
            if !desc.is_empty() {
                attributes.insert("description".into(), desc);
            }
        }

        let structural_role = matches!(
            role.as_str(),
            "root" | "window" | "application" | "frame" | "pane" | "panel"
        );
        let has_rect = rect.width > 0 && rect.height > 0;
        let has_label = !name.trim().is_empty();
        let is_visible = if state_available {
            state_indicates_visible || has_rect || structural_role
        } else {
            has_rect || has_label || structural_role
        };

        let child_refs = match proxy.get_children().await {
            Ok(children) if !children.is_empty() => children,
            _ => {
                let child_count = proxy.child_count().await.unwrap_or(0);
                let mut refs = Vec::new();
                for i in 0..child_count.min(MAX_ATSPI_CHILDREN_PER_NODE as i32) {
                    if let Ok(child_ref) = proxy.get_child_at_index(i).await {
                        refs.push(child_ref);
                    }
                }
                refs
            }
        };

        (
            AccessibilityNode {
                id: stable_accessible_id(
                    &proxy.destination().to_string(),
                    &proxy.path().to_string(),
                ),
                role,
                name: if name.is_empty() { None } else { Some(name) },
                value: None,
                rect,
                children: Vec::new(),
                is_visible,
                attributes,
                som_id: None,
            },
            child_refs,
        )
    }

    async fn crawl_atspi_tree(
        root: &AccessibleProxy<'_>,
        conn: &AccessibilityConnection,
    ) -> Result<AccessibilityNode> {
        let mut queue = VecDeque::from([PendingAccessible {
            destination: root.destination().to_string(),
            path: root.path().to_string(),
            depth: 0,
            parent: None,
        }]);
        let mut visited = HashSet::new();
        let mut slots: Vec<NodeSlot> = Vec::new();

        while let Some(pending) = queue.pop_front() {
            if pending.depth > MAX_ATSPI_CRAWL_DEPTH || slots.len() >= MAX_ATSPI_NODES_PER_CRAWL {
                continue;
            }
            if pending.path.ends_with("/null") {
                continue;
            }
            let key = format!("{}{}", pending.destination, pending.path);
            if !visited.insert(key) {
                continue;
            }

            let proxy =
                match build_accessible_proxy(conn, &pending.destination, &pending.path).await {
                    Ok(proxy) => proxy,
                    Err(_) => continue,
                };
            let current_path = proxy.path().to_string();
            let (node, child_refs) = read_atspi_node(&proxy, conn).await;
            let index = slots.len();
            slots.push(NodeSlot {
                parent: pending.parent,
                node,
            });

            if pending.depth >= MAX_ATSPI_CRAWL_DEPTH {
                continue;
            }
            for child_ref in child_refs.into_iter().take(MAX_ATSPI_CHILDREN_PER_NODE) {
                let child_path = child_ref.path.to_string();
                if child_path.ends_with("/null") || child_path == current_path {
                    continue;
                }
                queue.push_back(PendingAccessible {
                    destination: child_ref.name.to_string(),
                    path: child_path,
                    depth: pending.depth + 1,
                    parent: Some(index),
                });
            }
        }

        if slots.is_empty() {
            return Err(anyhow!("AT-SPI crawl produced no accessible nodes"));
        }

        let parents = slots.iter().map(|slot| slot.parent).collect::<Vec<_>>();
        let mut nodes = slots
            .into_iter()
            .map(|slot| Some(slot.node))
            .collect::<Vec<_>>();
        let mut root_node = None;

        for index in (0..nodes.len()).rev() {
            let Some(node) = nodes[index].take() else {
                continue;
            };
            if let Some(parent_index) = parents[index] {
                if let Some(parent) = nodes.get_mut(parent_index).and_then(Option::as_mut) {
                    if node.is_visible || !node.children.is_empty() {
                        parent.children.push(node);
                    }
                }
            } else {
                root_node = Some(node);
            }
        }

        let mut root_node = root_node.ok_or_else(|| anyhow!("AT-SPI crawl lost root node"))?;
        reverse_child_order(&mut root_node);
        Ok(root_node)
    }

    fn reverse_child_order(root: &mut AccessibilityNode) {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            node.children.reverse();
            for child in &mut node.children {
                stack.push(child);
            }
        }
    }

    #[cfg(test)]
    mod tests;
}

// [NEW] Native macOS Implementation using AXUIElement (Accessibility API)
#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;
    use accessibility::{AXAttribute, AXUIElement, AXUIElementAttributes};
    use accessibility_sys::{
        kAXFocusedApplicationAttribute, kAXPositionAttribute, kAXSizeAttribute,
        kAXValueTypeCGPoint, kAXValueTypeCGSize, AXValueGetType, AXValueGetTypeID, AXValueGetValue,
        AXValueRef,
    };
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::string::CFString;
    use std::collections::HashMap;
    use std::ffi::c_void;

    #[repr(C)]
    struct CGPoint {
        x: f64,
        y: f64,
    }

    #[repr(C)]
    struct CGSize {
        width: f64,
        height: f64,
    }

    fn ax_attr<T>(name: &'static str) -> AXAttribute<T> {
        AXAttribute::new(&CFString::from_static_string(name))
    }

    fn cfstring_to_opt_string(value: Result<CFString, accessibility::Error>) -> Option<String> {
        value
            .ok()
            .map(|v| v.to_string())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    fn cfbool_to_opt_bool(
        value: Result<core_foundation::boolean::CFBoolean, accessibility::Error>,
    ) -> Option<bool> {
        value.ok().map(|v| bool::from(v))
    }

    fn read_ax_point(element: &AXUIElement) -> Option<(f64, f64)> {
        let raw = element
            .attribute(&ax_attr::<CFType>(kAXPositionAttribute))
            .ok()?;
        let ax_type = unsafe { AXValueGetTypeID() };
        if raw.type_of() != ax_type {
            return None;
        }
        let value_ref = raw.as_CFTypeRef() as AXValueRef;
        if unsafe { AXValueGetType(value_ref) } != kAXValueTypeCGPoint {
            return None;
        }
        let mut out = CGPoint { x: 0.0, y: 0.0 };
        let ok = unsafe {
            AXValueGetValue(
                value_ref,
                kAXValueTypeCGPoint,
                (&mut out as *mut CGPoint).cast::<c_void>(),
            )
        };
        if ok {
            Some((out.x, out.y))
        } else {
            None
        }
    }

    fn read_ax_size(element: &AXUIElement) -> Option<(f64, f64)> {
        let raw = element
            .attribute(&ax_attr::<CFType>(kAXSizeAttribute))
            .ok()?;
        let ax_type = unsafe { AXValueGetTypeID() };
        if raw.type_of() != ax_type {
            return None;
        }
        let value_ref = raw.as_CFTypeRef() as AXValueRef;
        if unsafe { AXValueGetType(value_ref) } != kAXValueTypeCGSize {
            return None;
        }
        let mut out = CGSize {
            width: 0.0,
            height: 0.0,
        };
        let ok = unsafe {
            AXValueGetValue(
                value_ref,
                kAXValueTypeCGSize,
                (&mut out as *mut CGSize).cast::<c_void>(),
            )
        };
        if ok {
            Some((out.width, out.height))
        } else {
            None
        }
    }

    fn element_rect(element: &AXUIElement) -> Rect {
        let (x, y) = read_ax_point(element).unwrap_or((0.0, 0.0));
        let (w, h) = read_ax_size(element).unwrap_or((0.0, 0.0));
        Rect {
            x: x.round() as i32,
            y: y.round() as i32,
            width: w.round() as i32,
            height: h.round() as i32,
        }
    }

    fn crawl_element(element: &AXUIElement, depth: usize) -> Result<AccessibilityNode> {
        if depth > 50 {
            return Err(anyhow!("Max depth reached"));
        }

        let mut attributes: HashMap<String, String> = HashMap::new();

        if let Some(role) = cfstring_to_opt_string(element.role()) {
            attributes.insert("role".to_string(), role);
        }
        if let Some(subrole) = cfstring_to_opt_string(element.subrole()) {
            attributes.insert("subrole".to_string(), subrole);
        }
        if let Some(desc) = cfstring_to_opt_string(element.role_description()) {
            attributes.insert("role_description".to_string(), desc);
        }
        if let Some(identifier) = cfstring_to_opt_string(element.identifier()) {
            attributes.insert("identifier".to_string(), identifier);
        }
        if let Some(help) = cfstring_to_opt_string(element.help()) {
            attributes.insert("help".to_string(), help);
        }
        if let Some(enabled) = cfbool_to_opt_bool(element.enabled()) {
            if !enabled {
                attributes.insert("disabled".to_string(), "true".to_string());
            }
        }
        if let Some(focused) = cfbool_to_opt_bool(element.focused()) {
            if focused {
                attributes.insert("focused".to_string(), "true".to_string());
            }
        }

        let name = cfstring_to_opt_string(element.title())
            .or_else(|| cfstring_to_opt_string(element.description()))
            .or_else(|| cfstring_to_opt_string(element.label_value()));

        let value = element
            .attribute(&AXAttribute::<CFType>::value())
            .ok()
            .map(|v| v.to_string())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let rect = element_rect(element);

        let mut children = Vec::new();
        if let Ok(kids) = element.children() {
            for child in kids.into_iter().take(50) {
                if let Ok(node) = crawl_element(&child, depth + 1) {
                    children.push(node);
                }
            }
        }

        Ok(AccessibilityNode {
            id: format!("{:p}", element.as_concrete_TypeRef()),
            role: attributes
                .get("role")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
            name,
            value,
            rect,
            children,
            is_visible: true,
            attributes,
            som_id: None,
        })
    }

    pub fn fetch_tree() -> Result<AccessibilityNode> {
        let system = AXUIElement::system_wide();

        // Prefer focused application to keep the tree bounded to the primary interactive surface.
        let focused_app = system
            .attribute(&ax_attr::<AXUIElement>(kAXFocusedApplicationAttribute))
            .unwrap_or(system);

        // Avoid long AX RPC stalls.
        let _ = focused_app.set_messaging_timeout(0.35);

        crawl_element(&focused_app, 0)
    }
}

// Fallback for non-Windows/Linux/macOS (e.g. other Unix targets)
#[cfg(all(
    not(target_os = "windows"),
    not(target_os = "linux"),
    not(target_os = "macos")
))]
mod stub_impl {
    use super::*;
    use std::collections::HashMap;

    pub fn fetch_tree() -> Result<AccessibilityNode> {
        Ok(AccessibilityNode {
            id: "root-stub".to_string(),
            role: "window".to_string(),
            name: Some("Stub OS Tree (Platform Not Supported)".to_string()),
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 1920,
                height: 1080,
            },
            is_visible: true,
            children: vec![],
            attributes: HashMap::new(),
            som_id: None, // [FIX] Added missing field
        })
    }
}

/// Public wrapper to fetch the raw accessibility tree.
/// Used by the GUI driver for Visual Grounding (Set-of-Marks) overlay.
pub async fn fetch_tree_direct() -> Result<AccessibilityNode> {
    #[cfg(target_os = "windows")]
    return windows_impl::fetch_tree();

    #[cfg(target_os = "linux")]
    return linux_impl::fetch_tree().await;

    #[cfg(target_os = "macos")]
    return macos_impl::fetch_tree();

    #[cfg(all(
        not(target_os = "windows"),
        not(target_os = "linux"),
        not(target_os = "macos")
    ))]
    return stub_impl::fetch_tree();
}

const CONTEXT_SLICE_ARTIFACT_PREFIX: &str = "desktop.context_slice.";

fn digest32(bytes: &[u8], label: &str) -> Result<[u8; 32]> {
    let digest = sha256(bytes).map_err(|error| anyhow!("{} digest failed: {}", label, error))?;
    let mut output = [0u8; 32];
    let len = digest.as_ref().len().min(32);
    output[..len].copy_from_slice(&digest.as_ref()[..len]);
    Ok(output)
}

fn context_slice_artifact_id(slice_id: &[u8; 32]) -> String {
    format!("{CONTEXT_SLICE_ARTIFACT_PREFIX}{}", hex::encode(slice_id))
}

/// A real desktop context provider backed by runtime-managed evidence artifacts.
pub struct NativeSubstrateProvider {
    memory_runtime: Option<Arc<MemoryRuntime>>,
}

impl NativeSubstrateProvider {
    pub fn new(memory_runtime: Option<Arc<MemoryRuntime>>) -> Self {
        Self { memory_runtime }
    }
}

#[async_trait]
impl SovereignSubstrateProvider for NativeSubstrateProvider {
    async fn get_intent_constrained_slice(
        &self,
        intent: &ActionRequest,
        monitor_handle: u32,
        slice_bytes: &[u8],
    ) -> Result<ContextSlice, anyhow::Error> {
        let xml_data = slice_bytes.to_vec();
        let slice_id = digest32(&xml_data, "context slice")?;
        let intent_hash = intent.hash();
        let mut proof_input = xml_data.clone();
        proof_input.extend_from_slice(&intent_hash);
        let proof = digest32(&proof_input, "context slice provenance")?;
        let session_id = intent.context.session_id.unwrap_or([0u8; 32]);

        if let Some(memory_runtime) = self.memory_runtime.as_ref() {
            let artifact_id = context_slice_artifact_id(&slice_id);
            let metadata_json = serde_json::to_string(&json!({
                "kind": "context_slice",
                "artifact_id": artifact_id,
                "session_id": hex::encode(session_id),
                "intent_id": hex::encode(intent_hash),
                "monitor_handle": monitor_handle,
                "content_type": "application/xml",
                "slice_id": hex::encode(slice_id),
            }))
            .map_err(|error| anyhow!("Failed to serialize context slice metadata: {}", error))?;

            memory_runtime
                .upsert_artifact_json(session_id, &artifact_id, &metadata_json)
                .map_err(|error| anyhow!("Failed to persist context slice metadata: {}", error))?;
            memory_runtime
                .put_artifact_blob(session_id, &artifact_id, &xml_data)
                .map_err(|error| anyhow!("Failed to persist context slice blob: {}", error))?;
        }

        Ok(ContextSlice {
            slice_id,
            frame_id: 0,
            chunks: vec![xml_data],
            mhnsw_root: [0u8; 32],
            traversal_proof: Some(proof.to_vec()),
            intent_id: intent_hash,
        })
    }
}

#[cfg(test)]
#[path = "platform/tests.rs"]
mod tests;
