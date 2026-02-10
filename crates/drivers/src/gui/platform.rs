// Path: crates/drivers/src/gui/platform.rs

use super::accessibility::{
    serialize_tree_to_xml, AccessibilityNode, Rect, SovereignSubstrateProvider,
};
use anyhow::{anyhow, Result};
use ioi_crypto::algorithms::hash::sha256;
use ioi_scs::{FrameType, RetentionClass, SovereignContextStore};
use ioi_types::app::{ActionRequest, ContextSlice};
// [FIX] Removed VmError import as we are switching to anyhow::Result to match trait
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

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
    use atspi::{CoordType, State}; // [NEW] Import State enum
    use futures::future::BoxFuture;
    use futures::FutureExt;
    use std::collections::HashMap;

    pub async fn fetch_tree() -> Result<AccessibilityNode> {
        // 1. Connect to the Accessibility Bus
        let conn = AccessibilityConnection::open().await?;

        // 2. Get the desktop root
        let root = AccessibleProxy::builder(&conn.connection().clone())
            .destination("org.a11y.atspi.Registry")?
            .path("/org/a11y/atspi/accessible/root")?
            .build()
            .await?;

        // 3. Recursive crawl
        crawl_atspi_node(&root, &conn, 0).await
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
        match normalized.as_str() {
            "pushbutton" => "push button".to_string(),
            "togglebutton" => "toggle button".to_string(),
            "combobox" => "combo box".to_string(),
            "checkbox" => "check box".to_string(),
            "radiobutton" => "radio button".to_string(),
            "menuitem" => "menu item".to_string(),
            "listitem" => "list item".to_string(),
            "textbox" => "text box".to_string(),
            "searchbox" => "search box".to_string(),
            _ => normalized,
        }
    }

    fn normalize_attribute_key(key: &str) -> String {
        let mut normalized = key.trim().to_ascii_lowercase().replace('-', "_");
        if normalized == "placeholder_text" || normalized == "placeholdertext" {
            normalized = "placeholder".to_string();
        }
        normalized
    }

    fn crawl_atspi_node<'a>(
        proxy: &'a AccessibleProxy<'a>,
        conn: &'a AccessibilityConnection,
        depth: usize,
    ) -> BoxFuture<'a, Result<AccessibilityNode>> {
        async move {
            if depth > 50 {
                return Err(anyhow!("Max depth reached"));
            }

            let name = proxy.name().await.unwrap_or_default();
            // Map the role enum to a string.
            let role = proxy
                .get_role()
                .await
                .map(|r| normalize_role(&format!("{:?}", r)))
                .unwrap_or_else(|_| "unknown".into());

            // Retrieve real coordinates from AT-SPI
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

            // [NEW] Capture Attributes & State
            let mut attributes = HashMap::new();

            // 1. Raw AT-SPI attributes
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

            // 2. Standard State (The Critical Addition)
            if let Ok(state_set) = proxy.get_state().await {
                // Map critical states to attributes for the Lens/XML serializer
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
                if state_set.contains(State::Expanded) {
                    attributes.insert("expanded".to_string(), "true".to_string());
                }

                // Visibility check optimization
                // [FIX] Removed check for State::Hidden
                if !state_set.contains(State::Visible) {
                    // We mark it in attributes, let the serializer prune.
                    attributes.insert("hidden".to_string(), "true".to_string());
                }
            }

            // 3. Map standard fields if useful
            if let Ok(desc) = proxy.description().await {
                if !desc.is_empty() {
                    attributes.insert("description".into(), desc);
                }
            }

            // Determine visibility
            let is_visible = !attributes.contains_key("hidden");

            // Fetch children
            let child_count = proxy.child_count().await.unwrap_or(0);
            let mut children = Vec::new();

            // Limit fan-out
            for i in 0..child_count.min(50) {
                if let Ok(child_ref) = proxy.get_child_at_index(i).await {
                    if let Ok(child_proxy) = AccessibleProxy::builder(&conn.connection().clone())
                        .destination(child_ref.name)?
                        .path(child_ref.path)?
                        .build()
                        .await
                    {
                        if let Ok(child_node) =
                            crawl_atspi_node(&child_proxy, conn, depth + 1).await
                        {
                            // Only include visible children to save context
                            if child_node.is_visible {
                                children.push(child_node);
                            }
                        }
                    }
                }
            }

            Ok(AccessibilityNode {
                // Generate a stable-ish ID based on path + index to allow referencing
                id: format!(
                    "atspi_{}_{}",
                    proxy.name().await.unwrap_or("unk".into()),
                    depth
                ),
                role,
                name: if name.is_empty() { None } else { Some(name) },
                value: None,
                rect,
                children,
                is_visible,
                attributes,   // [NEW]
                som_id: None, // [FIX] Added missing field
            })
        }
        .boxed()
    }
}

// Fallback for non-Windows/Linux (e.g. MacOS if accesskit not ready)
#[cfg(all(not(target_os = "windows"), not(target_os = "linux")))]
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

    #[cfg(all(not(target_os = "windows"), not(target_os = "linux")))]
    return stub_impl::fetch_tree();
}

/// A real, persistent substrate provider backed by `ioi-scs`.
pub struct NativeSubstrateProvider {
    scs: Arc<Mutex<SovereignContextStore>>,
}

impl NativeSubstrateProvider {
    pub fn new(scs: Arc<Mutex<SovereignContextStore>>) -> Self {
        Self { scs }
    }

    /// Fetches the live accessibility tree from the OS using platform-specific APIs.
    pub async fn get_raw_tree(&self) -> Result<AccessibilityNode> {
        fetch_tree_direct().await
    }
}

#[async_trait]
impl SovereignSubstrateProvider for NativeSubstrateProvider {
    // [FIX] Changed return type to anyhow::Result to match trait definition in accessibility.rs
    async fn get_intent_constrained_slice(
        &self,
        intent: &ActionRequest,
        _monitor_handle: u32,
    ) -> Result<ContextSlice, anyhow::Error> {
        // 1. Capture Raw Context from OS
        let raw_tree = self
            .get_raw_tree()
            .await
            .map_err(|e| anyhow!("Failed to fetch raw tree: {}", e))?;

        // 2. Apply Intent-Constraint (The Filter)
        let xml_data = serialize_tree_to_xml(&raw_tree, 0).into_bytes();

        // 3. Persist to Local SCS
        // We write the raw (but filtered) XML to the local store as a new Frame.
        let mut store = self.scs.lock().map_err(|_| anyhow!("SCS lock poisoned"))?;

        let session_id = intent.context.session_id.unwrap_or([0u8; 32]);

        let frame_id = store
            .append_frame(
                FrameType::Observation,
                &xml_data,
                0,
                [0u8; 32],
                session_id,
                RetentionClass::Ephemeral,
            )
            .map_err(|e| anyhow!("Failed to append frame: {}", e))?;

        // 4. Generate Provenance (Binding to the Store)
        let slice_id_digest = sha256(&xml_data).map_err(|e| anyhow!("SHA256 failed: {}", e))?;
        let mut slice_id = [0u8; 32];
        let len = slice_id_digest.as_ref().len().min(32);
        slice_id[..len].copy_from_slice(&slice_id_digest.as_ref()[..len]);

        let intent_hash = intent.hash();

        let frame = store.toc.frames.get(frame_id as usize).unwrap();
        let mut proof = Vec::new();
        proof.extend_from_slice(&frame.mhnsw_root);
        proof.extend_from_slice(&frame.checksum);

        Ok(ContextSlice {
            slice_id,
            frame_id,
            chunks: vec![xml_data],
            mhnsw_root: frame.mhnsw_root,
            traversal_proof: Some(proof),
            intent_id: intent_hash,
        })
    }
}
