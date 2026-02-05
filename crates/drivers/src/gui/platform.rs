// Path: crates/drivers/src/gui/platform.rs

use super::accessibility::{
    serialize_tree_to_xml, AccessibilityNode, Rect, SovereignSubstrateProvider,
};
use anyhow::{anyhow, Result};
use ioi_crypto::algorithms::hash::sha256;
use ioi_scs::{FrameType, SovereignContextStore};
use ioi_types::app::{ActionRequest, ContextSlice};
use std::sync::{Arc, Mutex};
use async_trait::async_trait;
use std::collections::HashMap;

// Windows Dependencies
#[cfg(target_os = "windows")]
use accesskit_windows::UiaTree;

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
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
            if !s.is_empty() { attributes.insert("automation_id".to_string(), s); }
        }
        
        if let Ok(class_name) = element.CurrentClassName() {
            let s = class_name.to_string();
            if !s.is_empty() { attributes.insert("class".to_string(), s); }
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
            attributes, // [NEW]
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
    use atspi::CoordType;
    use futures::future::BoxFuture;
    use futures::FutureExt;

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

    fn crawl_atspi_node<'a>(
        proxy: &'a AccessibleProxy<'a>, 
        conn: &'a AccessibilityConnection,
        depth: usize
    ) -> BoxFuture<'a, Result<AccessibilityNode>> {
        async move {
            if depth > 50 { return Err(anyhow!("Max depth reached")); }

            let name = proxy.name().await.unwrap_or_default();
            // Map the role enum to a string.
            let role = proxy.get_role().await.map(|r| format!("{:?}", r)).unwrap_or("unknown".into());
            
            // Retrieve real coordinates from AT-SPI
            let ext = {
                 let comp_builder = ComponentProxy::builder(&conn.connection().clone())
                    .destination(proxy.destination().to_owned())
                    .expect("Invalid destination"); 
                 
                 if let Ok(comp_builder) = comp_builder.path(proxy.path().to_owned()) {
                     if let Ok(comp) = comp_builder.build().await {
                         comp.get_extents(CoordType::Screen).await.unwrap_or((0,0,0,0))
                     } else { (0,0,0,0) }
                 } else { (0,0,0,0) }
            };
            
            let rect = Rect {
                x: ext.0,
                y: ext.1,
                width: ext.2,
                height: ext.3,
            };

            // [NEW] Capture detailed attributes for Application Lenses
            let mut attributes = HashMap::new();

            // 1. Get raw AT-SPI attributes
            if let Ok(attrs) = proxy.get_attributes().await {
                for (k, v) in attrs {
                    attributes.insert(k, v);
                }
            }

            // 2. Map standard fields if useful
            if let Ok(desc) = proxy.description().await {
                if !desc.is_empty() { 
                    attributes.insert("description".into(), desc); 
                }
            }
            
            // 3. Try to get specific interface attributes (Value, Text, etc.)
            // (Simplified for this snippet)

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
                        if let Ok(child_node) = crawl_atspi_node(&child_proxy, conn, depth + 1).await {
                            children.push(child_node);
                        }
                    }
                }
            }

            Ok(AccessibilityNode {
                // Generate a stable-ish ID based on path + index to allow referencing
                id: format!("atspi_{}_{}", proxy.name().await.unwrap_or("unk".into()), depth), 
                role,
                name: if name.is_empty() { None } else { Some(name) },
                value: None, 
                rect,
                children,
                is_visible: true,
                attributes, // [NEW]
            })
        }.boxed()
    }
}

// Fallback for non-Windows/Linux (e.g. MacOS if accesskit not ready)
#[cfg(all(not(target_os = "windows"), not(target_os = "linux")))]
mod stub_impl {
    use super::*;
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
            attributes: HashMap::new(), // [NEW]
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
    async fn get_intent_constrained_slice(
        &self,
        intent: &ActionRequest,
        _monitor_handle: u32,
    ) -> Result<ContextSlice> {
        // 1. Capture Raw Context from OS
        let raw_tree = self.get_raw_tree().await?;

        // 2. Apply Intent-Constraint (The Filter)
        // Note: The caller (IoiGuiDriver) should have already applied any Lenses
        // before calling this if they wanted custom XML.
        // However, the trait expects this method to do the work.
        // If we want Lenses to be applied, they should be integrated here or passed in.
        // For now, we use the default serializer.
        let xml_data = serialize_tree_to_xml(&raw_tree, 0).into_bytes();

        // 3. Persist to Local SCS
        // We write the raw (but filtered) XML to the local store as a new Frame.
        // This gives us a permanent record of what the agent saw.
        let mut store = self.scs.lock().map_err(|_| anyhow!("SCS lock poisoned"))?;

        // Determine session ID context from the intent, or default to global (all zeros)
        // if this is a background observation not tied to a specific agent session.
        let session_id = intent.context.session_id.unwrap_or([0u8; 32]);

        // Placeholder: Assuming block height 0 for local captures if not synced from a service call
        let frame_id = store.append_frame(
            FrameType::Observation,
            &xml_data,
            0,
            [0u8; 32], // mHNSW root placeholder - would come from index update
            session_id, 
        )?;

        // 4. Generate Provenance (Binding to the Store)
        // The slice_id is the hash of the data.
        let slice_id_digest = sha256(&xml_data)?;
        let mut slice_id = [0u8; 32];
        let len = slice_id_digest.as_ref().len().min(32);
        slice_id[..len].copy_from_slice(&slice_id_digest.as_ref()[..len]);

        // The intent_hash binds this slice to the specific request.
        let intent_hash = intent.hash();

        // The provenance proof links this specific frame in the store to the SCS root.
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