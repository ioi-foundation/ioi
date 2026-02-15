use super::super::*;

impl BrowserDriver {
    pub async fn get_accessibility_tree(
        &self,
    ) -> std::result::Result<AccessibilityNode, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() };
        let p = page.ok_or(BrowserError::NoActivePage)?;

        p.execute(accessibility::EnableParams::default())
            .await
            .map_err(|e| BrowserError::Internal(format!("CDP AxEnable failed: {}", e)))?;

        let nodes_vec = p
            .execute(GetFullAxTreeParams::default())
            .await
            .map_err(|e| BrowserError::Internal(format!("CDP GetAxTree failed: {}", e)))?
            .nodes
            .clone();

        if nodes_vec.is_empty() {
            return Err(BrowserError::Internal(
                "Empty accessibility tree returned".into(),
            ));
        }

        let root_ax = &nodes_vec[0];
        let rect_lookup = self.collect_ax_node_rects(&p, &nodes_vec).await;
        Ok(self.convert_ax_node(root_ax, &nodes_vec, &rect_lookup))
    }

    pub async fn get_visual_tree(&self) -> std::result::Result<AccessibilityNode, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        page.execute(accessibility::EnableParams::default())
            .await
            .ok();

        let snapshot = page
            .execute(accessibility::GetFullAxTreeParams::default())
            .await
            .map_err(|e| BrowserError::Internal(format!("GetFullAxTree failed: {}", e)))?;

        let nodes = snapshot.nodes.clone();

        if nodes.is_empty() {
            return Err(BrowserError::Internal("Empty tree".into()));
        }

        let rect_lookup = self.collect_ax_node_rects(&page, &nodes).await;
        Ok(self.convert_ax_node(&nodes[0], &nodes, &rect_lookup))
    }

    fn convert_ax_node(
        &self,
        ax_node: &accessibility::AxNode,
        all_nodes: &[accessibility::AxNode],
        rect_lookup: &HashMap<String, AccessibilityRect>,
    ) -> AccessibilityNode {
        let mut children = Vec::new();
        if let Some(child_ids) = &ax_node.child_ids {
            for cid in child_ids {
                if let Some(child_ax) = all_nodes.iter().find(|n| &n.node_id == cid) {
                    children.push(self.convert_ax_node(child_ax, all_nodes, rect_lookup));
                }
            }
        }

        fn extract_string(val_opt: &Option<accessibility::AxValue>) -> Option<String> {
            val_opt.as_ref().and_then(|v| {
                if let Some(inner) = &v.value {
                    if let Some(s) = inner.as_str() {
                        if s.is_empty() {
                            None
                        } else {
                            Some(s.to_string())
                        }
                    } else if let Some(b) = inner.as_bool() {
                        Some(b.to_string())
                    } else if let Some(n) = inner.as_f64() {
                        Some(n.to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
        }

        let name = extract_string(&ax_node.name);
        let mut value = extract_string(&ax_node.value);
        let role = extract_string(&ax_node.role)
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "generic".to_string());

        let is_visible = !ax_node.ignored;
        let id_string: String = ax_node.node_id.clone().into();

        let mut attributes = HashMap::new();
        // Preserve the raw CDP AX node ID even after semantic lenses rewrite `node.id`.
        attributes.insert("cdp_node_id".to_string(), id_string.clone());
        if let Some(backend_id) = ax_node.backend_dom_node_id {
            attributes.insert(
                "backend_dom_node_id".to_string(),
                backend_id.inner().to_string(),
            );
        }
        if let Some(desc) = extract_string(&ax_node.description) {
            attributes.insert("description".to_string(), desc.clone());
            if value.is_none() {
                value = Some(desc);
            }
        }
        if let Some(chrome_role) = extract_string(&ax_node.chrome_role) {
            attributes.insert("chrome_role".to_string(), chrome_role);
        }

        if let Some(props) = &ax_node.properties {
            for prop in props {
                let key = prop.name.as_ref().to_ascii_lowercase();
                if key.is_empty() {
                    continue;
                }
                if let Some(raw_val) = &prop.value.value {
                    let parsed = if let Some(s) = raw_val.as_str() {
                        if s.is_empty() {
                            None
                        } else {
                            Some(s.to_string())
                        }
                    } else if let Some(b) = raw_val.as_bool() {
                        Some(b.to_string())
                    } else if let Some(n) = raw_val.as_f64() {
                        Some(n.to_string())
                    } else {
                        None
                    };

                    if let Some(parsed_val) = parsed {
                        attributes.insert(key.clone(), parsed_val.clone());
                        if value.is_none()
                            && matches!(key.as_str(), "valuetext" | "roledescription")
                        {
                            value = Some(parsed_val);
                        }
                    }
                }
            }
        }

        let rect = rect_lookup
            .get(&id_string)
            .copied()
            .unwrap_or(AccessibilityRect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            });

        AccessibilityNode {
            id: id_string,
            role,
            name,
            value,
            rect,
            children,
            is_visible,
            attributes,
            som_id: None,
        }
    }

    fn rect_from_dom_quad(quad: &[f64]) -> Option<(AccessibilityRect, f64)> {
        if quad.len() < 8 {
            return None;
        }

        let xs = [quad[0], quad[2], quad[4], quad[6]];
        let ys = [quad[1], quad[3], quad[5], quad[7]];
        if xs.iter().any(|v| !v.is_finite()) || ys.iter().any(|v| !v.is_finite()) {
            return None;
        }

        let min_x = xs.iter().copied().fold(f64::INFINITY, f64::min);
        let max_x = xs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let min_y = ys.iter().copied().fold(f64::INFINITY, f64::min);
        let max_y = ys.iter().copied().fold(f64::NEG_INFINITY, f64::max);

        let width = max_x - min_x;
        let height = max_y - min_y;
        if width <= 1.0 || height <= 1.0 {
            return None;
        }

        let rect = AccessibilityRect {
            x: min_x.floor().clamp(i32::MIN as f64, i32::MAX as f64) as i32,
            y: min_y.floor().clamp(i32::MIN as f64, i32::MAX as f64) as i32,
            width: width.ceil().clamp(1.0, i32::MAX as f64) as i32,
            height: height.ceil().clamp(1.0, i32::MAX as f64) as i32,
        };

        Some((rect, width * height))
    }

    async fn resolve_backend_node_rect(
        page: &Page,
        backend_node_id: chromiumoxide::cdp::browser_protocol::dom::BackendNodeId,
    ) -> Option<AccessibilityRect> {
        let quad_rect = page
            .execute(
                GetContentQuadsParams::builder()
                    .backend_node_id(backend_node_id)
                    .build(),
            )
            .await
            .ok()
            .and_then(|quads| {
                quads
                    .quads
                    .iter()
                    .filter_map(|q| Self::rect_from_dom_quad(q.inner().as_slice()))
                    .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
                    .map(|(rect, _)| rect)
            });

        if quad_rect.is_some() {
            return quad_rect;
        }

        page.execute(
            GetBoxModelParams::builder()
                .backend_node_id(backend_node_id)
                .build(),
        )
        .await
        .ok()
        .and_then(|model| Self::rect_from_dom_quad(model.model.border.inner().as_slice()))
        .map(|(rect, _)| rect)
    }

    async fn collect_ax_node_rects(
        &self,
        page: &Page,
        nodes: &[accessibility::AxNode],
    ) -> HashMap<String, AccessibilityRect> {
        let mut rects_by_node = HashMap::new();
        let mut rects_by_backend = HashMap::new();

        for ax_node in nodes {
            let backend_node_id = match ax_node.backend_dom_node_id {
                Some(id) => id,
                None => continue,
            };
            let backend_key = *backend_node_id.inner();

            let rect = if let Some(cached) = rects_by_backend.get(&backend_key).copied() {
                Some(cached)
            } else {
                let resolved = Self::resolve_backend_node_rect(page, backend_node_id).await;
                if let Some(found) = resolved {
                    rects_by_backend.insert(backend_key, found);
                }
                resolved
            };

            if let Some(found) = rect {
                let node_id: String = ax_node.node_id.clone().into();
                rects_by_node.insert(node_id, found);
            }
        }

        rects_by_node
    }

    /// Click an element by raw CDP Accessibility node id.
    ///
    /// This is used by semantic browser interaction:
    /// semantic_id -> cdp_node_id -> backend_dom_node_id -> DOM quad center.
    pub async fn click_ax_node(
        &self,
        target_cdp_id: &str,
    ) -> std::result::Result<(), BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;
        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;

        page.execute(accessibility::EnableParams::default())
            .await
            .map_err(|e| BrowserError::Internal(format!("CDP AxEnable failed: {}", e)))?;

        let nodes = page
            .execute(GetFullAxTreeParams::default())
            .await
            .map_err(|e| BrowserError::Internal(format!("CDP GetAxTree failed: {}", e)))?
            .nodes
            .clone();

        let target_node = nodes
            .iter()
            .find(|node| node.node_id.as_ref() == target_cdp_id)
            .ok_or_else(|| {
                BrowserError::Internal(format!(
                    "Element with CDP node id '{}' not found in current accessibility tree",
                    target_cdp_id
                ))
            })?;

        let backend_node_id = target_node.backend_dom_node_id.ok_or_else(|| {
            BrowserError::Internal(format!(
                "Element '{}' is not backed by a DOM node and cannot be clicked",
                target_cdp_id
            ))
        })?;

        fn quad_center(quad: &[f64]) -> Option<(f64, f64, f64)> {
            if quad.len() < 8 {
                return None;
            }

            let xs = [quad[0], quad[2], quad[4], quad[6]];
            let ys = [quad[1], quad[3], quad[5], quad[7]];

            let min_x = xs.iter().copied().fold(f64::INFINITY, f64::min);
            let max_x = xs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            let min_y = ys.iter().copied().fold(f64::INFINITY, f64::min);
            let max_y = ys.iter().copied().fold(f64::NEG_INFINITY, f64::max);

            let width = max_x - min_x;
            let height = max_y - min_y;
            if !width.is_finite() || !height.is_finite() || width <= 1.0 || height <= 1.0 {
                return None;
            }

            let cx = xs.iter().sum::<f64>() / 4.0;
            let cy = ys.iter().sum::<f64>() / 4.0;
            if !cx.is_finite() || !cy.is_finite() {
                return None;
            }

            Some((cx, cy, width * height))
        }

        let content_quads = page
            .execute(
                GetContentQuadsParams::builder()
                    .backend_node_id(backend_node_id)
                    .build(),
            )
            .await
            .map_err(|e| BrowserError::Internal(format!("CDP getContentQuads failed: {}", e)))?;

        let mut best_center = content_quads
            .quads
            .iter()
            .filter_map(|q| quad_center(q.inner().as_slice()))
            .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(x, y, _)| (x, y));

        if best_center.is_none() {
            let model = page
                .execute(
                    GetBoxModelParams::builder()
                        .backend_node_id(backend_node_id)
                        .build(),
                )
                .await
                .map_err(|e| BrowserError::Internal(format!("CDP getBoxModel failed: {}", e)))?;
            best_center =
                quad_center(model.model.border.inner().as_slice()).map(|(x, y, _)| (x, y));
        }

        let (x, y) = best_center.ok_or_else(|| {
            BrowserError::Internal(format!(
                "Element '{}' has no visible clickable geometry",
                target_cdp_id
            ))
        })?;

        self.synthetic_click(x, y).await
    }
}

#[cfg(test)]
mod tests {
    use super::BrowserDriver;

    #[test]
    fn rect_from_dom_quad_builds_bounds() {
        let quad = [10.2, 20.8, 50.0, 20.1, 49.6, 60.4, 10.1, 60.9];
        let (rect, area) = BrowserDriver::rect_from_dom_quad(&quad).expect("quad should resolve");
        assert_eq!(rect.x, 10);
        assert_eq!(rect.y, 20);
        assert_eq!(rect.width, 40);
        assert_eq!(rect.height, 41);
        assert!(area > 1500.0);
    }

    #[test]
    fn rect_from_dom_quad_rejects_degenerate_geometry() {
        let tiny = [10.0, 10.0, 10.5, 10.0, 10.5, 10.4, 10.0, 10.4];
        assert!(BrowserDriver::rect_from_dom_quad(&tiny).is_none());
    }

    #[test]
    fn rect_from_dom_quad_rejects_non_finite_values() {
        let bad = [10.0, 10.0, f64::NAN, 10.0, 50.0, 50.0, 10.0, 50.0];
        assert!(BrowserDriver::rect_from_dom_quad(&bad).is_none());
    }
}
