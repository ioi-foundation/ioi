use super::*;

pub(crate) fn normalize_registry_id(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn build_plugin_computed_publisher_trust(
    publisher_id: Option<String>,
    signing_key_id: Option<String>,
    state: &str,
    source: Option<String>,
    root_id: Option<String>,
    root_label: Option<String>,
    statement_issued_at_ms: Option<u64>,
    detail: Option<String>,
    revoked_at_ms: Option<u64>,
) -> PluginComputedPublisherTrust {
    PluginComputedPublisherTrust {
        publisher_id,
        signing_key_id,
        state: Some(state.to_string()),
        source,
        root_id,
        root_label,
        statement_issued_at_ms,
        detail,
        revoked_at_ms,
        ..Default::default()
    }
}

pub(crate) fn compute_plugin_local_registry_publisher_trust(
    entry: &PluginMarketplaceCatalogEntry,
    publishers: &[PluginMarketplacePublisher],
    verification: &PluginComputedVerification,
) -> Option<PluginComputedPublisherTrust> {
    if verification.status.as_deref() != Some("verified") {
        return None;
    }

    let publisher_id = normalize_registry_id(entry.publisher_id.clone());
    let signing_key_id = normalize_registry_id(entry.signing_key_id.clone());
    let trust_source = Some("local publisher registry".to_string());
    let publisher_label = entry
        .publisher_label
        .clone()
        .unwrap_or_else(|| "this publisher".to_string());

    let Some(publisher_id_value) = publisher_id.clone() else {
        return Some(build_plugin_computed_publisher_trust(
            None,
            signing_key_id,
            "unknown",
            trust_source,
            None,
            None,
            None,
            Some(
                "Package signature is valid, but no publisher identity was supplied for trust-chain verification."
                    .to_string(),
            ),
            None,
        ));
    };

    let Some(publisher) = publishers
        .iter()
        .find(|candidate| candidate.id.trim() == publisher_id_value)
    else {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "unknown",
            trust_source,
            None,
            None,
            None,
            Some(format!(
                "Package signature is valid, but publisher '{}' is not present in the trusted publisher registry.",
                publisher_label
            )),
            None,
        ));
    };

    let registry_label = publisher
        .label
        .clone()
        .unwrap_or_else(|| publisher_label.clone());

    if matches!(publisher.trust_status.as_deref(), Some("revoked")) {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "revoked",
            publisher.trust_source.clone().or(trust_source),
            None,
            None,
            None,
            Some(format!(
                "Publisher '{}' has been revoked in the plugin trust registry.",
                registry_label
            )),
            publisher.revoked_at_ms,
        ));
    }

    let declared_key_material = entry
        .signature_public_key
        .as_deref()
        .and_then(|raw| decode_signature_material(raw, "signaturePublicKey").ok());
    let signing_key = if let Some(signing_key_id_value) = signing_key_id.as_deref() {
        publisher
            .signing_keys
            .iter()
            .find(|candidate| candidate.id.trim() == signing_key_id_value)
    } else if let Some(declared_bytes) = declared_key_material.as_ref() {
        publisher.signing_keys.iter().find(|candidate| {
            decode_signature_material(&candidate.public_key, "publisher signing key")
                .map(|bytes| bytes == *declared_bytes)
                .unwrap_or(false)
        })
    } else {
        None
    };

    let Some(signing_key) = signing_key else {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "unknown",
            publisher.trust_source.clone().or(trust_source),
            None,
            None,
            None,
            Some(format!(
                "Package signature is valid, but the signing key is not recognized for publisher '{}'.",
                registry_label
            )),
            None,
        ));
    };

    if matches!(signing_key.status.as_deref(), Some("revoked")) {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            Some(signing_key.id.clone()),
            "revoked",
            publisher.trust_source.clone().or(trust_source),
            None,
            None,
            None,
            Some(format!(
                "Publisher '{}' signed this package with a revoked marketplace key.",
                registry_label
            )),
            signing_key.revoked_at_ms.or(publisher.revoked_at_ms),
        ));
    }

    if let Some(declared_bytes) = declared_key_material {
        match decode_signature_material(&signing_key.public_key, "publisher signing key") {
            Ok(registry_bytes) if registry_bytes == declared_bytes => {}
            Ok(_) => {
                return Some(build_plugin_computed_publisher_trust(
                    Some(publisher_id_value),
                    Some(signing_key.id.clone()),
                    "unknown",
                    publisher.trust_source.clone().or(trust_source),
                    None,
                    None,
                    None,
                    Some(format!(
                        "Package signature is valid, but the declared signing key does not match publisher '{}' registry key '{}'.",
                        registry_label, signing_key.id
                    )),
                    None,
                ));
            }
            Err(_) => {
                return Some(build_plugin_computed_publisher_trust(
                    Some(publisher_id_value),
                    Some(signing_key.id.clone()),
                    "unknown",
                    publisher.trust_source.clone().or(trust_source),
                    None,
                    None,
                    None,
                    Some(format!(
                        "Package signature is valid, but publisher '{}' registry key '{}' could not be decoded.",
                        registry_label, signing_key.id
                    )),
                    None,
                ));
            }
        }
    }

    Some(build_plugin_computed_publisher_trust(
        Some(publisher_id_value),
        Some(signing_key.id.clone()),
        "trusted",
        publisher.trust_source.clone().or(trust_source),
        None,
        None,
        None,
        Some(format!(
            "Package signature is valid and publisher '{}' is trusted by the local marketplace registry.",
            registry_label
        )),
        None,
    ))
}

pub(crate) fn compute_plugin_rooted_publisher_trust(
    entry: &PluginMarketplaceCatalogEntry,
    publishers: &[PluginMarketplacePublisher],
    roots: &[PluginMarketplaceTrustRoot],
    verification: &PluginComputedVerification,
) -> Option<PluginComputedPublisherTrust> {
    if verification.status.as_deref() != Some("verified") {
        return None;
    }

    let publisher_id = normalize_registry_id(entry.publisher_id.clone());
    let signing_key_id = normalize_registry_id(entry.signing_key_id.clone());
    let trust_source = Some("marketplace root verification".to_string());
    let publisher_label = entry
        .publisher_label
        .clone()
        .unwrap_or_else(|| "this publisher".to_string());

    let Some(publisher_id_value) = publisher_id.clone() else {
        return Some(build_plugin_computed_publisher_trust(
            None,
            signing_key_id,
            "unknown_root",
            trust_source,
            None,
            None,
            None,
            Some(
                "Package signature is valid, but no publisher identity was supplied for marketplace root verification."
                    .to_string(),
            ),
            None,
        ));
    };

    let Some(publisher) = publishers
        .iter()
        .find(|candidate| candidate.id.trim() == publisher_id_value)
    else {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "unknown_root",
            trust_source,
            None,
            None,
            None,
            Some(format!(
                "Package signature is valid, but publisher '{}' is not present in the marketplace publisher statement set.",
                publisher_label
            )),
            None,
        ));
    };

    let registry_label = publisher
        .label
        .clone()
        .unwrap_or_else(|| publisher_label.clone());
    let root_id = normalize_registry_id(publisher.trust_root_id.clone());
    let statement_issued_at_ms = publisher.statement_issued_at_ms;
    let statement_signature = publisher
        .statement_signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let Some(root_id_value) = root_id.clone() else {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "unknown_root",
            trust_source,
            None,
            None,
            statement_issued_at_ms,
            Some(format!(
                "Package signature is valid, but publisher '{}' is not anchored to a trusted marketplace root.",
                registry_label
            )),
            publisher.revoked_at_ms,
        ));
    };

    let Some(root) = roots
        .iter()
        .find(|candidate| candidate.id.trim() == root_id_value)
    else {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "unknown_root",
            trust_source,
            Some(root_id_value.clone()),
            Some(root_id_value.clone()),
            statement_issued_at_ms,
            Some(format!(
                "Package signature is valid, but publisher '{}' chains to unknown marketplace root '{}'.",
                registry_label, root_id_value
            )),
            publisher.revoked_at_ms,
        ));
    };

    let root_label = root.label.clone().unwrap_or_else(|| root.id.clone());
    if matches!(root.status.as_deref(), Some("revoked")) {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "revoked_by_root",
            root.trust_source
                .clone()
                .or_else(|| publisher.trust_source.clone())
                .or(trust_source),
            Some(root.id.clone()),
            Some(root_label.clone()),
            statement_issued_at_ms,
            Some(format!(
                "Marketplace root '{}' has been revoked, so publisher '{}' can no longer be trusted.",
                root_label, registry_label
            )),
            root.revoked_at_ms.or(publisher.revoked_at_ms),
        ));
    }

    let root_algorithm = root
        .algorithm
        .clone()
        .unwrap_or_else(|| "ed25519".to_string());
    if !root_algorithm.eq_ignore_ascii_case("ed25519") {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "unknown_root",
            root.trust_source
                .clone()
                .or_else(|| publisher.trust_source.clone())
                .or(trust_source),
            Some(root.id.clone()),
            Some(root_label.clone()),
            statement_issued_at_ms,
            Some(format!(
                "Publisher '{}' chains to marketplace root '{}', but the root uses unsupported algorithm '{}'.",
                registry_label, root_label, root_algorithm
            )),
            publisher.revoked_at_ms,
        ));
    }

    let Some(statement_signature_raw) = statement_signature else {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "unknown_root",
            root.trust_source
                .clone()
                .or_else(|| publisher.trust_source.clone())
                .or(trust_source),
            Some(root.id.clone()),
            Some(root_label.clone()),
            statement_issued_at_ms,
            Some(format!(
                "Package signature is valid, but publisher '{}' is missing a signed marketplace root statement.",
                registry_label
            )),
            publisher.revoked_at_ms,
        ));
    };

    let root_public_key_bytes = match decode_signature_material(
        &root.public_key,
        "marketplace root public key",
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Some(build_plugin_computed_publisher_trust(
                Some(publisher_id_value),
                signing_key_id,
                "unknown_root",
                root.trust_source
                    .clone()
                    .or_else(|| publisher.trust_source.clone())
                    .or(trust_source),
                Some(root.id.clone()),
                Some(root_label.clone()),
                statement_issued_at_ms,
                Some(format!(
                    "Publisher '{}' chains to marketplace root '{}', but the root key could not be decoded: {}",
                    registry_label, root_label, error
                )),
                publisher.revoked_at_ms,
            ));
        }
    };
    let root_public_key = match <Ed25519PublicKey as SerializableKey>::from_bytes(
        &root_public_key_bytes,
    ) {
        Ok(public_key) => public_key,
        Err(error) => {
            return Some(build_plugin_computed_publisher_trust(
                Some(publisher_id_value),
                signing_key_id,
                "unknown_root",
                root.trust_source
                    .clone()
                    .or_else(|| publisher.trust_source.clone())
                    .or(trust_source),
                Some(root.id.clone()),
                Some(root_label.clone()),
                statement_issued_at_ms,
                Some(format!(
                    "Publisher '{}' chains to marketplace root '{}', but the root key is invalid: {}",
                    registry_label, root_label, error
                )),
                publisher.revoked_at_ms,
            ));
        }
    };
    let statement_signature_bytes =
        match decode_signature_material(statement_signature_raw, "publisherStatementSignature") {
            Ok(bytes) => bytes,
            Err(error) => {
                return Some(build_plugin_computed_publisher_trust(
                    Some(publisher_id_value),
                    signing_key_id,
                    "unknown_root",
                    root.trust_source
                        .clone()
                        .or_else(|| publisher.trust_source.clone())
                        .or(trust_source),
                    Some(root.id.clone()),
                    Some(root_label.clone()),
                    statement_issued_at_ms,
                    Some(format!(
                        "Publisher '{}' includes an unreadable marketplace root statement: {}",
                        registry_label, error
                    )),
                    publisher.revoked_at_ms,
                ));
            }
        };
    let statement_signature =
        match <Ed25519Signature as SerializableKey>::from_bytes(&statement_signature_bytes) {
            Ok(signature) => signature,
            Err(error) => {
                return Some(build_plugin_computed_publisher_trust(
                    Some(publisher_id_value),
                    signing_key_id,
                    "unknown_root",
                    root.trust_source
                        .clone()
                        .or_else(|| publisher.trust_source.clone())
                        .or(trust_source),
                    Some(root.id.clone()),
                    Some(root_label.clone()),
                    statement_issued_at_ms,
                    Some(format!(
                    "Publisher '{}' includes an invalid marketplace root statement signature: {}",
                    registry_label, error
                )),
                    publisher.revoked_at_ms,
                ));
            }
        };
    let statement_message = plugin_publisher_statement_message(&root.id, publisher);
    if root_public_key
        .verify(&statement_message, &statement_signature)
        .is_err()
    {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "unknown_root",
            root.trust_source
                .clone()
                .or_else(|| publisher.trust_source.clone())
                .or(trust_source),
            Some(root.id.clone()),
            Some(root_label.clone()),
            statement_issued_at_ms,
            Some(format!(
                "Publisher '{}' includes a marketplace statement that did not validate against root '{}'.",
                registry_label, root_label
            )),
            publisher.revoked_at_ms,
        ));
    }

    let declared_key_material = entry
        .signature_public_key
        .as_deref()
        .and_then(|raw| decode_signature_material(raw, "signaturePublicKey").ok());
    let signing_key = if let Some(signing_key_id_value) = signing_key_id.as_deref() {
        publisher
            .signing_keys
            .iter()
            .find(|candidate| candidate.id.trim() == signing_key_id_value)
    } else if let Some(declared_bytes) = declared_key_material.as_ref() {
        publisher.signing_keys.iter().find(|candidate| {
            decode_signature_material(&candidate.public_key, "publisher signing key")
                .map(|bytes| bytes == *declared_bytes)
                .unwrap_or(false)
        })
    } else {
        None
    };

    let Some(signing_key) = signing_key else {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "unknown_root",
            root.trust_source
                .clone()
                .or_else(|| publisher.trust_source.clone())
                .or(trust_source),
            Some(root.id.clone()),
            Some(root_label.clone()),
            statement_issued_at_ms,
            Some(format!(
                "Package signature is valid, but publisher '{}' statement does not recognize this signing key.",
                registry_label
            )),
            publisher.revoked_at_ms,
        ));
    };

    if matches!(signing_key.status.as_deref(), Some("revoked")) {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            Some(signing_key.id.clone()),
            "revoked_by_root",
            root.trust_source
                .clone()
                .or_else(|| publisher.trust_source.clone())
                .or(trust_source),
            Some(root.id.clone()),
            Some(root_label.clone()),
            statement_issued_at_ms,
            Some(format!(
                "Publisher '{}' signed this package with key '{}' that has been revoked by marketplace root '{}'.",
                registry_label, signing_key.id, root_label
            )),
            signing_key.revoked_at_ms.or(publisher.revoked_at_ms),
        ));
    }

    if let Some(declared_bytes) = declared_key_material {
        match decode_signature_material(&signing_key.public_key, "publisher signing key") {
            Ok(registry_bytes) if registry_bytes == declared_bytes => {}
            Ok(_) => {
                return Some(build_plugin_computed_publisher_trust(
                    Some(publisher_id_value),
                    Some(signing_key.id.clone()),
                    "unknown_root",
                    root.trust_source
                        .clone()
                        .or_else(|| publisher.trust_source.clone())
                        .or(trust_source),
                    Some(root.id.clone()),
                    Some(root_label.clone()),
                    statement_issued_at_ms,
                    Some(format!(
                        "Package signature is valid, but the declared signing key does not match publisher '{}' statement key '{}'.",
                        registry_label, signing_key.id
                    )),
                    publisher.revoked_at_ms,
                ));
            }
            Err(_) => {
                return Some(build_plugin_computed_publisher_trust(
                    Some(publisher_id_value),
                    Some(signing_key.id.clone()),
                    "unknown_root",
                    root.trust_source
                        .clone()
                        .or_else(|| publisher.trust_source.clone())
                        .or(trust_source),
                    Some(root.id.clone()),
                    Some(root_label.clone()),
                    statement_issued_at_ms,
                    Some(format!(
                        "Package signature is valid, but publisher '{}' statement key '{}' could not be decoded.",
                        registry_label, signing_key.id
                    )),
                    publisher.revoked_at_ms,
                ));
            }
        }
    }

    let publisher_state = match publisher.trust_status.as_deref() {
        Some("revoked") => "revoked_by_root",
        _ => "rooted",
    };
    let detail = if publisher_state == "revoked_by_root" {
        format!(
            "Package signature is valid, but publisher '{}' has been revoked by marketplace root '{}'.",
            registry_label, root_label
        )
    } else {
        format!(
            "Package signature is valid and publisher '{}' is rooted in trusted marketplace authority '{}'.",
            registry_label, root_label
        )
    };

    Some(build_plugin_computed_publisher_trust(
        Some(publisher_id_value),
        Some(signing_key.id.clone()),
        publisher_state,
        root.trust_source
            .clone()
            .or_else(|| publisher.trust_source.clone())
            .or(trust_source),
        Some(root.id.clone()),
        Some(root_label),
        statement_issued_at_ms,
        Some(detail),
        publisher.revoked_at_ms.or(root.revoked_at_ms),
    ))
}
