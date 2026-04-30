use super::html::*;
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::collections::BTreeSet;
use std::io::{Cursor, Write};
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

pub fn parse_chat_generated_artifact_payload(
    raw: &str,
) -> Result<ChatGeneratedArtifactPayload, String> {
    parse_chat_generated_artifact_payload_json(raw)
        .or_else(|_| {
            let extracted = extract_first_json_object(raw).ok_or_else(|| {
                "Chat artifact materialization output missing JSON payload".to_string()
            })?;
            parse_chat_generated_artifact_payload_json(&extracted)
                .map_err(|error| error.to_string())
        })
        .map_err(|error| {
            format!(
                "Failed to parse Chat artifact materialization payload: {}",
                error
            )
        })
}

fn parse_chat_generated_artifact_payload_json(
    raw: &str,
) -> Result<ChatGeneratedArtifactPayload, serde_json::Error> {
    let mut value = serde_json::from_str::<serde_json::Value>(raw)?;
    normalize_generated_artifact_payload_value(&mut value);
    serde_json::from_value::<ChatGeneratedArtifactPayload>(value)
}

include!("download_bundle.rs");
include!("validation.rs");
