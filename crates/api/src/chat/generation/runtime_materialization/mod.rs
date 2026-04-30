use super::*;
use crate::chat::payload::{
    extract_authored_document_body, renderer_document_completeness_failure,
    renderer_primary_view_contract_failure,
    synthesize_generated_artifact_payload_from_raw_document,
};
use ioi_types::error::VmError;

include!("direct_author_recovery.rs");
include!("preview.rs");
include!("direct_author.rs");
include!("deterministic_html_repair.rs");
include!("timeouts.rs");
include!("inference.rs");
include!("parse.rs");
include!("repair.rs");
include!("refinement.rs");

#[cfg(test)]
include!("tests.rs");
