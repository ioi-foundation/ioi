use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use ioi_crypto::algorithms::hash::sha256;
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_services::agentic::rules::ActionRules;
use ioi_types::app::agentic::{IntentMatrixEntry, IntentRoutingPolicy};
use ioi_types::app::{
    determinism_commit_state_key, determinism_evidence_state_key,
    determinism_step_contract_state_key, CommittedAction, DeterminismEvidence,
    DeterminismStepContractEvidence,
};
use ioi_types::codec;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub struct VerifyArgs {
    #[clap(subcommand)]
    pub command: VerifyCommands,
}

#[derive(Subcommand, Debug)]
pub enum VerifyCommands {
    /// Verifies determinism-boundary evidence for one session step.
    Determinism {
        /// Session ID (hex-encoded 32 bytes).
        session_id: String,
        /// Step index to verify.
        #[clap(long)]
        step: u32,
        /// RPC address of the node serving state.
        #[clap(long, default_value = "127.0.0.1:8555")]
        rpc: String,
        /// Optional policy JSON file to recompute and verify `policy_hash`.
        #[clap(long)]
        policy_file: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Serialize)]
struct VerifyDeterminismOutput {
    verdict: String,
    reason_codes: Vec<String>,
    details: Vec<String>,
    session_id: String,
    step_index: u32,
    intent_id: Option<String>,
    recovery_retry: Option<bool>,
    recovery_reason: Option<String>,
    request_hash: Option<String>,
    policy_hash: Option<String>,
    commitment_hash: Option<String>,
}

impl VerifyDeterminismOutput {
    fn invalid(session_id: String, step_index: u32) -> Self {
        Self {
            verdict: "INVALID_EVIDENCE".to_string(),
            reason_codes: Vec::new(),
            details: Vec::new(),
            session_id,
            step_index,
            intent_id: None,
            recovery_retry: None,
            recovery_reason: None,
            request_hash: None,
            policy_hash: None,
            commitment_hash: None,
        }
    }

    fn push_reason(&mut self, code: &str, detail: impl Into<String>) {
        self.reason_codes.push(code.to_string());
        self.details.push(detail.into());
    }

    fn finalize_verdict(mut self) -> Self {
        if self.reason_codes.is_empty() {
            self.verdict = "VALID_EVIDENCE".to_string();
        } else {
            self.verdict = "INVALID_EVIDENCE".to_string();
        }
        self
    }
}

pub async fn run(args: VerifyArgs) -> Result<()> {
    match args.command {
        VerifyCommands::Determinism {
            session_id,
            step,
            rpc,
            policy_file,
        } => run_verify_determinism(session_id, step, rpc, policy_file).await,
    }
}

async fn run_verify_determinism(
    session_id_hex: String,
    step_index: u32,
    rpc: String,
    policy_file: Option<PathBuf>,
) -> Result<()> {
    let mut output = VerifyDeterminismOutput::invalid(session_id_hex.clone(), step_index);

    let session_vec = match hex::decode(&session_id_hex) {
        Ok(bytes) => bytes,
        Err(err) => {
            output.push_reason(
                "INVALID_SESSION_ID_HEX",
                format!("session_id is not valid hex: {}", err),
            );
            print_output(output.finalize_verdict())?;
            return Ok(());
        }
    };
    if session_vec.len() != 32 {
        output.push_reason(
            "INVALID_SESSION_ID_LENGTH",
            format!("session_id must be 32 bytes, found {}", session_vec.len()),
        );
        print_output(output.finalize_verdict())?;
        return Ok(());
    }
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&session_vec);

    let channel = match tonic::transport::Channel::from_shared(format!("http://{}", rpc)) {
        Ok(endpoint) => match endpoint.connect().await {
            Ok(channel) => channel,
            Err(err) => {
                output.push_reason("RPC_CONNECT_FAILED", err.to_string());
                print_output(output.finalize_verdict())?;
                return Ok(());
            }
        },
        Err(err) => {
            output.push_reason("RPC_ENDPOINT_INVALID", err.to_string());
            print_output(output.finalize_verdict())?;
            return Ok(());
        }
    };

    let mut client = PublicApiClient::new(channel);

    let evidence_key = determinism_evidence_state_key(session_id, step_index);
    let evidence_bytes = match query_raw_state(&mut client, evidence_key).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            output.push_reason(
                "EVIDENCE_NOT_FOUND",
                "No determinism evidence bundle found for session/step",
            );
            print_output(output.finalize_verdict())?;
            return Ok(());
        }
        Err(err) => {
            output.push_reason("STATE_QUERY_FAILED", err);
            print_output(output.finalize_verdict())?;
            return Ok(());
        }
    };

    let evidence: DeterminismEvidence = match codec::from_bytes_canonical(&evidence_bytes) {
        Ok(value) => value,
        Err(err) => {
            output.push_reason("EVIDENCE_DECODE_FAILED", err.to_string());
            print_output(output.finalize_verdict())?;
            return Ok(());
        }
    };

    if evidence.schema_version != DeterminismEvidence::schema_version() {
        output.push_reason(
            "EVIDENCE_SCHEMA_MISMATCH",
            format!(
                "expected schema {} but found {}",
                DeterminismEvidence::schema_version(),
                evidence.schema_version
            ),
        );
    }

    output.request_hash = Some(hex::encode(evidence.committed_action.request_hash));
    output.policy_hash = Some(hex::encode(evidence.committed_action.policy_hash));
    output.commitment_hash = Some(hex::encode(evidence.committed_action.commitment_hash));
    output.recovery_retry = Some(evidence.recovery_retry);
    output.recovery_reason = evidence.recovery_reason.clone();

    let recomputed_request_hash = match evidence.request.try_hash() {
        Ok(hash) => hash,
        Err(err) => {
            output.push_reason("REQUEST_HASH_RECOMPUTE_FAILED", err.to_string());
            print_output(output.finalize_verdict())?;
            return Ok(());
        }
    };
    if recomputed_request_hash != evidence.committed_action.request_hash {
        output.push_reason(
            "REQUEST_HASH_MISMATCH",
            format!(
                "recomputed={} committed={}",
                hex::encode(recomputed_request_hash),
                hex::encode(evidence.committed_action.request_hash)
            ),
        );
    }

    if let Err(err) = evidence.committed_action.verify(
        &evidence.request,
        evidence.committed_action.policy_hash,
        evidence.committed_action.approval_ref,
    ) {
        output.push_reason("COMMITTED_ACTION_VERIFY_FAILED", err.to_string());
    }

    let commit_key = determinism_commit_state_key(session_id, step_index);
    match query_raw_state(&mut client, commit_key).await {
        Ok(Some(bytes)) => match codec::from_bytes_canonical::<CommittedAction>(&bytes) {
            Ok(stored_commit) => {
                if stored_commit != evidence.committed_action {
                    output.push_reason(
                        "COMMIT_RECORD_MISMATCH",
                        "CommittedAction in evidence does not match committed-action state record",
                    );
                }
            }
            Err(err) => output.push_reason("COMMIT_RECORD_DECODE_FAILED", err.to_string()),
        },
        Ok(None) => output.push_reason(
            "COMMIT_RECORD_MISSING",
            "No committed-action state record found for session/step",
        ),
        Err(err) => output.push_reason("STATE_QUERY_FAILED", err),
    }

    let mut intent_matrix = IntentRoutingPolicy::default().matrix;
    if let Some(path) = policy_file {
        match load_action_rules(&path) {
            Ok(rules) => {
                if let Err(err) =
                    verify_policy_hash_against_rules(&rules, evidence.committed_action.policy_hash)
                {
                    output.push_reason("POLICY_HASH_CHECK_FAILED", err.to_string());
                }
                intent_matrix = rules.ontology_policy.intent_routing.matrix;
            }
            Err(err) => {
                output.push_reason("POLICY_FILE_LOAD_FAILED", err.to_string());
            }
        }
    }

    let contract_key = determinism_step_contract_state_key(session_id, step_index);
    match query_raw_state(&mut client, contract_key).await {
        Ok(Some(contract_bytes)) => {
            match codec::from_bytes_canonical::<DeterminismStepContractEvidence>(&contract_bytes) {
                Ok(step_contract) => {
                    output.intent_id = Some(step_contract.intent_id.clone());
                    if step_contract.schema_version
                        != DeterminismStepContractEvidence::schema_version()
                    {
                        output.push_reason(
                            "STEP_CONTRACT_SCHEMA_MISMATCH",
                            format!(
                                "expected schema {} but found {}",
                                DeterminismStepContractEvidence::schema_version(),
                                step_contract.schema_version
                            ),
                        );
                    }
                    match verify_required_receipt_set(&step_contract, &intent_matrix) {
                        Ok(rrs) => {
                            if !rrs.missing_receipts.is_empty() {
                                output.push_reason(
                                    "RRS_MISSING_RECEIPTS",
                                    format!(
                                        "missing required receipts: {}",
                                        rrs.missing_receipts.join(",")
                                    ),
                                );
                            }
                            if !rrs.missing_postconditions.is_empty() {
                                output.push_reason(
                                    "RRS_MISSING_POSTCONDITIONS",
                                    format!(
                                        "missing required postconditions: {}",
                                        rrs.missing_postconditions.join(",")
                                    ),
                                );
                            }
                        }
                        Err((code, detail)) => output.push_reason(code, detail),
                    }
                }
                Err(err) => output.push_reason("STEP_CONTRACT_DECODE_FAILED", err.to_string()),
            }
        }
        Ok(None) => output.push_reason(
            "STEP_CONTRACT_EVIDENCE_MISSING",
            "No step-scoped contract evidence found for session/step",
        ),
        Err(err) => output.push_reason("STATE_QUERY_FAILED", err),
    }

    print_output(output.finalize_verdict())
}

fn load_action_rules(path: &PathBuf) -> Result<ActionRules> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read policy file {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse policy JSON {}", path.display()))
}

fn verify_policy_hash_against_rules(
    rules: &ActionRules,
    expected_policy_hash: [u8; 32],
) -> Result<()> {
    let canonical = serde_jcs::to_vec(&rules).context("policy JCS canonicalization failed")?;
    let digest = sha256(&canonical).map_err(|e| anyhow!("policy hash failed: {}", e))?;
    let mut actual = [0u8; 32];
    actual.copy_from_slice(digest.as_ref());

    if actual != expected_policy_hash {
        return Err(anyhow!(
            "policy_hash mismatch: expected={} actual={}",
            hex::encode(expected_policy_hash),
            hex::encode(actual)
        ));
    }

    Ok(())
}

#[derive(Debug, Default)]
struct RrsCheckOutcome {
    missing_receipts: Vec<String>,
    missing_postconditions: Vec<String>,
}

fn verify_required_receipt_set(
    step_contract: &DeterminismStepContractEvidence,
    intent_matrix: &[IntentMatrixEntry],
) -> std::result::Result<RrsCheckOutcome, (&'static str, String)> {
    let intent_id = step_contract.intent_id.trim().to_string();
    if intent_id.is_empty() {
        return Err((
            "STEP_CONTRACT_INTENT_INVALID",
            "step contract intent_id is empty".to_string(),
        ));
    }

    let Some(entry) = intent_matrix
        .iter()
        .find(|entry| entry.intent_id.trim() == intent_id)
    else {
        return Err((
            "RRS_PROFILE_NOT_FOUND",
            format!(
                "no intent-matrix profile found for resolved intent '{}'",
                intent_id
            ),
        ));
    };

    let required_receipts = canonical_markers(&entry.required_receipts);
    let mut required_postconditions = canonical_markers(&entry.required_postconditions);

    if intent_id == "system.clock.read" {
        push_unique(&mut required_postconditions, "clock_timestamp_observed");
    }
    if has_observed_receipt(step_contract, "timer_notification_contract_required") {
        push_unique(&mut required_postconditions, "timer_sleep_backend");
    }

    let mut outcome = RrsCheckOutcome::default();

    for receipt in &required_receipts {
        let Some(value) = observed_receipt_value(step_contract, receipt) else {
            outcome.missing_receipts.push(receipt.clone());
            continue;
        };
        let trimmed = value.trim();
        if trimmed.is_empty() {
            outcome.missing_receipts.push(receipt.clone());
        }
    }

    for postcondition in &required_postconditions {
        if !has_observed_postcondition(step_contract, postcondition) {
            outcome.missing_postconditions.push(postcondition.clone());
        }
    }

    if has_observed_postcondition(step_contract, "timer_sleep_backend")
        && !has_observed_postcondition(step_contract, "notification_path_armed")
    {
        outcome
            .missing_postconditions
            .push("notification_path_armed".to_string());
    }

    Ok(outcome)
}

fn canonical_markers(markers: &[String]) -> Vec<String> {
    let mut out = Vec::<String>::new();
    for marker in markers.iter().map(|value| value.trim()) {
        if marker.is_empty() {
            continue;
        }
        push_unique(&mut out, marker);
    }
    out
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_string());
    }
}

fn observed_receipt_value<'a>(
    step_contract: &'a DeterminismStepContractEvidence,
    name: &str,
) -> Option<&'a str> {
    step_contract
        .receipts
        .iter()
        .find(|value| value.trim() == name)
        .map(|value| value.as_str())
}

fn has_observed_receipt(step_contract: &DeterminismStepContractEvidence, name: &str) -> bool {
    step_contract
        .receipts
        .iter()
        .any(|value| value.trim() == name)
}

fn has_observed_postcondition(step_contract: &DeterminismStepContractEvidence, name: &str) -> bool {
    step_contract
        .postconditions
        .iter()
        .any(|value| value.trim() == name)
}

async fn query_raw_state(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    key: Vec<u8>,
) -> Result<Option<Vec<u8>>, String> {
    let req = QueryRawStateRequest { key };
    let resp = client
        .query_raw_state(req)
        .await
        .map_err(|e| format!("query_raw_state RPC failed: {}", e))?
        .into_inner();
    if resp.found {
        Ok(Some(resp.value))
    } else {
        Ok(None)
    }
}

fn print_output(output: VerifyDeterminismOutput) -> Result<()> {
    let json =
        serde_json::to_string_pretty(&output).context("failed to serialize verification output")?;
    println!("{}", json);
    Ok(())
}
