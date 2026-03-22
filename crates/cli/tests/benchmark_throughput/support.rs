#![allow(dead_code)]

use anyhow::Result;
use ioi_types::app::{
    account_id_from_key_material, AccountId, ChainTransaction, SettlementPayload,
    SettlementTransaction, SignHeader, SignatureProof, SignatureSuite,
};
use libp2p::identity::Keypair;
use std::time::Duration;

pub const NUM_ACCOUNTS: usize = 500;
pub const TXS_PER_ACCOUNT: u64 = 200;
pub const TOTAL_TXS: usize = NUM_ACCOUNTS * TXS_PER_ACCOUNT as usize;

pub const NUM_RPC_CONNECTIONS: usize = 16;
pub const BACKOFF_MS: u64 = 50;
pub const MAX_RETRIES: usize = 100;

pub const BLOCK_TIME_MS: u64 = 1_000;

#[derive(Debug, Clone, Copy)]
pub struct ThroughputBenchmarkReport {
    pub attempted: usize,
    pub accepted: u64,
    pub committed: u64,
    pub injection_tps: f64,
    pub e2e_tps: f64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LatencySummary {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
}

#[derive(Debug, Clone)]
pub struct BenchmarkChurnSummary {
    pub fallback_blocks: usize,
    pub max_replay_debt: u64,
    pub max_validation_aborts: u64,
    pub max_execution_errors: u64,
}

impl Default for BenchmarkChurnSummary {
    fn default() -> Self {
        Self {
            fallback_blocks: 0,
            max_replay_debt: 0,
            max_validation_aborts: 0,
            max_execution_errors: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BenchmarkSubmissionSummary {
    pub submit_retries: u64,
    pub submit_timeout_retries: u64,
    pub submit_duplicates: u64,
    pub submit_latency: LatencySummary,
}

impl Default for BenchmarkSubmissionSummary {
    fn default() -> Self {
        Self {
            submit_retries: 0,
            submit_timeout_retries: 0,
            submit_duplicates: 0,
            submit_latency: LatencySummary::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BenchmarkAlignmentSummary {
    pub requested_submit_lead_ms: u64,
    pub actual_start_lead_ms: u64,
    pub ready_budget_ms: u64,
    pub submit_complete_vs_due_ms: Option<i64>,
    pub target_height: Option<u64>,
    pub committed_on_target_height: Option<bool>,
    pub first_committed_height_delta: Option<i64>,
    pub committed_before_target_height_txs: Option<u64>,
    pub committed_at_target_height_txs: Option<u64>,
}

impl Default for BenchmarkAlignmentSummary {
    fn default() -> Self {
        Self {
            requested_submit_lead_ms: 0,
            actual_start_lead_ms: 0,
            ready_budget_ms: 0,
            submit_complete_vs_due_ms: None,
            target_height: None,
            committed_on_target_height: None,
            first_committed_height_delta: None,
            committed_before_target_height_txs: None,
            committed_at_target_height_txs: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PaperBenchmarkResult {
    pub scenario: String,
    pub validators: usize,
    pub safety_mode: String,
    pub lane: String,
    pub attempted: usize,
    pub accepted: u64,
    pub committed: u64,
    pub committed_blocks: usize,
    pub injection_tps: f64,
    pub sustained_tps: f64,
    pub commit_latency: LatencySummary,
    pub sampled_commit_visibility_lag_ms: Option<i64>,
    pub terminal_latency: Option<LatencySummary>,
    pub terminal_close_blocks: usize,
    pub terminal_abort_blocks: usize,
    pub churn: BenchmarkChurnSummary,
    pub submission: BenchmarkSubmissionSummary,
    pub alignment: BenchmarkAlignmentSummary,
}

pub fn create_transfer_tx(
    sender_key: &Keypair,
    sender_id: AccountId,
    recipient: AccountId,
    amount: u64,
    nonce: u64,
    chain_id: u32,
) -> ChainTransaction {
    let public_key = sender_key.public().encode_protobuf();

    let header = SignHeader {
        account_id: sender_id,
        nonce,
        chain_id: chain_id.into(),
        tx_version: 1,
        session_auth: None,
    };

    let settlement_tx = SettlementTransaction {
        header,
        payload: SettlementPayload::Transfer {
            to: recipient,
            amount: amount as u128,
        },
        signature_proof: SignatureProof::default(),
    };

    let payload_bytes = settlement_tx.to_sign_bytes().unwrap();
    let signature = sender_key.sign(&payload_bytes).unwrap();

    let settlement_tx_signed = SettlementTransaction {
        header: settlement_tx.header,
        payload: settlement_tx.payload,
        signature_proof: SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key,
            signature,
        },
    };

    ChainTransaction::Settlement(settlement_tx_signed)
}

pub fn generate_accounts(count: usize) -> Result<Vec<(Keypair, AccountId)>> {
    let mut accounts = Vec::with_capacity(count);
    for _ in 0..count {
        let key = Keypair::generate_ed25519();
        let pk = key.public().encode_protobuf();
        let id = AccountId(account_id_from_key_material(SignatureSuite::ED25519, &pk)?);
        accounts.push((key, id));
    }
    Ok(accounts)
}

pub fn print_report(report: ThroughputBenchmarkReport) {
    println!("\n--- Benchmark Results ---");
    println!("Total Attempted:   {}", report.attempted);
    println!("Total Accepted:    {}", report.accepted);
    println!("Total Committed:   {}", report.committed);
    println!("-------------------------");
    println!(
        "Injection Rate:    {:.2} TPS (Client Push)",
        report.injection_tps
    );
    println!("End-to-End TPS:    {:.2} TPS (Sustained)", report.e2e_tps);
    println!("-------------------------");
}

pub fn summarize_latencies(samples: &[Duration]) -> LatencySummary {
    if samples.is_empty() {
        return LatencySummary::default();
    }

    let mut millis = samples
        .iter()
        .map(|sample| sample.as_secs_f64() * 1_000.0)
        .collect::<Vec<_>>();
    millis.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let percentile = |p: f64| -> f64 {
        let max_index = millis.len().saturating_sub(1);
        let idx = ((max_index as f64) * p).round() as usize;
        millis[idx.min(max_index)]
    };

    LatencySummary {
        p50_ms: percentile(0.50),
        p95_ms: percentile(0.95),
        p99_ms: percentile(0.99),
        max_ms: *millis.last().unwrap_or(&0.0),
    }
}

pub fn render_markdown_table(results: &[PaperBenchmarkResult]) -> String {
    let mut lines = vec![
        "| scenario | validators | mode | lane | attempted | accepted | committed | blocks | injection_tps | sustained_tps | fallback_blocks | max_replay_debt | max_validation_aborts | max_execution_errors | submit_retries | submit_timeout_retries | submit_duplicates | submit_p50_ms | submit_p95_ms | align_requested_lead_ms | align_actual_start_lead_ms | align_ready_budget_ms | submit_complete_vs_due_ms | align_target_height | align_hit_target_height | first_commit_height_delta | committed_before_target_height_txs | committed_at_target_height_txs | commit_p50_ms | commit_p95_ms | commit_p99_ms | sampled_commit_visibility_lag_ms | terminal_p50_ms | terminal_p95_ms | terminal_close_blocks | terminal_abort_blocks |".to_string(),
        "|---|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|".to_string(),
    ];

    for result in results {
        let terminal_p50 = result
            .terminal_latency
            .map(|summary| format!("{:.2}", summary.p50_ms))
            .unwrap_or_else(|| "-".to_string());
        let terminal_p95 = result
            .terminal_latency
            .map(|summary| format!("{:.2}", summary.p95_ms))
            .unwrap_or_else(|| "-".to_string());
        let submit_complete_vs_due = result
            .alignment
            .submit_complete_vs_due_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        let target_height = result
            .alignment
            .target_height
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        let committed_on_target_height = result
            .alignment
            .committed_on_target_height
            .map(|value| {
                if value {
                    "yes".to_string()
                } else {
                    "no".to_string()
                }
            })
            .unwrap_or_else(|| "-".to_string());
        let first_committed_height_delta = result
            .alignment
            .first_committed_height_delta
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        let committed_before_target_height_txs = result
            .alignment
            .committed_before_target_height_txs
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        let committed_at_target_height_txs = result
            .alignment
            .committed_at_target_height_txs
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        let sampled_commit_visibility_lag_ms = result
            .sampled_commit_visibility_lag_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());

        lines.push(format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {:.2} | {:.2} | {} | {} | {} | {} | {} | {} | {} | {:.2} | {:.2} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {:.2} | {:.2} | {:.2} | {} | {} | {} | {} | {} |",
            result.scenario,
            result.validators,
            result.safety_mode,
            result.lane,
            result.attempted,
            result.accepted,
            result.committed,
            result.committed_blocks,
            result.injection_tps,
            result.sustained_tps,
            result.churn.fallback_blocks,
            result.churn.max_replay_debt,
            result.churn.max_validation_aborts,
            result.churn.max_execution_errors,
            result.submission.submit_retries,
            result.submission.submit_timeout_retries,
            result.submission.submit_duplicates,
            result.submission.submit_latency.p50_ms,
            result.submission.submit_latency.p95_ms,
            result.alignment.requested_submit_lead_ms,
            result.alignment.actual_start_lead_ms,
            result.alignment.ready_budget_ms,
            submit_complete_vs_due,
            target_height,
            committed_on_target_height,
            first_committed_height_delta,
            committed_before_target_height_txs,
            committed_at_target_height_txs,
            result.commit_latency.p50_ms,
            result.commit_latency.p95_ms,
            result.commit_latency.p99_ms,
            sampled_commit_visibility_lag_ms,
            terminal_p50,
            terminal_p95,
            result.terminal_close_blocks,
            result.terminal_abort_blocks,
        ));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::{
        render_markdown_table, BenchmarkAlignmentSummary, BenchmarkChurnSummary,
        BenchmarkSubmissionSummary, LatencySummary, PaperBenchmarkResult,
    };

    #[test]
    fn render_markdown_table_includes_churn_columns() {
        let table = render_markdown_table(&[PaperBenchmarkResult {
            scenario: "guardian_majority_4v".to_string(),
            validators: 4,
            safety_mode: "GuardianMajority".to_string(),
            lane: "base_final".to_string(),
            attempted: 256,
            accepted: 256,
            committed: 256,
            committed_blocks: 2,
            injection_tps: 10119.85,
            sustained_tps: 207.89,
            commit_latency: LatencySummary {
                p50_ms: 304.37,
                p95_ms: 1230.48,
                p99_ms: 1231.26,
                max_ms: 1231.26,
            },
            sampled_commit_visibility_lag_ms: Some(287),
            terminal_latency: None,
            terminal_close_blocks: 0,
            terminal_abort_blocks: 0,
            churn: BenchmarkChurnSummary {
                fallback_blocks: 1,
                max_replay_debt: 5128,
                max_validation_aborts: 4972,
                max_execution_errors: 2926,
            },
            submission: BenchmarkSubmissionSummary {
                submit_retries: 17,
                submit_timeout_retries: 3,
                submit_duplicates: 9,
                submit_latency: LatencySummary {
                    p50_ms: 18.5,
                    p95_ms: 77.0,
                    p99_ms: 91.0,
                    max_ms: 91.0,
                },
            },
            alignment: BenchmarkAlignmentSummary {
                requested_submit_lead_ms: 250,
                actual_start_lead_ms: 374,
                ready_budget_ms: 374,
                submit_complete_vs_due_ms: Some(-24),
                target_height: Some(11),
                committed_on_target_height: Some(false),
                first_committed_height_delta: Some(1),
                committed_before_target_height_txs: Some(64),
                committed_at_target_height_txs: Some(128),
            },
        }]);

        assert!(table.contains("fallback_blocks"));
        assert!(table.contains("max_replay_debt"));
        assert!(table.contains("submit_retries"));
        assert!(table.contains("submit_p50_ms"));
        assert!(table.contains("submit_duplicates"));
        assert!(table.contains("align_actual_start_lead_ms"));
        assert!(table.contains("submit_complete_vs_due_ms"));
        assert!(table.contains("align_hit_target_height"));
        assert!(table.contains("first_commit_height_delta"));
        assert!(table.contains("committed_before_target_height_txs"));
        assert!(table.contains("committed_at_target_height_txs"));
        assert!(table.contains("sampled_commit_visibility_lag_ms"));
        assert!(table.contains(
            "| guardian_majority_4v | 4 | GuardianMajority | base_final | 256 | 256 | 256 | 2 | 10119.85 | 207.89 | 1 | 5128 | 4972 | 2926 | 17 | 3 | 9 | 18.50 | 77.00 | 250 | 374 | 374 | -24 | 11 | no | 1 | 64 | 128 | 304.37 | 1230.48 | 1231.26 | 287 |"
        ));
    }
}
