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
    pub terminal_latency: Option<LatencySummary>,
    pub terminal_close_blocks: usize,
    pub terminal_abort_blocks: usize,
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
        "| scenario | validators | mode | lane | attempted | accepted | committed | blocks | injection_tps | sustained_tps | commit_p50_ms | commit_p95_ms | commit_p99_ms | terminal_p50_ms | terminal_p95_ms | terminal_close_blocks | terminal_abort_blocks |".to_string(),
        "|---|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|".to_string(),
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

        lines.push(format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {} | {} | {} | {} |",
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
            result.commit_latency.p50_ms,
            result.commit_latency.p95_ms,
            result.commit_latency.p99_ms,
            terminal_p50,
            terminal_p95,
            result.terminal_close_blocks,
            result.terminal_abort_blocks,
        ));
    }

    lines.join("\n")
}
