use super::{
    build_block_execution_receipts, replay_gate_label, ExecutedTransaction,
    ParallelReplayStatsSnapshot,
};
use ioi_api::chain::{
    TransactionExecutionOutcome, BLOCK_EXECUTION_RECEIPT_DOMAIN, BLOCK_EXECUTION_RECEIPT_SCHEMA,
    BLOCK_EXECUTION_RECEIPT_VERSION,
};
use ioi_types::app::{
    AccountId, ChainId, ChainTransaction, SignHeader, SignatureProof, SystemPayload,
    SystemTransaction,
};

#[test]
fn replay_stats_only_fallback_on_internal_errors() {
    assert_eq!(
        ParallelReplayStatsSnapshot {
            validation_aborts: 7,
            validation_errors: 0,
            validation_rewinds: 3,
            execution_errors: 0,
            validation_abort_budget_exhausted: false,
        }
        .fallback_gate(),
        None
    );
    assert_eq!(
        ParallelReplayStatsSnapshot {
            validation_aborts: 0,
            validation_errors: 1,
            validation_rewinds: 0,
            execution_errors: 0,
            validation_abort_budget_exhausted: false,
        }
        .fallback_gate(),
        Some("parallel_validation_error_fallback")
    );
    assert_eq!(
        ParallelReplayStatsSnapshot {
            validation_aborts: 4,
            validation_errors: 2,
            validation_rewinds: 1,
            execution_errors: 9,
            validation_abort_budget_exhausted: false,
        }
        .fallback_gate(),
        Some("parallel_execution_error_fallback")
    );
    assert_eq!(
        ParallelReplayStatsSnapshot {
            validation_aborts: 64,
            validation_errors: 0,
            validation_rewinds: 0,
            execution_errors: 0,
            validation_abort_budget_exhausted: true,
        }
        .fallback_gate(),
        Some("parallel_validation_abort_budget_fallback")
    );
}

#[test]
fn system_service_calls_use_sequential_replay_gate() {
    assert_eq!(
        replay_gate_label(4, false, false, false, true),
        "system_service_calls"
    );
    assert_eq!(replay_gate_label(4, false, false, false, false), "parallel");
}

const RECEIPT_TEST_HEIGHT: u64 = 17;

fn transaction(seed: u8) -> ChainTransaction {
    ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([seed; 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "execution_receipts".into(),
            method: "noop@v1".into(),
            params: vec![seed],
        },
        signature_proof: SignatureProof::default(),
    }))
}

#[test]
fn an_empty_block_mints_no_receipts() {
    let receipts = build_block_execution_receipts(&[], &[], RECEIPT_TEST_HEIGHT)
        .expect("empty block builds a receipt set");

    assert!(receipts.is_empty());
}

#[test]
fn receipts_follow_block_order_and_bind_per_transaction_results() {
    let transactions = vec![transaction(1), transaction(2)];
    let executed = vec![
        ExecutedTransaction {
            proof_bytes: vec![0xA0, 0xA1],
            gas_used: 11,
        },
        ExecutedTransaction {
            proof_bytes: vec![0xB0, 0xB1, 0xB2],
            gas_used: 22,
        },
    ];

    let receipts = build_block_execution_receipts(&transactions, &executed, RECEIPT_TEST_HEIGHT)
        .expect("receipt set");

    assert_eq!(receipts.len(), 2);
    for (index, receipt) in receipts.iter().enumerate() {
        assert_eq!(receipt.transaction_index, index as u64);
        assert_eq!(receipt.block_height, RECEIPT_TEST_HEIGHT);
        assert_eq!(receipt.schema, BLOCK_EXECUTION_RECEIPT_SCHEMA);
        assert_eq!(receipt.version, BLOCK_EXECUTION_RECEIPT_VERSION);
        assert_eq!(receipt.domain, BLOCK_EXECUTION_RECEIPT_DOMAIN);
        assert_eq!(receipt.outcome, TransactionExecutionOutcome::Success);
        assert!(receipt.proof_present);
        assert_eq!(
            receipt.transaction_hash,
            transactions[index].hash().expect("transaction hash")
        );
    }

    // Each receipt carries its OWN gas, never the block aggregate (33).
    assert_eq!(receipts[0].gas_used, 11);
    assert_eq!(receipts[1].gas_used, 22);
    // ...and its own proof, so the two receipts are not interchangeable.
    assert_ne!(receipts[0].proof_hash, receipts[1].proof_hash);
}

#[test]
fn a_result_count_mismatch_refuses_to_mint_receipts() {
    let transactions = vec![transaction(1), transaction(2)];
    let executed = vec![ExecutedTransaction {
        proof_bytes: vec![0xA0],
        gas_used: 11,
    }];

    assert!(
        build_block_execution_receipts(&transactions, &executed, RECEIPT_TEST_HEIGHT).is_err(),
        "a short result set must not be padded into a full receipt set"
    );
}

/// Sequential, parallel, and fallback-sequential preparation all funnel their
/// per-transaction results through this one builder, so identical successful
/// executions mint byte-identical receipts. This asserts the builder half of
/// that property; the single-funnel half is structural (see `prepare_block`).
#[test]
fn identical_execution_results_mint_identical_receipts() {
    let transactions = vec![transaction(1), transaction(2), transaction(3)];
    let executed: Vec<ExecutedTransaction> = (0u8..3)
        .map(|index| ExecutedTransaction {
            proof_bytes: vec![0xC0, index],
            gas_used: 100 + u64::from(index),
        })
        .collect();

    let first = build_block_execution_receipts(&transactions, &executed, RECEIPT_TEST_HEIGHT)
        .expect("first receipt set");
    let second = build_block_execution_receipts(&transactions, &executed, RECEIPT_TEST_HEIGHT)
        .expect("second receipt set");

    assert_eq!(first, second);

    let first_material: Vec<_> = first
        .iter()
        .map(|receipt| receipt.material().expect("material"))
        .collect();
    let second_material: Vec<_> = second
        .iter()
        .map(|receipt| receipt.material().expect("material"))
        .collect();
    assert_eq!(first_material, second_material);
}
