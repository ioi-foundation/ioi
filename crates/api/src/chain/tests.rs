// Path: crates/api/src/chain/tests.rs
//! Tests for individual block execution receipt material.

use super::*;
use ioi_types::app::{
    AccountId, ChainId, SignHeader, SignatureProof, SystemPayload, SystemTransaction,
};

const HEIGHT: u64 = 42;

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

fn proof_for(index: usize) -> Vec<u8> {
    vec![0xAB, index as u8, 0xCD]
}

fn gas_for(index: usize) -> u64 {
    100 + index as u64
}

/// Builds the receipt set, proofs, and gas total a well-formed block would carry.
fn well_formed(
    transactions: &[ChainTransaction],
) -> (Vec<BlockExecutionReceipt>, Vec<Vec<u8>>, u64) {
    let mut receipts = Vec::new();
    let mut proofs = Vec::new();
    let mut gas_used = 0u64;

    for (index, tx) in transactions.iter().enumerate() {
        let proof_bytes = proof_for(index);
        let tx_gas = gas_for(index);
        receipts.push(BlockExecutionReceipt::for_success(
            HEIGHT,
            index as u64,
            tx.hash().expect("transaction hash"),
            tx_gas,
            &proof_bytes,
        ));
        gas_used += tx_gas;
        proofs.push(proof_bytes);
    }

    (receipts, proofs, gas_used)
}

#[test]
fn material_matches_the_registered_bundle_v2_shape() {
    let transactions = vec![transaction(1)];
    let (receipts, _, _) = well_formed(&transactions);
    let material = receipts[0].material().expect("material");
    let object = material.as_object().expect("material is a JSON object");

    // `receipt-proof-bundle.v2` `$defs/material` is exactly these three keys,
    // with `additionalProperties: false`.
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["body", "body_hash", "sequence"]);

    assert_eq!(object["sequence"], 0);
    assert!(object["body"].is_object());

    let body_hash = object["body_hash"].as_str().expect("body_hash is a string");
    let (algorithm, digest) = body_hash.split_once(':').expect("sha256-labelled hash");
    assert_eq!(algorithm, "sha256");
    assert_eq!(digest.len(), 64);
    assert!(digest
        .chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));

    // Recomputed here rather than read back from `body_hash()`, so this asserts
    // the value a verifier would independently derive.
    let expected = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            serde_jcs::to_vec(&object["body"]).expect("JCS encoding")
        ))
    );
    assert_eq!(body_hash, expected);
}

#[test]
fn body_binds_schema_version_domain_and_the_observed_execution_facts() {
    let tx = transaction(7);
    let tx_hash = tx.hash().expect("transaction hash");
    let proof_bytes = proof_for(0);
    let receipt = BlockExecutionReceipt::for_success(HEIGHT, 3, tx_hash, 4_242, &proof_bytes);
    let body = receipt.body().expect("body");

    assert_eq!(body["schema"], BLOCK_EXECUTION_RECEIPT_SCHEMA);
    assert_eq!(body["version"], BLOCK_EXECUTION_RECEIPT_VERSION);
    assert_eq!(body["domain"], BLOCK_EXECUTION_RECEIPT_DOMAIN);
    assert_eq!(body["block_height"], HEIGHT);
    assert_eq!(body["transaction_index"], 3);
    assert_eq!(
        body["transaction_hash"],
        format!("sha256:{}", hex::encode(tx_hash))
    );
    assert_eq!(body["outcome"], "success");
    assert_eq!(body["gas_used"], 4_242);
    assert_eq!(body["proof_present"], true);
    assert_eq!(
        body["proof_hash"],
        format!("sha256:{}", hex::encode(Sha256::digest(&proof_bytes)))
    );
}

#[test]
fn an_absent_proof_is_reported_as_absent_rather_than_as_a_placeholder() {
    let tx = transaction(9);
    let receipt =
        BlockExecutionReceipt::for_success(HEIGHT, 0, tx.hash().expect("transaction hash"), 0, &[]);

    assert!(!receipt.proof_present);
    // The honest hash of the bytes actually emitted (none), not a sentinel.
    let empty_digest: [u8; 32] = Sha256::digest(b"").into();
    assert_eq!(receipt.proof_hash, empty_digest);
}

#[test]
fn the_body_hash_binds_every_field_the_receipt_claims() {
    let transactions = vec![transaction(3), transaction(4)];
    let base = BlockExecutionReceipt::for_success(
        HEIGHT,
        0,
        transactions[0].hash().expect("transaction hash"),
        500,
        &proof_for(0),
    );
    let baseline = base.body_hash().expect("baseline body hash");

    // `outcome` is absent from this table on purpose: it has exactly one
    // variant today, so there is no second value to mutate it to. That is a
    // named residual, not an unbound field.
    let mutations: Vec<(&str, BlockExecutionReceipt)> = vec![
        (
            "schema",
            BlockExecutionReceipt {
                schema: "ioi.some-other-receipt".into(),
                ..base.clone()
            },
        ),
        (
            "version",
            BlockExecutionReceipt {
                version: base.version + 1,
                ..base.clone()
            },
        ),
        (
            "domain",
            BlockExecutionReceipt {
                domain: "ioi.some-other-receipt.v1".into(),
                ..base.clone()
            },
        ),
        (
            "block_height",
            BlockExecutionReceipt {
                block_height: HEIGHT + 1,
                ..base.clone()
            },
        ),
        (
            "transaction_index",
            BlockExecutionReceipt {
                transaction_index: 1,
                ..base.clone()
            },
        ),
        (
            "transaction_hash",
            BlockExecutionReceipt {
                transaction_hash: transactions[1].hash().expect("transaction hash"),
                ..base.clone()
            },
        ),
        (
            "gas_used",
            BlockExecutionReceipt {
                gas_used: 501,
                ..base.clone()
            },
        ),
        (
            "proof_present",
            BlockExecutionReceipt {
                proof_present: false,
                ..base.clone()
            },
        ),
        (
            "proof_hash",
            BlockExecutionReceipt {
                proof_hash: [9u8; 32],
                ..base.clone()
            },
        ),
    ];

    for (field, mutated) in mutations {
        assert_ne!(
            mutated.body_hash().expect("mutated body hash"),
            baseline,
            "receipt body_hash does not bind '{field}'"
        );
    }
}

#[test]
fn distinct_transactions_produce_distinct_receipt_bodies() {
    let transactions = vec![transaction(1), transaction(2)];
    let (receipts, _, _) = well_formed(&transactions);

    assert_ne!(
        receipts[0].body_hash().expect("first body hash"),
        receipts[1].body_hash().expect("second body hash")
    );
}

#[test]
fn an_empty_block_validates_with_zero_receipts() {
    validate_block_execution_receipts(&[], &[], &[], HEIGHT, 0).expect("empty block validates");
}

#[test]
fn a_complete_in_order_receipt_set_validates() {
    let transactions = vec![transaction(1), transaction(2), transaction(3)];
    let (receipts, proofs, gas_used) = well_formed(&transactions);

    validate_block_execution_receipts(&receipts, &transactions, &proofs, HEIGHT, gas_used)
        .expect("well-formed receipt set validates");
}

#[test]
fn a_missing_receipt_is_rejected() {
    let transactions = vec![transaction(1), transaction(2)];
    let (mut receipts, proofs, gas_used) = well_formed(&transactions);
    receipts.pop();

    assert!(
        validate_block_execution_receipts(&receipts, &transactions, &proofs, HEIGHT, gas_used)
            .is_err()
    );
}

#[test]
fn reordered_receipts_are_rejected() {
    let transactions = vec![transaction(1), transaction(2)];
    let (mut receipts, proofs, gas_used) = well_formed(&transactions);
    receipts.swap(0, 1);

    assert!(
        validate_block_execution_receipts(&receipts, &transactions, &proofs, HEIGHT, gas_used)
            .is_err()
    );
}

#[test]
fn duplicated_receipts_are_rejected() {
    let transactions = vec![transaction(1), transaction(2)];
    let (mut receipts, proofs, _) = well_formed(&transactions);
    receipts[1] = receipts[0].clone();
    // Repeat the first receipt's gas too, so only the duplication is under test.
    let gas_used: u64 = receipts.iter().map(|receipt| receipt.gas_used).sum();

    assert!(
        validate_block_execution_receipts(&receipts, &transactions, &proofs, HEIGHT, gas_used)
            .is_err()
    );
}

#[test]
fn a_receipt_bound_to_another_transaction_is_rejected() {
    let transactions = vec![transaction(1), transaction(2)];
    let (mut receipts, proofs, gas_used) = well_formed(&transactions);
    receipts[0].transaction_hash = transactions[1].hash().expect("transaction hash");

    assert!(
        validate_block_execution_receipts(&receipts, &transactions, &proofs, HEIGHT, gas_used)
            .is_err()
    );
}

#[test]
fn a_receipt_unbound_from_its_proof_is_rejected() {
    let transactions = vec![transaction(1), transaction(2)];
    let (receipts, mut proofs, gas_used) = well_formed(&transactions);
    proofs[0].push(0xFF);

    assert!(
        validate_block_execution_receipts(&receipts, &transactions, &proofs, HEIGHT, gas_used)
            .is_err()
    );
}

#[test]
fn receipt_gas_must_account_for_the_block_total() {
    let transactions = vec![transaction(1), transaction(2)];
    let (receipts, proofs, gas_used) = well_formed(&transactions);

    assert!(validate_block_execution_receipts(
        &receipts,
        &transactions,
        &proofs,
        HEIGHT,
        gas_used + 1
    )
    .is_err());
}

#[test]
fn receipt_gas_accounting_refuses_u64_overflow() {
    let transactions = vec![transaction(1), transaction(2)];
    let (mut receipts, proofs, _) = well_formed(&transactions);
    receipts[0].gas_used = u64::MAX;
    receipts[1].gas_used = 1;

    let error = validate_block_execution_receipts(
        &receipts,
        &transactions,
        &proofs,
        HEIGHT,
        u64::MAX,
    )
    .expect_err("gas overflow must refuse");
    assert!(error.to_string().contains("overflows u64"));
}

#[test]
fn a_receipt_bound_to_another_block_is_rejected() {
    let transactions = vec![transaction(1)];
    let (mut receipts, proofs, gas_used) = well_formed(&transactions);
    receipts[0].block_height = HEIGHT + 1;

    assert!(
        validate_block_execution_receipts(&receipts, &transactions, &proofs, HEIGHT, gas_used)
            .is_err()
    );
}

#[test]
fn schema_version_or_domain_drift_is_rejected() {
    let transactions = vec![transaction(1)];
    let (receipts, proofs, gas_used) = well_formed(&transactions);

    let drifted = [
        BlockExecutionReceipt {
            schema: "ioi.some-other-receipt".into(),
            ..receipts[0].clone()
        },
        BlockExecutionReceipt {
            version: BLOCK_EXECUTION_RECEIPT_VERSION + 1,
            ..receipts[0].clone()
        },
        BlockExecutionReceipt {
            domain: "ioi.some-other-receipt.v1".into(),
            ..receipts[0].clone()
        },
    ];

    for receipt in drifted {
        assert!(validate_block_execution_receipts(
            std::slice::from_ref(&receipt),
            &transactions,
            &proofs,
            HEIGHT,
            gas_used
        )
        .is_err());
    }
}

#[test]
fn an_integer_beyond_jcs_range_is_refused_rather_than_rounded() {
    let tx = transaction(1);
    let receipt = BlockExecutionReceipt::for_success(
        HEIGHT,
        0,
        tx.hash().expect("transaction hash"),
        JCS_SAFE_INTEGER_MAX + 1,
        &proof_for(0),
    );

    assert!(receipt.body().is_err());
    assert!(receipt.body_hash().is_err());
    assert!(receipt.material().is_err());
}
