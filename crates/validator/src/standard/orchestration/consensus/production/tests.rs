use super::{parse_failed_tx_index, retain_nonce_heads_for_canonical_order};
use ioi_types::app::{
    AccountId, ChainId, ChainTransaction, SignHeader, SignatureProof, SignatureSuite,
    SystemPayload, SystemTransaction,
};

fn system_tx(account_id: AccountId, nonce: u64) -> ChainTransaction {
    ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id,
            nonce,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "guardian_registry".to_string(),
            method: "publish_aft_canonical_order_artifact_bundle@v1".to_string(),
            params: Vec::new(),
        },
        signature_proof: SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key: Vec::new(),
            signature: Vec::new(),
        },
    }))
}

#[test]
fn parses_failed_tx_index_from_execution_errors() {
    assert_eq!(
        parse_failed_tx_index("Transaction processing error: tx_index=3: Invalid transaction"),
        Some(3)
    );
    assert_eq!(
        parse_failed_tx_index("Execution client transport error: tx_index=17: boom"),
        Some(17)
    );
    assert_eq!(parse_failed_tx_index("no tx index here"), None);
}

#[test]
fn canonical_order_selection_retains_only_each_accounts_lowest_nonce() {
    let first_account = AccountId([1u8; 32]);
    let second_account = AccountId([2u8; 32]);
    let transactions = vec![
        system_tx(first_account, 4),
        system_tx(second_account, 7),
        system_tx(first_account, 2),
        system_tx(second_account, 8),
    ];

    let retained = retain_nonce_heads_for_canonical_order(&transactions);
    let retained_scopes = retained
        .iter()
        .map(|tx| super::nonce_scope(tx).expect("system transaction has nonce scope"))
        .collect::<Vec<_>>();

    assert_eq!(
        retained_scopes,
        vec![(second_account, 7), (first_account, 2)]
    );
}
