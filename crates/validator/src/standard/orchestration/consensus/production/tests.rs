use super::parse_failed_tx_index;

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
