use std::fs;
use std::path::{Path, PathBuf};

const RAW_VERIFIER: &str = "verify_wallet_approval_grant_binding(";

fn rust_files(root: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).expect("route source directory is readable") {
        let path = entry.expect("route entry is readable").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn live_routes_cannot_call_the_raw_approval_grant_verifier() {
    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../node/src/bin/hypervisor_daemon_routes");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    let allowed = [
        // The owner boundary treats this result as submitted evidence and follows it with
        // independently resolved current authority plus wallet-owned atomic consumption.
        "governed_authority.rs",
        // Existing v2 sequence-zero control immediately follows evidence verification with its
        // already-qualified owner resolution and wallet transaction.
        "system_sequence_zero_routes.rs",
    ];
    let mut violations = Vec::new();
    for path in files {
        let source = fs::read_to_string(&path).expect("route source is UTF-8");
        if source.contains(RAW_VERIFIER)
            && !allowed.contains(
                &path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or(""),
            )
        {
            violations.push(
                path.strip_prefix(&root)
                    .unwrap_or(&path)
                    .display()
                    .to_string(),
            );
        }
    }
    assert!(
        violations.is_empty(),
        "live route source calls the evidence-only raw verifier outside an owner admission boundary: {violations:?}"
    );
}
