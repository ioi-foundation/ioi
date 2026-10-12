//! BUILD-DELTA #36, the class sweep. Every site in crates/node and crates/services that MINTS a bearer credential
//! (a token a caller presents to prove authority) is registered here by (file, function, prefix) with its entropy
//! source. The scan reads source text: it fails on a mint in an unregistered function, on a second mint of a prefix
//! in a registered function, on a mint whose statement is built from a derivation (a slice of a hash, a clock),
//! on a registered mint whose function no longer shows its entropy source, and on a function named like a
//! credential (token, secret, bearer, key, verifier, state, nonce, jwt) that builds a `<prefix>_{..}` value and is
//! neither registered nor reviewed by name. It proves what the source says, not what the runtime does.

use std::fs;
use std::path::{Path, PathBuf};

struct Mint {
    file: &'static str,
    function: &'static str,
    /// The literal prefix this function mints (`ioi_mnt_`), or "" for a primitive that mints without one.
    prefix: &'static str,
    /// How many `"<prefix>…{…"` literals the function holds.
    count: usize,
    /// The entropy source the function body must show.
    entropy: &'static str,
    /// Statement fragments tolerated for this mint (a one-way id of the secret, never the secret).
    tolerates: &'static [&'static str],
    note: &'static str,
}

const DISCOVERY_NAMES: &[&str] = &[
    "token", "secret", "bearer", "key", "verifier", "state", "nonce", "jwt",
];

/// Concrete credential prefixes: every non-test literal that starts with one and holds a placeholder is a mint.
const PREFIXES: &[&str] = &[
    "ioi_mnt_",
    "ioi_pat_",
    "ioi_lease_",
    "wec_",
    "wbt_",
    "whk_",
    "idisp_",
    "ioi_sess_",
    "ioi_bootstrap_",
    "ioi_api_",
];

const MINTS: &[Mint] = &[
    Mint { file: "node/src/bin/hypervisor-daemon.rs", function: "async_main", prefix: "idisp_", count: 1, entropy: "uuid::Uuid::new_v4()", tolerates: &[], note: "per-boot internal dispatch secret: two UUIDv4 (244 bits), process memory only" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/authority_routes.rs", function: "issue_bearer_capability_lease", prefix: "ioi_lease_", count: 1, entropy: "rand::rngs::OsRng.fill_bytes(&mut secret)", tolerates: &[], note: "env-ops capability lease bearer: 32 bytes from the OS RNG" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", function: "handle_api_token_create", prefix: "ioi_pat_", count: 1, entropy: "uuid::Uuid::new_v4()", tolerates: &[], note: "API access tokens: two UUIDv4" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", function: "gen_opaque", prefix: "", count: 0, entropy: "uuid::Uuid::new_v4()", tolerates: &[], note: "bootstrap, session, SCIM and invite tokens: two UUIDv4 behind one primitive" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", function: "random_token", prefix: "", count: 0, entropy: "rand::thread_rng()", tolerates: &[], note: "OAuth state, nonce and PKCE verifier: the thread CSPRNG, seeded from the OS" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", function: "mint_github_app_jwt", prefix: "", count: 0, entropy: "jwt_encode(", tolerates: &[], note: "GitHub App JWT: SIGNED with the App private key (RS256), not random; its secrecy is the key's" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/managed_runtime_routes.rs", function: "handle_backup_export", prefix: "", count: 0, entropy: "uuid::Uuid::new_v4()", tolerates: &[], note: "managed backup export download token: UUIDv4 (122 bits), stored as a hash" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/orchestration_routes.rs", function: "new_webhook_token", prefix: "whk_", count: 1, entropy: "uuid::Uuid::new_v4()", tolerates: &[], note: "automation webhook trigger token: two UUIDv4" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/orchestration_routes.rs", function: "handle_automation_webhook", prefix: "whk_", count: 1, entropy: "uuid::Uuid::new_v4()", tolerates: &[], note: "webhook EVENT id (whk_evt_), not a credential: a UUIDv4" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/workload_effect_boundary.rs", function: "mint_guest_effect_capability", prefix: "wec_", count: 2, entropy: "OsRng.fill_bytes(&mut random)", tolerates: &["[.."], note: "workload effect capability token (32 OS-RNG bytes) and its ID, a one-way 32-hex prefix of the token's SHA-256" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/workload_effect_boundary.rs", function: "mint_guest_governed_provider_effect_capability", prefix: "wbt_", count: 1, entropy: "OsRng.fill_bytes(&mut trigger_random)", tolerates: &[], note: "host trigger: 32 bytes from the OS RNG" },
    Mint { file: "services/src/agentic/runtime/kernel/model_mount/capability_token_control.rs", function: "plan_capability_token_control", prefix: "ioi_mnt_", count: 1, entropy: "OsRng.fill_bytes(&mut secret)", tolerates: &[], note: "model-mount capability token: 32 bytes from the OS RNG, id drawn separately" },
    Mint { file: "services/src/agentic/runtime/connectors/google_auth.rs", function: "random_url_safe_token", prefix: "", count: 0, entropy: "rand::thread_rng()", tolerates: &[], note: "Google OAuth state and PKCE verifier primitive: the thread CSPRNG" },
    Mint { file: "services/src/agentic/runtime/connectors/google_auth.rs", function: "login", prefix: "", count: 0, entropy: "random_url_safe_token(48)", tolerates: &[], note: "Google OAuth state (24 bytes) and PKCE code_verifier (48 bytes) come from that primitive" },
];

/// Credential-NAMED functions that build a `<prefix>_{..}` value and were reviewed: each is an identifier or key, or a
/// nonce with its own entropy, not a bearer. Reviewed by name; a new one must be added here with its reason.
const DISCOVERY_REVIEWED: &[(&str, &str, &str)] = &[
    ("node/src/bin/hypervisor_daemon_routes/authority_challenge_routes.rs", "process_nonce", "in-flight marker for this process: 96 random bits, not presented anywhere"),
    ("node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", "session_create_intent_key", "a record key derived from a session ref, not a credential"),
    ("node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", "session_record_key", "a record key derived from a session ref, not a credential"),
    ("node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", "session_receipt_key", "a record key derived from a session ref, not a credential"),
    ("node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", "launch_record_key", "a record key, not a credential"),
    ("node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", "standing_draw_nonce", "an anti-replay nonce: nanoseconds then 64 random bits; it authorizes nothing by itself"),
    ("node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", "handle_secret_create", "sec_ is the public id of a stored secret (a hash of scope and name); the value is sealed"),
    ("node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", "handle_api_token_create", "pat_ is the token's public id, a short hash of the token's SHA-256 (BUILD-DELTA #40); the token is the ioi_pat_ mint, registered above"),
    ("node/src/bin/hypervisor_daemon_routes/provider_spend_reconciliation_routes.rs", "handle_provider_billing_statement_admit", "pbs_ is a statement id"),
    ("node/src/bin/hypervisor_daemon_routes/state_machine_routes.rs", "handle_state_machine_create", "sm_ is a state-machine id"),
    ("services/src/agentic/automation.rs", "monitor_workflow_id_from_keywords", "a workflow id built from keywords"),
    ("services/src/agentic/runtime/kernel/approval.rs", "approval_state_update_thread_id_for_agent_id", "a thread id"),
];

/// RED: the scan is not implemented yet.
fn scan(_files: &[(String, String)]) -> Vec<String> {
    Vec::new()
}

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path
                .file_name()
                .is_some_and(|n| n == "tests" || n == "target")
            {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn real_tree() -> Vec<(String, String)> {
    let mut paths = Vec::new();
    rust_files(&crates_dir().join("node/src"), &mut paths);
    rust_files(&crates_dir().join("services/src"), &mut paths);
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let rel = path
                .strip_prefix(crates_dir())
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel}: {e}"));
            (rel, text)
        })
        .collect()
}

/// The real tree with one file's text edited: the planted counterexamples.
fn tree_with(rel: &str, edit: impl Fn(&str) -> String) -> Vec<(String, String)> {
    let mut tree = real_tree();
    let entry = tree
        .iter_mut()
        .find(|(r, _)| r == rel)
        .unwrap_or_else(|| panic!("{rel} is in the tree"));
    entry.1 = edit(&entry.1);
    tree
}

const KERNEL: &str = "services/src/agentic/runtime/kernel/model_mount/capability_token_control.rs";
const ORCH: &str = "node/src/bin/hypervisor_daemon_routes/orchestration_routes.rs";
const AUTH: &str = "node/src/bin/hypervisor_daemon_routes/authority_routes.rs";

#[test]
fn the_real_tree_has_no_unregistered_mint_and_every_registered_mint_shows_its_entropy() {
    let violations = scan(&real_tree());
    assert!(
        violations.is_empty(),
        "minting sites outside the registry:\n{}",
        violations.join("\n")
    );
}

#[test]
fn a_second_derived_ioi_mnt_mint_in_the_kernel_file_fails_the_sweep() {
    let tree = tree_with(KERNEL, |text| {
        text.replacen(
            "let minted = format!(\"ioi_mnt_{}\", hex_lower(&secret));",
            "let minted = format!(\"ioi_mnt_{}\", hex_lower(&secret));\n            let second = format!(\"ioi_mnt_{}\", &create_hash[..32]);",
            1,
        )
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("ioi_mnt_")),
        "the planted second mint is caught: {violations:?}"
    );
}

#[test]
fn a_timestamp_derived_whk_mint_fails_the_sweep() {
    let tree = tree_with(ORCH, |text| {
        let start = text.find("fn new_webhook_token() -> String {").unwrap();
        let end = start + text[start..].find("\n}\n").unwrap() + 3;
        format!(
            "{}fn new_webhook_token() -> String {{\n    format!(\"whk_{{}}\", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis())\n}}\n{}",
            &text[..start],
            &text[end..]
        )
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("whk_")),
        "the planted timestamp mint is caught: {violations:?}"
    );
}

#[test]
fn a_mint_in_an_unregistered_function_fails_the_sweep() {
    let tree = tree_with(ORCH, |text| {
        format!("{text}\nfn mint_a_capability() -> String {{\n    format!(\"wec_{{}}\", 1)\n}}\n")
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("mint_a_capability")),
        "{violations:?}"
    );
}

#[test]
fn a_credential_named_function_building_a_new_prefix_fails_the_sweep() {
    let tree = tree_with(AUTH, |text| {
        format!("{text}\nfn fresh_secret_key() -> String {{\n    format!(\"zzk_{{}}\", 7)\n}}\n")
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("fresh_secret_key")),
        "{violations:?}"
    );
}

#[test]
fn a_registered_minting_function_that_disappears_fails_the_sweep() {
    let tree = tree_with(ORCH, |text| {
        text.replacen("fn new_webhook_token()", "fn renamed_webhook_token()", 1)
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("new_webhook_token")),
        "{violations:?}"
    );
}

#[test]
fn a_mint_inside_a_test_module_is_not_a_production_mint() {
    let tree = tree_with(AUTH, |text| {
        format!("{text}\n#[cfg(test)]\nmod planted {{\n    fn bearer() -> String {{\n        format!(\"ioi_pat_{{}}\", 1)\n    }}\n}}\n")
    });
    assert!(scan(&tree).is_empty());
}
