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
// ---------------------------------------------------------------------------------------------------------------
// The scanner. It reads source TEXT (std only) and reports violations; the tests below feed it the real tree and
// planted counterexamples. Strings, chars and comments are blanked in a "code" copy so braces inside them do not
// confuse function and test-module spans; literals are read from the original text.
// ---------------------------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Func {
    name: String,
    start: usize, // byte offset of `fn`
    end: usize,   // byte offset one past the closing brace
}

/// Same length as `text`, with the inside of every string, char literal and comment replaced by spaces (newlines kept).
fn blank_literals(text: &str) -> String {
    let b: Vec<u8> = text.bytes().collect();
    let mut out: Vec<u8> = b.clone();
    let mut i = 0;
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for k in from..to.min(out.len()) {
            if out[k] != b'\n' {
                out[k] = b' ';
            }
        }
    };
    while i < b.len() {
        let c = b[i];
        if c == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            let mut j = i;
            while j < b.len() && b[j] != b'\n' {
                j += 1;
            }
            blank(&mut out, i, j);
            i = j;
        } else if c == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            let mut j = i + 2;
            while j + 1 < b.len() && !(b[j] == b'*' && b[j + 1] == b'/') {
                j += 1;
            }
            blank(&mut out, i, (j + 2).min(b.len()));
            i = j + 2;
        } else if c == b'r'
            && i + 1 < b.len()
            && (b[i + 1] == b'"' || b[i + 1] == b'#')
            && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
        {
            let mut j = i + 1;
            let mut hashes = 0;
            while j < b.len() && b[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < b.len() && b[j] == b'"' {
                let mut k = j + 1;
                loop {
                    if k >= b.len() {
                        break;
                    }
                    if b[k] == b'"'
                        && (0..hashes).all(|h| k + 1 + h < b.len() && b[k + 1 + h] == b'#')
                    {
                        break;
                    }
                    k += 1;
                }
                blank(&mut out, j + 1, k);
                i = k + 1 + hashes;
            } else {
                i += 1;
            }
        } else if c == b'"' {
            let mut j = i + 1;
            while j < b.len() && b[j] != b'"' {
                if b[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            blank(&mut out, i + 1, j);
            i = j + 1;
        } else if c == b'\'' {
            // a char literal (b'x', '\n', b'{') but not a lifetime ('a)
            if i + 2 < b.len() && b[i + 1] == b'\\' {
                let mut j = i + 2;
                while j < b.len() && b[j] != b'\'' {
                    j += 1;
                }
                blank(&mut out, i + 1, j);
                i = j + 1;
            } else if i + 2 < b.len() && b[i + 2] == b'\'' {
                blank(&mut out, i + 1, i + 2);
                i += 3;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

fn matching_brace(code: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0i32;
    for (k, &ch) in code.iter().enumerate().skip(open) {
        if ch == b'{' {
            depth += 1;
        } else if ch == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(k + 1);
            }
        }
    }
    None
}

/// Byte-offset spans of `fn` items (name, start, end) and of `#[cfg(test)]` blocks.
fn spans(code: &str) -> (Vec<Func>, Vec<(usize, usize)>) {
    let bytes = code.as_bytes();
    let mut funcs = Vec::new();
    let mut tests = Vec::new();
    let mut search = 0;
    while let Some(rel) = code[search..].find("fn ") {
        let at = search + rel;
        search = at + 3;
        if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_') {
            continue;
        }
        let name: String = code[at + 3..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        // the body opens at the first `{` before a `;` (a trait item or an extern fn has none)
        let mut k = at + 3 + name.len();
        let mut open = None;
        let mut paren = 0i32;
        while k < bytes.len() {
            match bytes[k] {
                b'(' | b'[' => paren += 1,
                b')' | b']' => paren -= 1,
                b'{' if paren <= 0 => {
                    open = Some(k);
                    break;
                }
                b';' if paren <= 0 => break,
                _ => {}
            }
            k += 1;
        }
        if let Some(open) = open {
            if let Some(end) = matching_brace(bytes, open) {
                funcs.push(Func {
                    name,
                    start: at,
                    end,
                });
            }
        }
    }
    let mut s = 0;
    while let Some(rel) = code[s..].find("#[cfg(test)]") {
        let at = s + rel;
        s = at + 12;
        if let Some(open_rel) = code[s..].find('{') {
            let open = s + open_rel;
            // only a `mod`/`fn`/`impl` item header sits between the attribute and its brace
            let header = &code[s..open];
            if header.len() < 200 && !header.contains(';') {
                if let Some(end) = matching_brace(bytes, open) {
                    tests.push((at, end));
                }
            }
        }
    }
    (funcs, tests)
}

fn enclosing<'a>(funcs: &'a [Func], at: usize) -> Option<&'a Func> {
    funcs
        .iter()
        .filter(|f| f.start <= at && at < f.end)
        .min_by_key(|f| f.end - f.start)
}

fn line_of(text: &str, at: usize) -> usize {
    text[..at].matches('\n').count() + 1
}

/// Every `"<prefix>…{…"` string literal (the literal starts with the prefix and holds a placeholder), by byte offset.
fn prefix_literals(text: &str, prefix: &str) -> Vec<usize> {
    let needle = format!("\"{prefix}");
    let mut out = Vec::new();
    let mut s = 0;
    while let Some(rel) = text[s..].find(&needle) {
        let at = s + rel;
        s = at + needle.len();
        let literal_end = text[at + 1..]
            .find('"')
            .map(|e| at + 1 + e)
            .unwrap_or(text.len());
        if text[at + 1..literal_end].contains('{') {
            out.push(at);
        }
    }
    out
}

/// Literals shaped like `<word>_{…}` (a prefix followed by a placeholder): `"abc_{}"`, `"abc_evt_{}"`.
fn shaped_prefix_literals(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut s = 0;
    while let Some(rel) = text[s..].find('"') {
        let at = s + rel;
        let Some(end_rel) = text[at + 1..].find('"') else {
            break;
        };
        let end = at + 1 + end_rel;
        let literal = &text[at + 1..end];
        s = end + 1;
        let head: String = literal
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        if head.len() >= 3
            && head.len() <= 20
            && head.ends_with('_')
            && literal[head.len()..].starts_with('{')
        {
            out.push((at, head));
        }
    }
    out
}

/// The statement text from `at` to the next `;` (the minted expression).
fn statement_from(text: &str, at: usize) -> &str {
    let end = text[at..].find(';').map(|e| at + e).unwrap_or(text.len());
    &text[at..end]
}

/// Scan the given files. Returns one line per violation; empty means the registry is closed over these files.
fn scan(files: &[(String, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    let mut counts = vec![0usize; MINTS.len()];
    for (rel, text) in files {
        let code = blank_literals(text);
        let (funcs, tests) = spans(&code);
        let in_test = |at: usize| tests.iter().any(|(a, b)| *a <= at && at < *b);
        // 1. every concrete credential prefix mint
        let mut occurrences: Vec<(usize, String)> = Vec::new();
        for prefix in PREFIXES {
            for at in prefix_literals(text, prefix) {
                occurrences.push((at, (*prefix).to_string()));
            }
        }
        // prefixes found by shape inside credential-named functions are handled in pass 2
        occurrences.sort();
        for (at, prefix) in occurrences {
            if in_test(at) {
                continue;
            }
            let func = enclosing(&funcs, at)
                .map(|f| f.name.clone())
                .unwrap_or_else(|| "<no function>".to_string());
            let hit = MINTS
                .iter()
                .position(|m| m.file == rel && m.function == func && m.prefix == prefix);
            let Some(index) = hit else {
                violations.push(format!("{rel}:{}: `{prefix}…` is minted in `{func}`, which is not a registered minting site", line_of(text, at)));
                continue;
            };
            counts[index] += 1;
            let mint = &MINTS[index];
            let func_span = enclosing(&funcs, at).unwrap();
            let body = &text[func_span.start..func_span.end];
            if !body.contains(mint.entropy) {
                violations.push(format!("{rel}:{}: the `{prefix}…` mint in `{func}` does not show its registered entropy source {:?}", line_of(text, at), mint.entropy));
            }
            let statement = statement_from(text, at);
            for forbidden in [
                "[..",
                "hash_json(",
                "create_hash",
                "as_millis",
                "as_secs",
                "as_nanos",
                "SystemTime",
                "Instant::now",
            ] {
                if statement.contains(forbidden) && !mint.tolerates.contains(&forbidden) {
                    violations.push(format!("{rel}:{}: the `{prefix}…` mint in `{func}` is built from a derivation ({forbidden:?})", line_of(text, at)));
                }
            }
        }
        // 2. discovery: a credential-named function that builds a prefixed value must be registered or reviewed
        for func in &funcs {
            let lower = func.name.to_lowercase();
            if !DISCOVERY_NAMES.iter().any(|w| lower.contains(w)) || in_test(func.start) {
                continue;
            }
            for (at, head) in shaped_prefix_literals(&text[func.start..func.end]) {
                let at = func.start + at;
                let registered = MINTS
                    .iter()
                    .any(|m| m.file == rel && m.function == func.name && m.prefix == head);
                let reviewed = DISCOVERY_REVIEWED
                    .iter()
                    .any(|(f, n, _)| *f == rel && *n == func.name);
                if !registered && !reviewed {
                    violations.push(format!("{rel}:{}: `{}` builds a `{head}…` value and is neither registered nor reviewed", line_of(text, at), func.name));
                }
            }
        }
    }
    for (index, mint) in MINTS.iter().enumerate() {
        let Some((rel, text)) = files.iter().find(|(rel, _)| rel == mint.file) else {
            continue;
        };
        let code = blank_literals(text);
        let (funcs, _) = spans(&code);
        let Some(func) = funcs.iter().find(|f| f.name == mint.function) else {
            violations.push(format!(
                "{rel}: the registered minting function `{}` no longer exists",
                mint.function
            ));
            continue;
        };
        if mint.prefix.is_empty() {
            if !text[func.start..func.end].contains(mint.entropy) {
                violations.push(format!(
                    "{rel}: `{}` ({}) no longer shows {:?}",
                    mint.function, mint.note, mint.entropy
                ));
            }
        } else if counts[index] != mint.count {
            violations.push(format!(
                "{rel}: `{}` mints `{}…` {} time(s); the registry says {}",
                mint.function, mint.prefix, counts[index], mint.count
            ));
        }
    }
    violations
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
