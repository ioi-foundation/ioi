//! BUILD-DELTA #36 — a LINT that finds credential-minting sites in ordinary source shapes. It is not a proof, not a
//! closed guard, and it does not establish that any credential is random.
//!
//! WHAT IT DOES. In the non-test source of crates/node/src and crates/services/src, it finds string literals that start
//! with a registered credential prefix (`ioi_mnt_`, `ioi_pat_`, `ioi_lease_`, `wec_`, `wbt_`, `whk_`, `idisp_`, …) used to
//! build a value (`format!`, `+`, `.to_owned()`, `push_str`, `String::from`, `.join(`), and functions named like a credential
//! (token, secret, bearer, key, verifier, state, nonce, jwt) that build a `<prefix>_`-shaped value. Each must be a
//! registered (file, function, prefix, occurrence) or be reviewed by name; a registered function or file that disappears,
//! a second mint of a prefix, and a mint built from a hash slice or a clock fail. It reads every file as TOKENS, through
//! the tokenizer proc macros use (`proc_macro2`): comments are dropped and every literal (string, raw string, byte
//! string, C string, char, byte char) is one opaque token; functions, their bodies and `#[cfg(test)]` items are found in
//! the token tree, and every registered fragment is matched as a token sequence. The scanner section names the API
//! discovery can build on (a function-local `const` is visible in a function's token range).
//!
//! WHAT IT GUARANTEES: AN INVENTORY. Every mint site it knows is named (file, function, prefix, occurrence, or a
//! primitive's exact draw and building code), and removing or replacing a registered draw at its site is flagged: a
//! primitive entry and a prefixed mint's registered draw (`fed_by`) are matched as token sequences in the function
//! body's tokens, where no comment and no literal content can satisfy them, so a commented-out draw, or a copy of it in
//! any literal, is a removed draw. It does NOT prove that the draw executes or that its output reaches the credential: a
//! draw in a dead branch, a decoy copy beside a constant, and a buffer overwritten after the draw (`secret.fill(0)`) all
//! pass this lint BY DESIGN (`a_dead_branch_or_decoy_draw_is_a_documented_lint_limit` pins that). The EXECUTION
//! property is guarded BEHAVIOURALLY. NOW: the editor connection token, by preview_editor_lease_tokens.rs
//! `two_editor_runtime_starts_get_different_nonzero_tokens`. PLANNED (deferred, not yet in the tree): every site by
//! BUILD-DELTA #36d's 256-draw entropy tests (the editor host is #36d-e), and the type-level guard of BUILD-DELTA #42.
//! It is not evidence that a credential is random.
//!
//! KNOWN GAPS (covered by review now, and by the PLANNED behavioural entropy tests of BUILD-DELTA #36d and type-level
//! guard of BUILD-DELTA #42): a function-local `const` holding a registered prefix; a mint built by a helper in another file; a
//! prefix assembled by a macro (`concat!`, `stringify!`) or at run time; a credential whose prefix is not in the list;
//! a credential minted in a function whose name holds none of the keywords and no registered prefix; weak entropy at
//! run time. A pass means none of the accidental shapes above was found, and nothing more.

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

struct Mint {
    file: &'static str,
    function: &'static str,
    /// The literal prefix this function mints (`ioi_mnt_`), or "" for a primitive that mints without one.
    prefix: &'static str,
    /// Which occurrence of the prefix in the function this entry describes (0-based, in source order).
    nth: usize,
    /// For a prefix mint: text the mint's own statement must contain (the RNG/uuid call, or the variable the RNG filled).
    /// For a primitive: text the function body must contain.
    inline: &'static str,
    /// Text the function must contain BEFORE the statement, filling the variable `inline` names ("" when inline suffices).
    fed_by: &'static str,
    /// Statement fragments tolerated for this mint (a one-way id of the secret, never the secret).
    tolerates: &'static [&'static str],
    note: &'static str,
}

const DISCOVERY_NAMES: &[&str] = &[
    "token", "secret", "bearer", "key", "verifier", "state", "nonce", "jwt",
];

/// Concrete credential prefixes.
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
    Mint { file: "node/src/bin/hypervisor-daemon.rs", function: "async_main", prefix: "idisp_", nth: 0, inline: "uuid::Uuid::new_v4()", fed_by: "", tolerates: &[], note: "per-boot internal dispatch secret: two UUIDv4 (244 bits), process memory only" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/authority_routes.rs", function: "issue_bearer_capability_lease", prefix: "ioi_lease_", nth: 0, inline: "hex::encode(secret)", fed_by: "rand::rngs::OsRng.fill_bytes(&mut secret)", tolerates: &[], note: "env-ops capability lease bearer: 32 bytes from the OS RNG" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/editor_host.rs", function: "start_oss_runtime", prefix: "", nth: 0, inline: "rand::rngs::OsRng.fill_bytes(&mut secret);", fed_by: "", tolerates: &[], note: "editor runtime connection token (BUILD-DELTA #31(c)): its draw, 32 bytes from the OS RNG; no prefix and no credential keyword, so only this entry sees it" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/editor_host.rs", function: "start_oss_runtime", prefix: "", nth: 0, inline: "(hex::encode(secret), hex::encode(nonce))", fed_by: "", tolerates: &[], note: "editor runtime connection token: its building statement, the hex of that draw" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", function: "handle_api_token_create", prefix: "ioi_pat_", nth: 0, inline: "uuid::Uuid::new_v4()", fed_by: "", tolerates: &[], note: "API access tokens: two UUIDv4" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", function: "gen_opaque", prefix: "", nth: 0, inline: "uuid::Uuid::new_v4()", fed_by: "", tolerates: &[], note: "bootstrap, session, SCIM and invite tokens: two UUIDv4 behind one primitive" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", function: "random_token", prefix: "", nth: 0, inline: "rand::thread_rng()", fed_by: "", tolerates: &[], note: "OAuth state, nonce and PKCE verifier: the thread CSPRNG, seeded from the OS" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", function: "mint_github_app_jwt", prefix: "", nth: 0, inline: "jwt_encode(", fed_by: "", tolerates: &[], note: "GitHub App JWT: SIGNED with the App private key (RS256), not random; its secrecy is the key's" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/managed_runtime_routes.rs", function: "handle_backup_export", prefix: "", nth: 0, inline: "uuid::Uuid::new_v4()", fed_by: "", tolerates: &[], note: "managed backup export download token: UUIDv4 (122 bits), stored as a hash" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/orchestration_routes.rs", function: "new_webhook_token", prefix: "whk_", nth: 0, inline: "uuid::Uuid::new_v4()", fed_by: "", tolerates: &[], note: "automation webhook trigger token: two UUIDv4" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/orchestration_routes.rs", function: "handle_automation_webhook", prefix: "whk_", nth: 0, inline: "uuid::Uuid::new_v4()", fed_by: "", tolerates: &[], note: "webhook EVENT id (whk_evt_), not a credential: a UUIDv4" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/workload_effect_boundary.rs", function: "mint_guest_effect_capability", prefix: "wec_", nth: 0, inline: "hex::encode(random)", fed_by: "OsRng.fill_bytes(&mut random)", tolerates: &[], note: "workload effect capability token: 32 bytes from the OS RNG" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/workload_effect_boundary.rs", function: "mint_guest_effect_capability", prefix: "wec_", nth: 1, inline: "Sha256::digest(token.as_bytes())", fed_by: "", tolerates: &["[.."], note: "workload effect capability ID, not the credential: a one-way 32-hex prefix of the token's SHA-256" },
    Mint { file: "node/src/bin/hypervisor_daemon_routes/workload_effect_boundary.rs", function: "mint_guest_governed_provider_effect_capability", prefix: "wbt_", nth: 0, inline: "hex::encode(trigger_random)", fed_by: "OsRng.fill_bytes(&mut trigger_random)", tolerates: &[], note: "host trigger: 32 bytes from the OS RNG" },
    Mint { file: "services/src/agentic/runtime/kernel/model_mount/capability_token_control.rs", function: "plan_capability_token_control", prefix: "ioi_mnt_", nth: 0, inline: "hex_lower(&secret)", fed_by: "OsRng.fill_bytes(&mut secret)", tolerates: &[], note: "model-mount capability token: 32 bytes from the OS RNG, id drawn separately" },
    Mint { file: "services/src/agentic/runtime/connectors/google_auth.rs", function: "random_url_safe_token", prefix: "", nth: 0, inline: "rand::thread_rng()", fed_by: "", tolerates: &[], note: "Google OAuth state and PKCE verifier primitive: the thread CSPRNG" },
    Mint { file: "services/src/agentic/runtime/connectors/google_auth.rs", function: "login", prefix: "", nth: 0, inline: "random_url_safe_token(48)", fed_by: "", tolerates: &[], note: "Google OAuth state (24 bytes) and PKCE code_verifier (48 bytes) come from that primitive" },
    Mint { file: "services/src/agentic/runtime/connectors/google_auth.rs", function: "login", prefix: "", nth: 0, inline: "random_url_safe_token(24)", fed_by: "", tolerates: &[], note: "Google OAuth state: a 24-byte draw from that primitive" },
];

/// A function that builds a value carrying a registered credential prefix and is NOT a credential: a name keyed by
/// something public. Accepted only on an EXACT (file, function, prefix) match, only for one occurrence in that
/// function, and only when that occurrence's statement contains the reviewed `statement` fragment exactly (the same
/// prefix a real bearer mints, so any other way of building it there, an RNG draw included, is a violation); an entry
/// whose function no longer builds it is stale. The list is not a wildcard: the same shape anywhere else, or a second one in the same function, is still
/// a violation. These are not mints and are kept out of `MINTS`.
struct NonMint {
    file: &'static str,
    function: &'static str,
    prefix: &'static str,
    /// The exact statement fragment that builds the value; the matched statement must contain it verbatim.
    statement: &'static str,
    reason: &'static str,
}

const REVIEWED_NON_MINTS: &[NonMint] = &[
    NonMint { file: "node/src/bin/hypervisor_daemon_routes/editor_proxy.rs", function: "lease_cookie_name", prefix: "ioi_lease_", statement: "format!(\"ioi_lease_{public_port}\")", reason: "builds the cookie NAME; the cookie VALUE is the access token minted by issue_bearer_capability_lease" },
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
// The scanner. It reads each source file as TOKENS, through the tokenizer proc macros use
// (`proc_macro2::TokenStream::from_str`): comments are dropped and every literal (string, raw string, byte string, C
// string, char, byte char, number) is ONE opaque token, so no comment and no literal content can satisfy anything it
// matches. Its API, for discovery to build on: `file_tokens` (a file as a flat token sequence, each group opened and
// closed in place), `functions` (each function's name and the token range of its body, nested functions included;
// a function-local `const` is an ordinary statement inside that range), `test_items` (the `#[cfg(test)]` items),
// `string_content` (a string literal's contents), `pattern` (a code fragment as a token sequence) and
// `find_tokens` / `contains_tokens` (the token-sequence matcher). The tests feed it the real tree and planted
// counterexamples.
// ---------------------------------------------------------------------------------------------------------------

/// One token of a file. A group is flattened into its opening delimiter, its contents and its closing delimiter; a
/// literal keeps its exact source text (quotes, prefixes and hashes included) and is never looked inside, except by
/// `string_content`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Punct(char),
    Lit(String),
    Open(char),
    Close(char),
}

fn flatten(stream: proc_macro2::TokenStream, out: &mut Vec<Tok>) {
    for tree in stream {
        match tree {
            proc_macro2::TokenTree::Ident(ident) => out.push(Tok::Ident(ident.to_string())),
            proc_macro2::TokenTree::Punct(punct) => out.push(Tok::Punct(punct.as_char())),
            proc_macro2::TokenTree::Literal(literal) => out.push(Tok::Lit(literal.to_string())),
            proc_macro2::TokenTree::Group(group) => {
                let (open, close) = match group.delimiter() {
                    proc_macro2::Delimiter::Parenthesis => ('(', ')'),
                    proc_macro2::Delimiter::Brace => ('{', '}'),
                    proc_macro2::Delimiter::Bracket => ('[', ']'),
                    proc_macro2::Delimiter::None => ('\u{0}', '\u{0}'),
                };
                out.push(Tok::Open(open));
                flatten(group.stream(), out);
                out.push(Tok::Close(close));
            }
        }
    }
}

/// A file as a flat token sequence, or why it does not tokenize.
fn file_tokens(text: &str) -> Result<Vec<Tok>, String> {
    let stream = proc_macro2::TokenStream::from_str(text).map_err(|error| error.to_string())?;
    let mut out = Vec::new();
    flatten(stream, &mut out);
    Ok(out)
}

/// A code fragment as a token sequence. A fragment may leave delimiters open (`jwt_encode(`, `[..`): they are closed to
/// tokenize it and the closing tokens are dropped, so the pattern is a prefix of the code it names.
fn pattern(fragment: &str) -> Vec<Tok> {
    let mut unclosed = Vec::new();
    for c in fragment.chars() {
        match c {
            '(' => unclosed.push(')'),
            '[' => unclosed.push(']'),
            '{' => unclosed.push('}'),
            ')' | ']' | '}' => {
                unclosed.pop();
            }
            _ => {}
        }
    }
    let closers: String = unclosed.iter().rev().collect();
    let mut toks = file_tokens(&format!("{fragment}{closers}"))
        .unwrap_or_else(|error| panic!("the pattern {fragment:?} tokenizes: {error}"));
    toks.truncate(toks.len() - closers.chars().count());
    toks
}

/// Where `needle` first occurs in `haystack`, as a contiguous token sequence.
fn find_tokens(haystack: &[Tok], needle: &[Tok]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn contains_tokens(haystack: &[Tok], needle: &[Tok]) -> bool {
    find_tokens(haystack, needle).is_some()
}

/// One past the token that closes the group opened at `open`.
fn group_end(toks: &[Tok], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (k, tok) in toks.iter().enumerate().skip(open) {
        match tok {
            Tok::Open(_) => depth += 1,
            Tok::Close(_) => {
                depth -= 1;
                if depth == 0 {
                    return Some(k + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// The first brace group at this level from `from` (skipping other groups), or None when a `;` or the end of the
/// enclosing group comes first.
fn next_brace_group(toks: &[Tok], from: usize) -> Option<(usize, usize)> {
    let mut depth = 0usize;
    for (k, tok) in toks.iter().enumerate().skip(from) {
        match tok {
            Tok::Open('{') if depth == 0 => return group_end(toks, k).map(|end| (k, end)),
            Tok::Open(_) => depth += 1,
            Tok::Close(_) => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
            }
            Tok::Punct(';') if depth == 0 => return None,
            _ => {}
        }
    }
    None
}

/// A function with a body: its name and the token range of its body (the brace group after `fn <name>`, braces
/// included).
#[derive(Clone)]
struct Func {
    name: String,
    start: usize,
    end: usize,
}

/// Every function with a body, nested ones included, in token order.
fn functions(toks: &[Tok]) -> Vec<Func> {
    let mut out = Vec::new();
    for at in 0..toks.len() {
        let (Tok::Ident(keyword), Some(Tok::Ident(name))) = (&toks[at], toks.get(at + 1)) else {
            continue;
        };
        if keyword != "fn" {
            continue;
        }
        if let Some((start, end)) = next_brace_group(toks, at + 2) {
            out.push(Func {
                name: name.trim_start_matches("r#").to_string(),
                start,
                end,
            });
        }
    }
    out
}

/// The token ranges of `#[cfg(test)]` items: from the attribute through the item's brace group.
fn test_items(toks: &[Tok]) -> Vec<(usize, usize)> {
    let attribute = pattern("#[cfg(test)]");
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = find_tokens(&toks[from..], &attribute) {
        let at = from + rel;
        from = at + attribute.len();
        if let Some((_, end)) = next_brace_group(toks, from) {
            out.push((at, end));
        }
    }
    out
}

fn enclosing(funcs: &[Func], at: usize) -> Option<&Func> {
    funcs
        .iter()
        .filter(|f| f.start <= at && at < f.end)
        .min_by_key(|f| f.end - f.start)
}

/// A string literal's contents (`"…"`, `r"…"`, `r#"…"#`, and the byte and C forms of each), or None for any other
/// literal.
fn string_content(lit: &str) -> Option<&str> {
    let rest = ["br", "cr", "b", "c", "r", ""].iter().find_map(|prefix| {
        lit.strip_prefix(prefix).filter(|rest| {
            rest.starts_with('"') || (prefix.ends_with('r') && rest.starts_with('#'))
        })
    })?;
    let hashes = rest.chars().take_while(|c| *c == '#').count();
    let body = &rest[hashes..];
    let close = format!("\"{}", "#".repeat(hashes));
    (body.len() >= 1 + close.len() && body.starts_with('"') && body.ends_with(&close))
        .then(|| &body[1..body.len() - close.len()])
}

/// The statement holding the token at `at` inside `range`: from after the previous `;`, `{`, `}` or `,` to the end of
/// the call holding it (its innermost unclosed `(`), else to the next `;`.
fn statement_around(toks: &[Tok], at: usize, range: (usize, usize)) -> (usize, usize) {
    let mut start = range.0;
    for k in (range.0..at).rev() {
        if matches!(
            toks[k],
            Tok::Punct(';') | Tok::Open('{') | Tok::Close('}') | Tok::Punct(',')
        ) {
            start = k + 1;
            break;
        }
    }
    let mut depth = 0usize;
    let mut open = None;
    for k in (start..at).rev() {
        match toks[k] {
            Tok::Close(')') => depth += 1,
            Tok::Open('(') => {
                if depth == 0 {
                    open = Some(k);
                    break;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    if let Some(end) = open.and_then(|open| group_end(toks, open)) {
        if end <= range.1 {
            return (start, end);
        }
    }
    let end = (at..range.1)
        .find(|&k| toks[k] == Tok::Punct(';'))
        .unwrap_or(range.1);
    (start, end)
}

struct Candidate {
    prefix: &'static str,
    func: Option<Func>,
    statement: (usize, usize),
}

fn patterns(fragments: &[&str]) -> Vec<Vec<Tok>> {
    fragments.iter().map(|fragment| pattern(fragment)).collect()
}

fn is_building(statement: &[Tok]) -> bool {
    static BUILDING: std::sync::OnceLock<Vec<Vec<Tok>>> = std::sync::OnceLock::new();
    BUILDING
        .get_or_init(|| {
            patterns(&[
                "+",
                "push_str",
                "to_owned",
                "String::from",
                "format!",
                "concat!",
                ".join(",
                ".to_string()",
                ".into()",
            ])
        })
        .iter()
        .any(|p| contains_tokens(statement, p))
}

fn is_comparing(statement: &[Tok]) -> bool {
    static COMPARING: std::sync::OnceLock<Vec<Vec<Tok>>> = std::sync::OnceLock::new();
    COMPARING
        .get_or_init(|| {
            patterns(&[
                "starts_with",
                "strip_prefix",
                "matches!",
                "==",
                "!=",
                ".eq(",
                "ends_with",
                ".contains(",
            ])
        })
        .iter()
        .any(|p| contains_tokens(statement, p))
}

/// Every string literal that starts with a registered prefix and is used to BUILD a value (not to compare against one).
fn candidates(toks: &[Tok], funcs: &[Func], tests: &[(usize, usize)]) -> Vec<Candidate> {
    let mut out = Vec::new();
    for (at, tok) in toks.iter().enumerate() {
        let Tok::Lit(lit) = tok else {
            continue;
        };
        let Some(content) = string_content(lit) else {
            continue;
        };
        let Some(prefix) = PREFIXES.iter().find(|p| content.starts_with(**p)) else {
            continue;
        };
        if tests.iter().any(|(a, b)| *a <= at && at < *b) {
            continue;
        }
        let func = enclosing(funcs, at).cloned();
        let range = func.as_ref().map_or((0, toks.len()), |f| (f.start, f.end));
        let statement = statement_around(toks, at, range);
        let stmt = &toks[statement.0..statement.1];
        let building = content.contains('{') || is_building(stmt);
        let comparing = is_comparing(stmt);
        if func.is_some() && (!building || (comparing && !content.contains('{'))) {
            continue;
        }
        out.push(Candidate {
            prefix,
            func,
            statement,
        });
    }
    out
}

/// String literals shaped like `<word>_` or `<word>_{..}` inside a function, used to BUILD a value: prefixes this lint
/// was not told about.
fn shaped_prefixes(toks: &[Tok], func: &Func) -> Vec<String> {
    let mut out = Vec::new();
    for at in func.start..func.end {
        let Tok::Lit(lit) = &toks[at] else {
            continue;
        };
        let Some(content) = string_content(lit) else {
            continue;
        };
        let head: String = content
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        if !(head.len() >= 3
            && head.len() <= 20
            && head.ends_with('_')
            && (content.len() == head.len() || content[head.len()..].starts_with('{')))
        {
            continue;
        }
        if !content.contains('{') {
            let (a, z) = statement_around(toks, at, (func.start, func.end));
            let stmt = &toks[a..z];
            if !is_building(stmt) || is_comparing(stmt) {
                continue;
            }
        }
        out.push(head);
    }
    out
}

/// Scan the given files. One line per violation; empty means no accidental shape inside this lint's scope.
fn scan(files: &[(String, String)]) -> Vec<String> {
    let forbidden_fragments = [
        "[..",
        "hash_json(",
        "create_hash",
        "as_millis",
        "as_secs",
        "as_nanos",
        "SystemTime",
        "Instant::now",
    ];
    let forbidden: Vec<(&str, Vec<Tok>)> = forbidden_fragments
        .iter()
        .map(|fragment| (*fragment, pattern(fragment)))
        .collect();
    let mut violations = Vec::new();
    let mut found: Vec<(String, String, String, usize)> = Vec::new(); // (file, function, prefix, occurrences)
    let mut non_mints_built: Vec<(String, String)> = Vec::new(); // (file, function) of reviewed non-mints seen
    let mut tokenized: Vec<(String, Vec<Tok>, Vec<Func>)> = Vec::new();
    for (rel, text) in files {
        let toks = match file_tokens(text) {
            Ok(toks) => toks,
            Err(error) => {
                violations.push(format!(
                    "{rel}: the file does not tokenize ({error}); the sweep cannot read it"
                ));
                continue;
            }
        };
        let funcs = functions(&toks);
        let tests = test_items(&toks);
        // 1. every mint candidate against the registry, by (file, function, prefix, nth)
        let mut seen: Vec<(String, String, usize)> = Vec::new();
        for cand in candidates(&toks, &funcs, &tests) {
            let Some(func) = cand.func.clone() else {
                violations.push(format!("{rel}: `{}…` is held outside any function (a const or static): register the mint that uses it", cand.prefix));
                continue;
            };
            let nth = seen
                .iter()
                .filter(|(f, p, _)| *f == func.name && p == cand.prefix)
                .count();
            seen.push((func.name.clone(), cand.prefix.to_string(), nth));
            let statement = &toks[cand.statement.0..cand.statement.1];
            if let Some(non_mint) = REVIEWED_NON_MINTS
                .iter()
                .find(|n| n.file == rel && n.function == func.name && n.prefix == cand.prefix)
            {
                if nth > 0 {
                    violations.push(format!("{rel}: `{}` builds `{}…` more than once; only one reviewed non-mint is accepted there", func.name, cand.prefix));
                } else if !contains_tokens(statement, &pattern(non_mint.statement)) {
                    violations.push(format!(
                        "{rel}: `{}` builds `{}…` other than by its reviewed statement {:?}",
                        func.name, cand.prefix, non_mint.statement
                    ));
                } else {
                    non_mints_built.push((rel.clone(), func.name.clone()));
                }
                continue;
            }
            let Some(mint) = MINTS.iter().find(|m| {
                m.file == rel && m.function == func.name && m.prefix == cand.prefix && m.nth == nth
            }) else {
                let known = MINTS
                    .iter()
                    .any(|m| m.file == rel && m.function == func.name && m.prefix == cand.prefix);
                violations.push(if known {
                    format!(
                        "{rel}: `{}` mints `{}…` more times than the registry says (occurrence {})",
                        func.name,
                        cand.prefix,
                        nth + 1
                    )
                } else {
                    format!(
                        "{rel}: `{}…` is minted in `{}`, which is not a registered minting site",
                        cand.prefix, func.name
                    )
                });
                continue;
            };
            if !contains_tokens(statement, &pattern(mint.inline)) {
                violations.push(format!(
                    "{rel}: the `{}…` mint in `{}` is not formed from its registered source {:?}",
                    cand.prefix, func.name, mint.inline
                ));
            }
            if !mint.fed_by.is_empty() {
                let before = &toks[func.start..cand.statement.0.max(func.start)];
                if !contains_tokens(before, &pattern(mint.fed_by)) {
                    violations.push(format!(
                        "{rel}: the `{}…` mint in `{}` is not preceded by its registered draw {:?}",
                        cand.prefix, func.name, mint.fed_by
                    ));
                }
            }
            for (fragment, tokens) in &forbidden {
                if contains_tokens(statement, tokens) && !mint.tolerates.contains(fragment) {
                    violations.push(format!(
                        "{rel}: the `{}…` mint in `{}` is built from a derivation ({fragment:?})",
                        cand.prefix, func.name
                    ));
                }
            }
        }
        for (name, prefix, _) in &seen {
            if let Some(entry) = found
                .iter_mut()
                .find(|(f, n, p, _)| f == rel && n == name && p == prefix)
            {
                entry.3 += 1;
            } else {
                found.push((rel.clone(), name.clone(), prefix.clone(), 1));
            }
        }
        // 2. discovery: a credential-named function that builds a prefix-shaped value is registered or reviewed by name
        for func in &funcs {
            let lower = func.name.to_lowercase();
            if !DISCOVERY_NAMES.iter().any(|w| lower.contains(w))
                || tests
                    .iter()
                    .any(|(a, b)| *a <= func.start && func.start < *b)
            {
                continue;
            }
            for head in shaped_prefixes(&toks, func) {
                let registered = MINTS
                    .iter()
                    .any(|m| m.file == rel && m.function == func.name && m.prefix == head);
                let reviewed = DISCOVERY_REVIEWED
                    .iter()
                    .any(|(f, n, _)| *f == rel && *n == func.name);
                if !registered && !reviewed {
                    violations.push(format!(
                        "{rel}: `{}` builds a `{head}…` value and is neither registered nor reviewed",
                        func.name
                    ));
                }
            }
        }
        tokenized.push((rel.clone(), toks, funcs));
    }
    // 3. the registry against the tree: every registered file and function exists, every registered mint is found,
    // and every reviewed non-mint is still built where it was reviewed
    for non_mint in REVIEWED_NON_MINTS {
        if !files.iter().any(|(rel, _)| rel == non_mint.file) {
            violations.push(format!(
                "{}: the reviewed non-mint `{}`'s file is missing from the tree: remove it",
                non_mint.file, non_mint.function
            ));
        } else if !non_mints_built
            .iter()
            .any(|(f, n)| f == non_mint.file && n == non_mint.function)
        {
            violations.push(format!(
                "{}: the reviewed non-mint `{}` no longer builds `{}…` by {:?} ({}): remove it",
                non_mint.file,
                non_mint.function,
                non_mint.prefix,
                non_mint.statement,
                non_mint.reason
            ));
        }
    }
    let mut missing_files: Vec<&str> = Vec::new();
    for mint in MINTS {
        if !files.iter().any(|(rel, _)| rel == mint.file) {
            if !missing_files.contains(&mint.file) {
                missing_files.push(mint.file);
                violations.push(format!(
                    "{}: the registered file is missing from the tree",
                    mint.file
                ));
            }
            continue;
        }
        let Some((rel, toks, funcs)) = tokenized.iter().find(|(rel, _, _)| rel == mint.file) else {
            violations.push(format!(
                "{}: the registered minting function `{}` cannot be read: its file does not tokenize",
                mint.file, mint.function
            ));
            continue;
        };
        let Some(func) = funcs.iter().find(|f| f.name == mint.function) else {
            violations.push(format!(
                "{rel}: the registered minting function `{}` no longer exists",
                mint.function
            ));
            continue;
        };
        if mint.prefix.is_empty() {
            // The function body's tokens: a primitive's draw in a comment or inside any literal is not a draw.
            if !contains_tokens(&toks[func.start..func.end], &pattern(mint.inline)) {
                violations.push(format!(
                    "{rel}: `{}` ({}) no longer shows {:?}",
                    mint.function, mint.note, mint.inline
                ));
            }
        } else {
            let count = found
                .iter()
                .find(|(f, n, p, _)| f == rel && n == mint.function && p == mint.prefix)
                .map_or(0, |e| e.3);
            if count <= mint.nth {
                violations.push(format!(
                    "{rel}: `{}` no longer mints `{}…` (occurrence {} registered, {} found)",
                    mint.function,
                    mint.prefix,
                    mint.nth + 1,
                    count
                ));
            }
        }
    }
    violations.sort();
    violations.dedup();
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

const PROXY: &str = "node/src/bin/hypervisor_daemon_routes/editor_proxy.rs";
const EDITOR_HOST: &str = "node/src/bin/hypervisor_daemon_routes/editor_host.rs";

/// The editor runtime's connection token (BUILD-DELTA #31(c)) carries no prefix and its function no credential
/// keyword, so only the registry can see it: its 32-byte OS-random draw replaced by a constant, or its building
/// statement replaced by a constant, is a violation at that site.
#[test]
fn an_editor_connection_token_built_from_a_constant_fails_the_sweep() {
    let drawn_constant = tree_with(EDITOR_HOST, |text| {
        let planted = text.replacen(
            "        rand::rngs::OsRng.fill_bytes(&mut secret);\n",
            "        secret = [0u8; 32];\n",
            1,
        );
        assert_ne!(planted, text, "the planted draw edit applies");
        planted
    });
    let violations = scan(&drawn_constant);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("editor_host.rs") && v.contains("start_oss_runtime")),
        "the draw replaced by a constant is caught at its site: {violations:?}"
    );
    let built_constant = tree_with(EDITOR_HOST, |text| {
        let planted = text.replacen(
            "        (hex::encode(secret), hex::encode(nonce))\n",
            "        (\"0\".repeat(64), hex::encode(nonce))\n",
            1,
        );
        assert_ne!(planted, text, "the planted building edit applies");
        planted
    });
    let violations = scan(&built_constant);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("editor_host.rs") && v.contains("start_oss_runtime")),
        "the token built from a constant is caught at its site: {violations:?}"
    );
}

/// A registered draw commented out is a removed draw: the editor connection token's primitive draw, and the draw a
/// prefixed mint is registered as fed by (`issue_bearer_capability_lease`), each turned into a comment, is a violation
/// at its site.
#[test]
fn a_commented_out_draw_fails_the_sweep_at_its_site() {
    let editor = tree_with(EDITOR_HOST, |text| {
        let planted = text.replacen(
            "        rand::rngs::OsRng.fill_bytes(&mut secret);\n",
            "        // rand::rngs::OsRng.fill_bytes(&mut secret);\n",
            1,
        );
        assert_ne!(planted, text, "the planted comment applies");
        planted
    });
    let violations = scan(&editor);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("editor_host.rs") && v.contains("start_oss_runtime")),
        "a commented-out primitive draw is caught at its site: {violations:?}"
    );
    let lease = tree_with(AUTH, |text| {
        let planted = text.replacen(
            "rand::rngs::OsRng.fill_bytes(&mut secret)",
            "// rand::rngs::OsRng.fill_bytes(&mut secret)\n",
            1,
        );
        assert_ne!(planted, text, "the planted comment applies");
        planted
    });
    let violations = scan(&lease);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("issue_bearer_capability_lease") && v.contains("registered draw")),
        "a commented-out registered draw of a prefixed mint is caught at its site: {violations:?}"
    );
}

/// No literal and no raw-identifier decoy can satisfy a registered draw: the editor connection token's draw, and the lease
/// mint's registered draw (`issue_bearer_capability_lease`), each replaced by a copy of its text inside a raw C string
/// (`cr#"…"#`), and the editor draw replaced by a copy inside a C string, a byte string, a raw byte string, a string
/// between a byte char and a char, or by a raw identifier named like the draw (`r#fill_bytes`) that is not called, is a
/// violation at its site.
#[test]
fn a_registered_draw_inside_a_literal_or_a_raw_identifier_decoy_fails_the_sweep() {
    let draw = "        rand::rngs::OsRng.fill_bytes(&mut secret);\n";
    let editor_cases = [
        (
            "a raw C string",
            "        let _ = cr#\"\" rand::rngs::OsRng.fill_bytes(&mut secret); \"\"#;\n",
        ),
        (
            "a C string",
            "        let _ = c\" rand::rngs::OsRng.fill_bytes(&mut secret); \";\n",
        ),
        (
            "a byte string",
            "        let _ = b\" rand::rngs::OsRng.fill_bytes(&mut secret); \";\n",
        ),
        (
            "a raw byte string",
            "        let _ = br#\" rand::rngs::OsRng.fill_bytes(&mut secret); \"#;\n",
        ),
        (
            "a string between a byte char and a char",
            "        let _ = (b'\"', \" rand::rngs::OsRng.fill_bytes(&mut secret); \", '\"');\n",
        ),
        (
            "a raw identifier named like the draw, not called",
            "        let r#fill_bytes = (rand::rngs::OsRng, &mut secret);\n",
        ),
    ];
    let mut accepted = Vec::new();
    for (shape, replacement) in editor_cases {
        let tree = tree_with(EDITOR_HOST, |text| {
            let planted = text.replacen(draw, replacement, 1);
            assert_ne!(planted, text, "the planted {shape} applies");
            planted
        });
        let violations = scan(&tree);
        if !violations
            .iter()
            .any(|v| v.contains("editor_host.rs") && v.contains("start_oss_runtime"))
        {
            accepted.push(format!("editor draw in {shape}"));
        }
    }
    let lease = tree_with(AUTH, |text| {
        let planted = text.replacen(
            "    rand::rngs::OsRng.fill_bytes(&mut secret);\n",
            "    let _ = cr#\"\" rand::rngs::OsRng.fill_bytes(&mut secret) \"\"#;\n",
            1,
        );
        assert_ne!(planted, text, "the planted raw C string applies");
        planted
    });
    let violations = scan(&lease);
    if !violations
        .iter()
        .any(|v| v.contains("issue_bearer_capability_lease") && v.contains("registered draw"))
    {
        accepted.push("lease draw in a raw C string".to_string());
    }
    assert!(
        accepted.is_empty(),
        "each copy of a registered draw that is not the draw is a violation at its site; accepted: {accepted:?}"
    );
}

/// DOCUMENTED LIMITS, pinned so no pass is read as more than an inventory: a registered draw kept in a dead branch, or a
/// decoy copy of it in a closure that never runs, passes this lint. The EXECUTION property is guarded behaviourally:
/// NOW for the editor connection token, by preview_editor_lease_tokens.rs
/// two_editor_runtime_starts_get_different_nonzero_tokens (two starts give two different non-zero tokens); PLANNED
/// (deferred) for every site, by BUILD-DELTA #36d's 256-draw entropy tests (the editor host is #36d-e), and at the type
/// level by BUILD-DELTA #42.
#[test]
fn a_dead_branch_or_decoy_draw_is_a_documented_lint_limit() {
    for (shape, replacement) in [
        (
            "a dead branch",
            "        if false {\n            rand::rngs::OsRng.fill_bytes(&mut secret);\n        }\n",
        ),
        (
            "a decoy closure that never runs",
            "        let _decoy = || rand::rngs::OsRng.fill_bytes(&mut secret);\n",
        ),
    ] {
        let tree = tree_with(EDITOR_HOST, |text| {
            let planted = text.replacen(
                "        rand::rngs::OsRng.fill_bytes(&mut secret);\n",
                replacement,
                1,
            );
            assert_ne!(planted, text, "the planted {shape} applies");
            planted
        });
        let violations = scan(&tree);
        assert!(
            !violations.iter().any(|v| v.contains("editor_host.rs")),
            "{shape} passes the lint by design (a documented limit; the behavioural guards catch it): {violations:?}"
        );
    }
}

/// A reviewed non-mint whose file is missing from the tree is a violation, as a registered mint's missing file is:
/// its exemption never goes stale silently.
#[test]
fn a_reviewed_non_mint_whose_file_is_missing_fails_the_sweep() {
    let tree: Vec<(String, String)> = real_tree()
        .into_iter()
        .filter(|(rel, _)| rel != PROXY)
        .collect();
    let violations = scan(&tree);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("editor_proxy.rs") && v.contains("missing")),
        "a missing reviewed non-mint file is caught: {violations:?}"
    );
}

/// A reviewed non-mint is accepted only where and as it was reviewed: the same `ioi_lease_` cookie-name shape in
/// another function, a second one inside the reviewed function, and an RNG-built `ioi_lease_` value in place of the
/// reviewed statement inside the reviewed function are each still a violation.
#[test]
fn a_reviewed_non_mint_is_accepted_only_on_its_exact_site() {
    let elsewhere = tree_with(PROXY, |text| {
        format!("{text}\npub(crate) fn another_cookie_name(public_port: u16) -> String {{\n    format!(\"ioi_lease_{{public_port}}\")\n}}\n")
    });
    let violations = scan(&elsewhere);
    assert!(
        violations.iter().any(|v| v.contains("another_cookie_name")),
        "the same shape in another function is caught: {violations:?}"
    );
    let twice = tree_with(PROXY, |text| {
        text.replacen(
            "    format!(\"ioi_lease_{public_port}\")\n",
            "    let _again = format!(\"ioi_lease_{public_port}\");\n    format!(\"ioi_lease_{public_port}\")\n",
            1,
        )
    });
    let violations = scan(&twice);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("lease_cookie_name") && v.contains("more than once")),
        "a second occurrence in the reviewed function is caught: {violations:?}"
    );
    let minted_there = tree_with(PROXY, |text| {
        text.replacen(
            "    format!(\"ioi_lease_{public_port}\")\n",
            "    let mut secret = [0u8; 32];\n    rand::rngs::OsRng.fill_bytes(&mut secret);\n    format!(\"ioi_lease_{}\", hex::encode(secret))\n",
            1,
        )
    });
    let violations = scan(&minted_there);
    assert!(
        violations.iter().any(|v| v.contains("lease_cookie_name")
            && v.contains("other than by its reviewed statement")),
        "an RNG-built bearer in place of the reviewed statement is caught: {violations:?}"
    );
}

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

// ---- plants for the shapes the scan was extended to cover (each must fail the scan) ---------------------------

const GOOGLE: &str = "services/src/agentic/runtime/connectors/google_auth.rs";
const LIFECYCLE: &str = "node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs";

#[test]
fn a_prefix_joined_by_to_owned_and_plus_fails_the_sweep() {
    let tree = tree_with(AUTH, |text| {
        format!("{text}\nfn make_value(tail: &str) -> String {{\n    \"ioi_pat_\".to_owned() + tail\n}}\n")
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("make_value")),
        "{violations:?}"
    );
}

#[test]
fn a_prefix_built_with_push_str_fails_the_sweep() {
    let tree = tree_with(AUTH, |text| {
        format!("{text}\nfn make_value(tail: &str) -> String {{\n    let mut out = String::new();\n    out.push_str(\"whk_\");\n    out.push_str(tail);\n    out\n}}\n")
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("make_value")),
        "{violations:?}"
    );
}

#[test]
fn a_prefix_held_in_a_const_and_used_in_format_fails_the_sweep() {
    let tree = tree_with(AUTH, |text| {
        format!("{text}\nconst MINT_PREFIX: &str = \"wec_\";\nfn make_value(n: u64) -> String {{\n    format!(\"{{MINT_PREFIX}}{{n}}\")\n}}\n")
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("wec_")),
        "{violations:?}"
    );
}

#[test]
fn a_registered_mint_fed_by_something_other_than_the_registered_source_fails_the_sweep() {
    // the function still holds the registered OsRng draw elsewhere, but the formatted value no longer comes from it
    let tree = tree_with(KERNEL, |text| {
        text.replacen(
            "let minted = format!(\"ioi_mnt_{}\", hex_lower(&secret));",
            "let minted = format!(\"ioi_mnt_{}\", hex_lower(&id_material));",
            1,
        )
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("ioi_mnt_")),
        "{violations:?}"
    );
}

#[test]
fn a_nested_block_comment_cannot_hide_a_following_credential_function() {
    let tree = tree_with(AUTH, |text| {
        format!("{text}\n/* outer /* inner */ \" still a comment */\nfn leak_secret_token() -> String {{\n    format!(\"zzk_{{}}\", 1)\n}}\n")
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("leak_secret_token")),
        "{violations:?}"
    );
}

#[test]
fn a_raw_byte_string_cannot_hide_a_following_credential_function() {
    let tree = tree_with(AUTH, |text| {
        format!("{text}\nconst RAW: &[u8] = br#\"}} \" fn \"#;\nfn leak_secret_token() -> String {{\n    format!(\"zzk_{{}}\", 2)\n}}\n")
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("leak_secret_token")),
        "{violations:?}"
    );
}

#[test]
fn a_quote_character_literal_cannot_hide_a_following_credential_function() {
    let tree = tree_with(AUTH, |text| {
        format!("{text}\nfn quote() -> char {{\n    '\"'\n}}\nfn leak_secret_token() -> String {{\n    format!(\"zzk_{{}}\", 3)\n}}\n")
    });
    let violations = scan(&tree);
    assert!(
        violations.iter().any(|v| v.contains("leak_secret_token")),
        "{violations:?}"
    );
}

#[test]
fn a_registered_file_that_is_missing_fails_the_sweep() {
    let mut tree = real_tree();
    tree.retain(|(rel, _)| rel != ORCH);
    let violations = scan(&tree);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("orchestration_routes.rs") && v.contains("missing")),
        "{violations:?}"
    );
}

#[test]
fn a_google_state_that_is_no_longer_drawn_at_random_fails_the_sweep() {
    let tree = tree_with(GOOGLE, |text| {
        text.replacen(
            "let state = random_url_safe_token(24);",
            "let state = String::from(\"fixed-state\");",
            1,
        )
    });
    let violations = scan(&tree);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("random_url_safe_token(24)")),
        "{violations:?}"
    );
}

#[test]
fn a_prefix_assembled_from_pieces_is_a_named_out_of_scope_shape_not_a_pass() {
    // A prefix split across macro pieces is OUTSIDE this lint's scope (the header names it; review and BUILD-DELTA #42
    // cover it). This test pins that the lint does not claim to catch it, so nobody reads a pass as more than it is.
    let tree = tree_with(LIFECYCLE, |text| {
        format!("{text}\nfn make_value() -> String {{\n    concat!(\"ioi_p\", \"at_\", \"x\").to_string()\n}}\n")
    });
    assert!(scan(&tree).is_empty());
}
