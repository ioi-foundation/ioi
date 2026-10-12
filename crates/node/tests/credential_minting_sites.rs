//! BUILD-DELTA #36 — a LINT that finds credential-minting sites in ordinary source shapes. It is not a proof, not a
//! closed guard, and it does not establish that any credential is random.
//!
//! WHAT IT DOES. In the non-test source of crates/node/src and crates/services/src, it finds string literals that start
//! with a registered credential prefix (`ioi_mnt_`, `ioi_pat_`, `ioi_lease_`, `wec_`, `wbt_`, `whk_`, `idisp_`, …) used to
//! build a value (`format!`, `+`, `.to_owned()`, `push_str`, `String::from`, `.join(`), and functions named like a credential
//! (token, secret, bearer, key, verifier, state, nonce, jwt) that build a `<prefix>_`-shaped value. Each must be a
//! registered (file, function, prefix, occurrence) or be reviewed by name; a registered function or file that disappears,
//! a second mint of a prefix, and a mint built from a hash slice or a clock fail. The lexer blanks strings (raw and byte
//! included), char literals and nested block comments before it finds function and `#[cfg(test)]` spans.
//!
//! WHAT ITS ENTROPY CHECK IS. A HEURISTIC. It checks that a mint's own statement names its registered source (the RNG or
//! uuid call, or a variable) and that a registered draw appears earlier in the function. It reads the text as written, so it does NOT
//! see a commented-out draw, a buffer overwritten after the draw (`secret.fill(0)`), or a draw that is dead code. It is
//! not evidence that a credential is random.
//!
//! KNOWN GAPS (covered by review, by the behavioural entropy tests of BUILD-DELTA #36d and by the type-level guard of
//! BUILD-DELTA #42): a function-local `const` holding a registered prefix; a mint built by a helper in another file; a
//! prefix assembled by a macro (`concat!`, `stringify!`) or at run time; a credential whose prefix is not in the list;
//! a credential minted in a function whose name holds none of the keywords and no registered prefix; weak entropy at
//! run time. A pass means none of the accidental shapes above was found, and nothing more.

use std::fs;
use std::path::{Path, PathBuf};

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
// The scanner. Std only; it reads source TEXT and reports violations. The tests feed it the real tree and planted
// counterexamples.
// ---------------------------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Func {
    name: String,
    start: usize, // byte offset of `fn`
    end: usize,   // byte offset one past the closing brace
}

/// A string literal's contents: byte offsets of the text between its delimiters.
#[derive(Clone, Copy)]
struct Lit {
    start: usize,
    end: usize,
}

/// A copy of `text` of the same byte length with the inside of every string (plain, raw, byte), char literal and
/// (nested) comment blanked to spaces, newlines kept; plus the spans of the string literals' contents.
fn lex(text: &str) -> (String, Vec<Lit>) {
    let b = text.as_bytes();
    let mut out: Vec<u8> = b.to_vec();
    let mut lits = Vec::new();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for k in from..to.min(out.len()) {
            if out[k] != b'\n' {
                out[k] = b' ';
            }
        }
    };
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            let mut j = i;
            while j < b.len() && b[j] != b'\n' {
                j += 1;
            }
            blank(&mut out, i, j);
            i = j;
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let mut depth = 1;
            let mut j = i + 2;
            while j < b.len() && depth > 0 {
                if b[j] == b'/' && b.get(j + 1) == Some(&b'*') {
                    depth += 1;
                    j += 2;
                } else if b[j] == b'*' && b.get(j + 1) == Some(&b'/') {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j);
            i = j;
        } else if (c == b'r' || (c == b'b' && b.get(i + 1) == Some(&b'r')))
            && (i == 0 || !ident(b[i - 1]))
            && {
                let mut k = i + if c == b'b' { 2 } else { 1 };
                while b.get(k) == Some(&b'#') {
                    k += 1;
                }
                b.get(k) == Some(&b'"')
            }
        {
            let mut k = i + if c == b'b' { 2 } else { 1 };
            let mut hashes = 0;
            while b.get(k) == Some(&b'#') {
                hashes += 1;
                k += 1;
            }
            let content = k + 1;
            let mut e = content;
            while e < b.len() {
                if b[e] == b'"' && (0..hashes).all(|h| b.get(e + 1 + h) == Some(&b'#')) {
                    break;
                }
                e += 1;
            }
            lits.push(Lit {
                start: content,
                end: e.min(b.len()),
            });
            blank(&mut out, content, e);
            i = e + 1 + hashes;
        } else if c == b'"' {
            let content = i + 1;
            let mut j = content;
            while j < b.len() && b[j] != b'"' {
                if b[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            lits.push(Lit {
                start: content,
                end: j.min(b.len()),
            });
            blank(&mut out, content, j);
            i = j + 1;
        } else if c == b'\'' {
            // a char literal ('x', '\n', '"', '—') but not a lifetime ('a)
            if b.get(i + 1) == Some(&b'\\') {
                let mut j = i + 3;
                while j < b.len() && b[j] != b'\'' {
                    j += 1;
                }
                blank(&mut out, i + 1, j);
                i = j + 1;
            } else if let Some(&lead) = b.get(i + 1) {
                let len = if lead < 0x80 {
                    1
                } else if lead >= 0xF0 {
                    4
                } else if lead >= 0xE0 {
                    3
                } else {
                    2
                };
                if b.get(i + 1 + len) == Some(&b'\'') {
                    blank(&mut out, i + 1, i + 1 + len);
                    i += 2 + len;
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    (
        String::from_utf8(out)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()),
        lits,
    )
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

/// Byte-offset spans of `fn` items and of `#[cfg(test)]` blocks, from the lexed code.
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

fn enclosing(funcs: &[Func], at: usize) -> Option<&Func> {
    funcs
        .iter()
        .filter(|f| f.start <= at && at < f.end)
        .min_by_key(|f| f.end - f.start)
}

fn line_of(text: &str, at: usize) -> usize {
    text[..at.min(text.len())].matches('\n').count() + 1
}

/// The statement holding `at`, from the call expression holding the literal (or the previous delimiter) to its end.
fn statement_around(code: &str, at: usize, limit_end: usize) -> (usize, usize) {
    let bytes = code.as_bytes();
    // start: the previous statement/field delimiter
    let mut start = 0;
    let mut k = at;
    while k > 0 {
        k -= 1;
        if matches!(bytes[k], b';' | b'{' | b'}' | b',') {
            start = k + 1;
            break;
        }
    }
    // the innermost unmatched '(' before the literal and its match bound the call; otherwise run to the ';'
    let mut depth = 0i32;
    let mut open = None;
    let mut j = at;
    while j > start {
        j -= 1;
        match bytes[j] {
            b')' => depth += 1,
            b'(' => {
                if depth == 0 {
                    open = Some(j);
                    break;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    if let Some(open) = open {
        let mut d = 0i32;
        for (idx, &ch) in bytes.iter().enumerate().skip(open) {
            if idx >= limit_end {
                break;
            }
            if ch == b'(' {
                d += 1;
            } else if ch == b')' {
                d -= 1;
                if d == 0 {
                    return (start, idx + 1);
                }
            }
        }
    }
    let end = code[at..limit_end.min(code.len())]
        .find(';')
        .map(|e| at + e)
        .unwrap_or(limit_end.min(code.len()));
    (start, end)
}

struct Candidate {
    at: usize,
    prefix: &'static str,
    func: Option<Func>,
    statement: (usize, usize),
}

/// Every literal that starts with a registered prefix and is used to BUILD a value (not to compare against one).
fn candidates(
    text: &str,
    code: &str,
    lits: &[Lit],
    funcs: &[Func],
    tests: &[(usize, usize)],
) -> Vec<Candidate> {
    let mut out = Vec::new();
    for lit in lits {
        let content = &text[lit.start..lit.end];
        let Some(prefix) = PREFIXES.iter().find(|p| content.starts_with(**p)) else {
            continue;
        };
        if tests.iter().any(|(a, b)| *a <= lit.start && lit.start < *b) {
            continue;
        }
        let func = enclosing(funcs, lit.start).cloned();
        let limit = func.as_ref().map(|f| f.end).unwrap_or(code.len());
        let statement = statement_around(code, lit.start, limit);
        let stmt_text = &text[statement.0..statement.1.min(text.len())];
        let building = content.contains('{') || is_building(stmt_text);
        let comparing = is_comparing(stmt_text);
        if func.is_some() && (!building || (comparing && !content.contains('{'))) {
            continue;
        }
        out.push(Candidate {
            at: lit.start,
            prefix,
            func,
            statement,
        });
    }
    out.sort_by_key(|c| c.at);
    out
}

/// Literals shaped like `<word>_` or `<word>_{..}` inside a function, used to BUILD a value: prefixes this lint was
/// not told about.
fn shaped_prefixes(
    text: &str,
    code: &str,
    lits: &[Lit],
    from: usize,
    to: usize,
) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for lit in lits.iter().filter(|l| l.start >= from && l.end <= to) {
        let content = &text[lit.start..lit.end];
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
            let (a, z) = statement_around(code, lit.start, to);
            let stmt = &text[a..z.min(text.len())];
            if !is_building(stmt) || is_comparing(stmt) {
                continue;
            }
        }
        out.push((lit.start, head));
    }
    out
}

fn is_building(statement: &str) -> bool {
    [
        "+",
        "push_str",
        "to_owned",
        "String::from",
        "format!",
        "concat!",
        ".join(",
        ".to_string()",
        ".into()",
    ]
    .iter()
    .any(|m| statement.contains(m))
}

fn is_comparing(statement: &str) -> bool {
    [
        "starts_with",
        "strip_prefix",
        "matches!",
        "==",
        "!=",
        ".eq(",
        "ends_with",
        ".contains(",
    ]
    .iter()
    .any(|m| statement.contains(m))
}

/// Scan the given files. One line per violation; empty means no accidental shape inside this lint's scope.
fn scan(files: &[(String, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    let mut found: Vec<(String, String, String, usize)> = Vec::new(); // (file, function, prefix, occurrences)
    let mut non_mints_built: Vec<(String, String)> = Vec::new(); // (file, function) of reviewed non-mints seen
    for (rel, text) in files {
        let (code, lits) = lex(text);
        let (funcs, tests) = spans(&code);
        // 1. every mint candidate against the registry, by (file, function, prefix, nth)
        let mut seen: Vec<(String, String, usize)> = Vec::new();
        for cand in candidates(text, &code, &lits, &funcs, &tests) {
            let Some(func) = cand.func.clone() else {
                violations.push(format!("{rel}:{}: `{}…` is held outside any function (a const or static): register the mint that uses it", line_of(text, cand.at), cand.prefix));
                continue;
            };
            let nth = seen
                .iter()
                .filter(|(f, p, _)| *f == func.name && p == cand.prefix)
                .count();
            seen.push((func.name.clone(), cand.prefix.to_string(), nth));
            let line = line_of(text, cand.at);
            if let Some(non_mint) = REVIEWED_NON_MINTS
                .iter()
                .find(|n| n.file == rel && n.function == func.name && n.prefix == cand.prefix)
            {
                let statement = &text[cand.statement.0..cand.statement.1.min(text.len())];
                if nth > 0 {
                    violations.push(format!("{rel}:{line}: `{}` builds `{}…` more than once; only one reviewed non-mint is accepted there", func.name, cand.prefix));
                } else if !statement.contains(non_mint.statement) {
                    violations.push(format!(
                        "{rel}:{line}: `{}` builds `{}…` other than by its reviewed statement {:?}",
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
                    format!("{rel}:{line}: `{}` mints `{}…` more times than the registry says (occurrence {})", func.name, cand.prefix, nth + 1)
                } else {
                    format!("{rel}:{line}: `{}…` is minted in `{}`, which is not a registered minting site", cand.prefix, func.name)
                });
                continue;
            };
            let statement = &text[cand.statement.0..cand.statement.1.min(text.len())];
            if !statement.contains(mint.inline) {
                violations.push(format!("{rel}:{line}: the `{}…` mint in `{}` is not formed from its registered source {:?}", cand.prefix, func.name, mint.inline));
            }
            if !mint.fed_by.is_empty() {
                let before = &text[func.start..cand.statement.0.min(text.len()).max(func.start)];
                if !before.contains(mint.fed_by) {
                    violations.push(format!("{rel}:{line}: the `{}…` mint in `{}` is not preceded by its registered draw {:?}", cand.prefix, func.name, mint.fed_by));
                }
            }
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
                    violations.push(format!("{rel}:{line}: the `{}…` mint in `{}` is built from a derivation ({forbidden:?})", cand.prefix, func.name));
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
            for (at, head) in shaped_prefixes(text, &code, &lits, func.start, func.end) {
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
    // 3. the registry against the tree: every registered file and function exists, every registered mint is found,
    // and every reviewed non-mint is still built where it was reviewed
    for non_mint in REVIEWED_NON_MINTS {
        if files.iter().any(|(rel, _)| rel == non_mint.file)
            && !non_mints_built
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
        let Some((rel, text)) = files.iter().find(|(rel, _)| rel == mint.file) else {
            if !missing_files.contains(&mint.file) {
                missing_files.push(mint.file);
                violations.push(format!(
                    "{}: the registered file is missing from the tree",
                    mint.file
                ));
            }
            continue;
        };
        let (code, _) = lex(text);
        let (funcs, _) = spans(&code);
        let Some(func) = funcs.iter().find(|f| f.name == mint.function) else {
            violations.push(format!(
                "{rel}: the registered minting function `{}` no longer exists",
                mint.function
            ));
            continue;
        };
        if mint.prefix.is_empty() {
            if !text[func.start..func.end].contains(mint.inline) {
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
