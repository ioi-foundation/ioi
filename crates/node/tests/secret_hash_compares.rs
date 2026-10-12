//! Every daemon compare of a PRESENTED secret's SHA-256 against a stored hash reads every byte of
//! both (`authority_routes::constant_time_eq`, directly or through `stored_hash_matches`): the
//! bootstrap token, the automation webhook token, session tokens (both lookups and logout), API
//! access tokens and SCIM tokens. A source read of the production code (test modules excluded),
//! because the property is how the compare is written, not what it answers.
//!
//! The daemon-wide scan reads every source of the daemon binary (crates/node/src/bin), the key
//! store it verifies passwords with (crates/crypto/src) and the model-mount capability tokens
//! (crates/services/src/agentic/runtime/kernel/model_mount): no credential a caller presents is
//! compared with plain == or != there, except the reviewed non-credential compares it lists.

use std::path::Path;

/// The index just past the `}` that closes the block opened at `open`, skipping braces inside
/// comments, string, raw-string and char literals.
fn block_end(text: &str, open: usize) -> usize {
    let b = text.as_bytes();
    let (mut i, mut depth) = (open, 0usize);
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i += 1;
            }
            b'r' if (b.get(i + 1) == Some(&b'"') || b.get(i + 1) == Some(&b'#'))
                && !(i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) =>
            {
                let mut hashes = 0;
                let mut j = i + 1;
                while b.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if b.get(j) == Some(&b'"') {
                    let closing: Vec<u8> = std::iter::once(b'"')
                        .chain(std::iter::repeat(b'#').take(hashes))
                        .collect();
                    j += 1;
                    while j < b.len() && !b[j..].starts_with(&closing) {
                        j += 1;
                    }
                    i = j + closing.len() - 1;
                }
            }
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'\'' => {
                if b.get(i + 1) == Some(&b'\\') {
                    i += 2;
                    while i < b.len() && b[i] != b'\'' {
                        i += 1;
                    }
                } else if b.get(i + 2) == Some(&b'\'') {
                    i += 2;
                }
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    b.len()
}

/// The production text of a daemon route module: every `#[cfg(test)]` item (a `mod … { … }` block)
/// removed by brace matching, so test helpers never count and production code is never skipped.
fn production_source(file: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/bin/hypervisor_daemon_routes")
        .join(file);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while let Some(found) = text[at..].find("#[cfg(test)]") {
        let start = at + found;
        out.push_str(&text[at..start]);
        let Some(open) = text[start..].find('{') else {
            at = text.len();
            break;
        };
        at = block_end(&text, start + open);
    }
    out.push_str(&text[at..]);
    out
}

/// Lines that compare a hash with `==` / `!=` where one side is a presented secret's SHA-256 or a
/// stored token hash.
fn plain_secret_hash_compares(source: &str) -> Vec<String> {
    source
        .lines()
        .filter(|line| {
            let compares = line.contains("==") || line.contains("!=");
            let hashes_a_secret = line.contains("sha256_hex_str(")
                || line.contains("[\"token_hash\"]")
                || line.contains("\"webhook_token_hash\"");
            compares && hashes_a_secret
        })
        .map(|line| line.trim().to_string())
        .collect()
}

#[test]
fn every_presented_secret_hash_is_compared_in_constant_time() {
    let lifecycle = production_source("lifecycle_routes.rs");
    let orchestration = production_source("orchestration_routes.rs");
    // The read reaches the production handlers and none of the test modules.
    for (source, present, absent) in [
        (
            &lifecycle,
            &[
                "fn handle_auth_bootstrap(",
                "fn presented_session_record(",
                "fn handle_auth_logout(",
                "fn resolve_scim_configuration(",
            ][..],
            "mod preview_authority_tests",
        ),
        (
            &orchestration,
            &["fn handle_automation_webhook("][..],
            "fn token_opens_trigger(",
        ),
    ] {
        for name in present {
            assert!(
                source.contains(name),
                "the production read reaches `{name}`"
            );
        }
        assert!(
            !source.contains(absent),
            "the production read excludes `{absent}`"
        );
    }
    let mut plain = plain_secret_hash_compares(&lifecycle);
    plain.extend(plain_secret_hash_compares(&orchestration));
    assert!(
        plain.is_empty(),
        "secret-hash compares written with == / != (they stop at the first differing byte):\n{}",
        plain.join("\n")
    );
    for (what, source, needle, count) in [
        (
            "the bootstrap token, session lookups, logout, API tokens and SCIM tokens",
            &lifecycle,
            "stored_hash_matches(",
            7,
        ),
        (
            "the automation webhook token",
            &orchestration,
            "constant_time_eq(",
            1,
        ),
    ] {
        assert!(
            source.matches(needle).count() >= count,
            "{what}: expected at least {count} uses of `{needle}` (definition included)"
        );
    }
    assert!(
        lifecycle.contains("super::authority_routes::constant_time_eq("),
        "stored_hash_matches compares through authority_routes::constant_time_eq"
    );
}

// ---- The daemon-wide scan ------------------------------------------------------------------------

/// Where the wide scan reads: every source file of the daemon binary and its route modules
/// (crates/node/src/bin), the key store the daemon verifies passwords with (crates/crypto/src), and
/// the model-mount capability tokens the daemon authenticates model-mount calls with
/// (crates/services/src/agentic/runtime/kernel/model_mount).
const SCANNED_DIRS: &[&str] = &[
    "crates/node/src/bin",
    "crates/crypto/src",
    "crates/services/src/agentic/runtime/kernel/model_mount",
];

/// The names that make a compare a CREDENTIAL compare.
const CREDENTIAL_NAMES: &[&str] = &[
    "token_hash",
    "sha256_hex_str(",
    "webhook_token_hash",
    "invite_id",
    "Some(state)",
    "bearer",
    "secret",
    "password_hash",
    "connection_token",
    "access_token",
    "api_key",
    "csrf",
];

/// Why a listed plain compare is not a presented-credential compare.
#[derive(Clone, Copy)]
enum Review {
    /// Reviewed: not a compare of a credential the caller presents against a stored one.
    NotACredential(&'static str),
    /// Introduced by another set of the same master batch; absent on this set's own base.
    OtherSet(&'static str),
    /// A known open finding owned elsewhere; this entry is removed when it is fixed.
    Open(&'static str),
}

/// The reviewed plain compares (file suffix, the compare's text, review). Every other credential
/// compare written with == or != fails the scan.
const REVIEWED: &[(&str, &str, Review)] = &[
    (
        "ioi_intelligence_routes.rs",
        "sensitivity == \"secret\"",
        Review::NotACredential("a sensitivity label"),
    ),
    (
        "k8s_candidate_source.rs",
        "== \"insecure_dev\"",
        Review::NotACredential("a CA-mode setting beside an outbound bearer"),
    ),
    (
        "lifecycle_routes.rs",
        "s[\"secret_id\"].as_str() == Some(secret_id.as_str())",
        Review::NotACredential("a secret's public record id"),
    ),
    (
        "lifecycle_routes.rs",
        "s[\"secret_id\"].as_str() == Some(id.as_str())",
        Review::NotACredential("a secret's public record id"),
    ),
    (
        "lifecycle_routes.rs",
        "b[\"id\"].as_str() == Some(\"bootstrap\")",
        Review::NotACredential(
            "selects the bootstrap record by its fixed id; its token hash is compared in constant time",
        ),
    ),
    (
        "lifecycle_routes.rs",
        "if cookie != bearer",
        Review::OtherSet(
            "BUILD-DELTA #24: two values the same request presents must be one credential; no stored secret",
        ),
    ),
    (
        "orchestration_routes.rs",
        ".map(str::to_string) == prior_hash",
        Review::NotACredential("the webhook rotation re-reads the hash it just wrote"),
    ),
    (
        "orchestration_routes.rs",
        "!= Some(token_hash.as_str())",
        Review::NotACredential("the webhook rotation re-reads the hash it just wrote"),
    ),
    (
        "storage_backend_routes.rs",
        "c[\"connector_id\"].as_str() == Some(text(account, \"account_id\"))",
        Review::NotACredential("a connector's public id"),
    ),
];

/// Two byte-aligned views of a source text: `structure` blanks comments and every string, raw
/// string, byte string and char literal; `code` blanks comments only. Newlines are kept.
fn views(text: &str) -> (Vec<u8>, Vec<u8>) {
    let b = text.as_bytes();
    let mut structure = b.to_vec();
    let mut code = b.to_vec();
    fn blank(v: &mut [u8], from: usize, to: usize) {
        for byte in v.iter_mut().take(to).skip(from) {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }
    let mut i = 0;
    while i < b.len() {
        let after_ident = i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
        if b[i..].starts_with(b"//") {
            let end = b[i..]
                .iter()
                .position(|c| *c == b'\n')
                .map_or(b.len(), |p| i + p);
            blank(&mut structure, i, end);
            blank(&mut code, i, end);
            i = end;
            continue;
        }
        if b[i..].starts_with(b"/*") {
            let (mut depth, mut j) = (0usize, i);
            while j < b.len() {
                if b[j..].starts_with(b"/*") {
                    depth += 1;
                    j += 2;
                } else if b[j..].starts_with(b"*/") {
                    depth -= 1;
                    j += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    j += 1;
                }
            }
            blank(&mut structure, i, j);
            blank(&mut code, i, j);
            i = j;
            continue;
        }
        let raw_open = match (after_ident, b[i], b.get(i + 1)) {
            (false, b'r', Some(b'"' | b'#')) => Some(i + 1),
            (false, b'b', Some(b'r')) => Some(i + 2),
            _ => None,
        };
        if let Some(mut j) = raw_open {
            let mut hashes = 0;
            while b.get(j) == Some(&b'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) == Some(&b'"') {
                let closing: Vec<u8> = std::iter::once(b'"')
                    .chain(std::iter::repeat(b'#').take(hashes))
                    .collect();
                let mut k = j + 1;
                while k < b.len() && !b[k..].starts_with(&closing) {
                    k += 1;
                }
                let end = (k + closing.len()).min(b.len());
                blank(&mut structure, i, end);
                i = end;
                continue;
            }
        }
        let string_open = match (after_ident, b[i], b.get(i + 1)) {
            (_, b'"', _) => Some(i + 1),
            (false, b'b', Some(b'"')) => Some(i + 2),
            _ => None,
        };
        if let Some(mut j) = string_open {
            while j < b.len() && b[j] != b'"' {
                if b[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            let end = (j + 1).min(b.len());
            blank(&mut structure, i, end);
            i = end;
            continue;
        }
        if b[i] == b'\'' {
            let rest = &text[i + 1..];
            let mut chars = rest.chars();
            let length = match chars.next() {
                Some('\\') => rest[1..].find('\'').filter(|p| *p <= 10).map(|p| p + 3),
                Some(first) if chars.next() == Some('\'') => Some(first.len_utf8() + 2),
                _ => None,
            };
            if let Some(length) = length {
                blank(&mut structure, i, i + length);
                i += length;
                continue;
            }
        }
        i += 1;
    }
    (structure, code)
}

/// Remove every `#[cfg(test)]` item (through its `;`, or its block's matching `}`) from both views.
fn without_test_items(structure: &mut [u8], code: &mut [u8]) {
    let mut from = 0;
    while let Some(found) = find(structure, b"#[cfg(test)]", from) {
        let mut end = structure.len();
        let mut depth = 0i64;
        let mut k = found + b"#[cfg(test)]".len();
        while k < structure.len() {
            match structure[k] {
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth -= 1,
                b';' if depth == 0 => {
                    end = k + 1;
                    break;
                }
                b'{' if depth == 0 => {
                    let mut braces = 0i64;
                    while k < structure.len() {
                        match structure[k] {
                            b'{' => braces += 1,
                            b'}' => {
                                braces -= 1;
                                if braces == 0 {
                                    break;
                                }
                            }
                            _ => {}
                        }
                        k += 1;
                    }
                    end = (k + 1).min(structure.len());
                    break;
                }
                _ => {}
            }
            k += 1;
        }
        for index in found..end {
            if structure[index] != b'\n' {
                structure[index] = b' ';
                code[index] = b' ';
            }
        }
        from = end;
    }
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|p| p + from)
}

/// The credential compares written with == or != in one file: each statement-sized chunk (split at
/// `;`, `{` and `}` outside literals and comments) is split again at `&&` and `||`, and a piece is
/// a credential compare when it holds == or != (outside literals) and names a credential.
fn plain_credential_compares(text: &str) -> Vec<(usize, String)> {
    let (mut structure, mut code) = views(text);
    without_test_items(&mut structure, &mut code);
    let mut found = Vec::new();
    let mut start = 0;
    for end in 0..=structure.len() {
        if end < structure.len() && !matches!(structure[end], b';' | b'{' | b'}') {
            continue;
        }
        let mut piece_start = start;
        let mut k = start;
        while k <= end {
            let boundary = k == end
                || (k + 1 < end
                    && (structure[k..].starts_with(b"&&") || structure[k..].starts_with(b"||")));
            if boundary {
                let piece_structure = &structure[piece_start..k];
                let piece_code = String::from_utf8_lossy(&code[piece_start..k])
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                let compares = find(piece_structure, b"==", 0).is_some()
                    || find(piece_structure, b"!=", 0).is_some();
                if compares
                    && CREDENTIAL_NAMES
                        .iter()
                        .any(|name| piece_code.contains(name))
                {
                    let line = text[..piece_start].matches('\n').count() + 1;
                    found.push((line, piece_code));
                }
                piece_start = k + 2;
                k += 2;
                continue;
            }
            k += 1;
        }
        start = end + 1;
    }
    found
}

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {dir:?}: {e}"))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Daemon-wide: no credential a caller presents (a token or its hash, an invite id, an OAuth state,
/// a bearer, a secret, a password hash, a connection token, an access token, an API key) is compared
/// with plain == or != anywhere the daemon authenticates; each plain compare that names one is a
/// reviewed non-credential compare (listed with its reason), and every listed entry still exists
/// (an entry from another set of the batch may be absent on this set's own base). The scanner reads
/// production code only and is checked to reach the authenticating handlers.
#[test]
fn no_presented_credential_is_compared_with_plain_equality_anywhere_the_daemon_authenticates() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    for dir in SCANNED_DIRS {
        rust_files(&workspace.join(dir), &mut files);
    }
    assert!(
        files.len() > 100,
        "the scan reads the daemon's sources ({} files)",
        files.len()
    );
    let mut unreviewed = Vec::new();
    let mut used = vec![false; REVIEWED.len()];
    let mut reached = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        let display = path
            .strip_prefix(&workspace)
            .unwrap_or(path)
            .display()
            .to_string();
        let (mut structure, mut code) = views(&text);
        without_test_items(&mut structure, &mut code);
        let production = String::from_utf8_lossy(&code);
        for handler in [
            "fn handle_auth_oidc_callback(",
            "fn handle_org_invite_accept(",
            "fn open_ceremony_by_state(",
            "fn handle_automation_webhook(",
        ] {
            if production.contains(handler) {
                reached.push(handler);
            }
        }
        for (line, compare) in plain_credential_compares(&text) {
            match REVIEWED
                .iter()
                .position(|(file, needle, _)| display.ends_with(file) && compare.contains(needle))
            {
                Some(index) => used[index] = true,
                None => unreviewed.push(format!("{display}:{line}: {compare}")),
            }
        }
    }
    for handler in [
        "fn handle_auth_oidc_callback(",
        "fn handle_org_invite_accept(",
        "fn open_ceremony_by_state(",
        "fn handle_automation_webhook(",
    ] {
        assert!(reached.contains(&handler), "the scan reaches `{handler}`");
    }
    assert!(
        unreviewed.is_empty(),
        "credential compares written with == / != (they stop at the first differing byte):\n{}",
        unreviewed.join("\n")
    );
    let stale: Vec<String> = REVIEWED
        .iter()
        .zip(&used)
        .filter(|((_, _, review), used)| !**used && !matches!(review, Review::OtherSet(_)))
        .map(|((file, needle, _), _)| format!("{file}: {needle}"))
        .collect();
    assert!(
        stale.is_empty(),
        "reviewed entries that no longer exist (remove them):\n{}",
        stale.join("\n")
    );
    let _ = REVIEWED
        .iter()
        .map(|(_, _, review)| match review {
            Review::NotACredential(why) | Review::OtherSet(why) | Review::Open(why) => why.len(),
        })
        .sum::<usize>();
}

/// The shared compare reads every byte of both inputs: the length difference enters the
/// accumulator, the loop runs over the longer input with no exit, and the accumulator is tested
/// only after the loop.
#[test]
fn the_shared_constant_time_compare_reads_every_byte() {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/bin/hypervisor_daemon_routes/authority_routes.rs"),
    )
    .expect("read authority_routes.rs");
    let start = text
        .find("pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {")
        .expect("the shared constant-time compare");
    let body = &text[start..block_end(&text, start + text[start..].find('{').unwrap())];
    for needed in [
        "let mut difference = left.len() ^ right.len();",
        "for index in 0..left.len().max(right.len())",
        "difference |=",
    ] {
        assert!(body.contains(needed), "the compare has `{needed}`:\n{body}");
    }
    assert!(
        body.trim_end()
            .trim_end_matches('}')
            .trim_end()
            .ends_with("difference == 0"),
        "the accumulator is tested only at the end:\n{body}"
    );
    for forbidden in ["return", "break", "?;"] {
        assert!(
            !body.contains(forbidden),
            "no early exit (`{forbidden}`):\n{body}"
        );
    }
}
