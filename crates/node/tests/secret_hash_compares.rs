//! Every daemon compare of a PRESENTED secret's SHA-256 against a stored hash reads every byte of
//! both (`authority_routes::constant_time_eq`, directly or through `stored_hash_matches`): the
//! bootstrap token, the automation webhook token, session tokens (both lookups and logout), API
//! access tokens and SCIM tokens. A source read of the production code (test modules excluded),
//! because the property is how the compare is written, not what it answers.

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
